use anyhow::{Result, anyhow};
use argon2::{Argon2, Params};
use bincode::Options;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, OsRng},
};
use chrono::Utc;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::io::{self, AsyncBufReadExt};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc};
use tokio::time::{Duration, MissedTickBehavior, interval};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const PROTOCOL_SALT_UUID: &str = "123e4567-e89b-12d3-a456-426614174000";
const PROTOCOL_VERSION: u8 = 8;

const WIRE_PACKET_SIZE: usize = 1300;
const WIRE_TOKEN_SIZE: usize = 8;
const WIRE_NONCE_SIZE: usize = 24;
const TAG_SIZE: usize = 16;
const ENCRYPTED_BLOB_SIZE: usize = WIRE_PACKET_SIZE - WIRE_TOKEN_SIZE - WIRE_NONCE_SIZE;
const MAX_PLAINTEXT_SIZE: usize = ENCRYPTED_BLOB_SIZE - TAG_SIZE;

const TICK_RATE_MS: u64 = 200;
const NONCE_CACHE_TTL_SECS: i64 = 60;
const MAX_NONCE_CACHE_SIZE: usize = 5_000;
const HANDSHAKE_RESEND_MS: i64 = 1000;

#[derive(Zeroize, ZeroizeOnDrop)]
struct MasterKey([u8; 32]);

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
struct SessionKey([u8; 32]);

#[derive(Debug, PartialEq)]
enum DecryptedSource {
    MasterKey,
    SessionKey,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
enum InnerMessage {
    HandshakeInit(HandshakePayload),
    HandshakeResp(HandshakePayload),
    Data { seq: u64, payload: Vec<u8> },
    Ack { seq: u64 },
    Noise,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct HandshakePayload {
    timestamp_micros: i64,
    ephemeral_pub: [u8; 32],
    hmac_signature: [u8; 32],
    nonce_handshake: [u8; 16],
    version: u8,
}

#[derive(Clone)]
struct QueuedItem {
    msg: InnerMessage,
    target: SocketAddr,
    use_session_key: bool,
}

struct ReplayProtection {
    highest_seq: u64,
    window_bitmap: u64,
}

impl ReplayProtection {
    fn new() -> Self {
        Self {
            highest_seq: 0,
            window_bitmap: 0,
        }
    }
    fn check_and_update(&mut self, seq: u64) -> bool {
        if seq == 0 {
            return false;
        }
        if seq > self.highest_seq {
            let diff = seq - self.highest_seq;
            if diff >= 64 {
                self.window_bitmap = 1;
            } else {
                self.window_bitmap <<= diff;
                self.window_bitmap |= 1;
            }
            self.highest_seq = seq;
            return true;
        }
        let diff = self.highest_seq - seq;
        if diff >= 64 {
            return false;
        }
        let mask = 1 << diff;
        if (self.window_bitmap & mask) != 0 {
            return false;
        }
        self.window_bitmap |= mask;
        true
    }
}

struct NonceCache {
    map: HashMap<[u8; 16], i64>,
    queue: VecDeque<([u8; 16], i64)>,
}

impl NonceCache {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            queue: VecDeque::new(),
        }
    }
    fn check_and_insert(&mut self, nonce: [u8; 16], current_time: i64) -> bool {
        if self.map.contains_key(&nonce) {
            return false;
        }
        while let Some(&(n, ts)) = self.queue.front() {
            if current_time - ts >= NONCE_CACHE_TTL_SECS || self.map.len() >= MAX_NONCE_CACHE_SIZE {
                self.map.remove(&n);
                self.queue.pop_front();
            } else {
                break;
            }
        }
        self.map.insert(nonce, current_time);
        self.queue.push_back((nonce, current_time));
        true
    }
}

struct PeerSession {
    session_key: SessionKey,
    peer_addr: Option<SocketAddr>,
    is_established: bool,
    next_send_seq: u64,
    replay_prot: Arc<Mutex<ReplayProtection>>,
    handshake_pending: bool,
    handshake_start_time: i64,
    last_handshake_payload: Option<InnerMessage>,
    sas_fingerprint: Option<String>,
    my_sent_nonce: Option<[u8; 16]>,
}

struct ChatHistory {
    messages: VecDeque<String>,
}

impl ChatHistory {
    fn new() -> Self {
        Self {
            messages: VecDeque::with_capacity(100),
        }
    }
    fn add(&mut self, msg: String) {
        if self.messages.len() >= 100 {
            self.messages.pop_front();
        }
        self.messages.push_back(msg);
    }
}

fn bincode_config() -> impl bincode::Options {
    bincode::options()
        .with_limit(2048)
        .with_little_endian()
        .with_fixint_encoding()
}

fn derive_master_key(password: &str) -> MasterKey {
    let params = Params::new(64 * 1024, 3, 1, None).unwrap();
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key_buffer = [0u8; 32];
    argon2
        .hash_password_into(
            password.as_bytes(),
            PROTOCOL_SALT_UUID.as_bytes(),
            &mut key_buffer,
        )
        .unwrap();
    MasterKey(key_buffer)
}

fn derive_time_based_keys(master: &MasterKey, time_slot: i64) -> ([u8; 8], Zeroizing<[u8; 32]>) {
    let hk = Hkdf::<Sha256>::new(Some(PROTOCOL_SALT_UUID.as_bytes()), &master.0);

    let mut token = [0u8; 32];
    hk.expand(format!("token_v8:{}", time_slot).as_bytes(), &mut token)
        .unwrap();
    let mut final_token = [0u8; 8];
    final_token.copy_from_slice(&token[0..8]);

    let mut enc_key = [0u8; 32];
    hk.expand(format!("enc_key_v8:{}", time_slot).as_bytes(), &mut enc_key)
        .unwrap();

    (final_token, Zeroizing::new(enc_key))
}

fn derive_hmac_key(master: &MasterKey) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(b"hmac_static_salt"), &master.0);
    let mut key = [0u8; 32];
    hk.expand(b"hmac_auth", &mut key).unwrap();
    Zeroizing::new(key)
}

fn derive_session_key(shared: &[u8; 32], n_init: &[u8; 16], n_resp: &[u8; 16]) -> SessionKey {
    let hk = Hkdf::<Sha256>::new(Some(b"session_ctx"), shared);
    let mut key = [0u8; 32];
    let mut info = Vec::new();
    info.extend_from_slice(n_init);
    info.extend_from_slice(n_resp);
    hk.expand(&info, &mut key).unwrap();
    SessionKey(key)
}

fn verify_handshake_hmac(
    key: &[u8; 32],
    ts: i64,
    pubk: &[u8; 32],
    nonce: &[u8; 16],
    sig: &[u8; 32],
    ctx: &[u8],
) -> bool {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
    mac.update(&ts.to_le_bytes());
    mac.update(pubk);
    mac.update(nonce);
    mac.update(ctx);
    let expected = mac.finalize().into_bytes();
    expected[..32].ct_eq(sig).into()
}

fn compute_handshake_hmac(
    key: &[u8; 32],
    ts: i64,
    pubk: &[u8; 32],
    nonce: &[u8; 16],
    ctx: &[u8],
) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
    mac.update(&ts.to_le_bytes());
    mac.update(pubk);
    mac.update(nonce);
    mac.update(ctx);
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes()[..32]);
    out
}

fn generate_sas(key: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(b"SAS_V2_XChaCha");
    h.update(key);
    let res = h.finalize();
    format!(
        "{:02X} {:02X} {:02X} {:02X}",
        res[0], res[1], res[2], res[3]
    )
}

fn encrypt_cbr(key: &[u8; 32], msg: &InnerMessage) -> Result<([u8; 24], Vec<u8>)> {
    let raw = bincode_config().serialize(msg)?;

    if raw.len() > MAX_PLAINTEXT_SIZE - 2 {
        return Err(anyhow!("Payload too big"));
    }

    let mut buffer = vec![0u8; MAX_PLAINTEXT_SIZE];
    let len_bytes = (raw.len() as u16).to_le_bytes();
    buffer[0] = len_bytes[0];
    buffer[1] = len_bytes[1];
    buffer[2..2 + raw.len()].copy_from_slice(&raw);
    OsRng.fill_bytes(&mut buffer[2 + raw.len()..]);

    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let xnonce = XNonce::from_slice(&nonce);

    let ciphertext = cipher
        .encrypt(xnonce, buffer.as_slice())
        .map_err(|e| anyhow!("Encrypt: {}", e))?;

    Ok((nonce, ciphertext))
}

fn decrypt_cbr(key: &[u8; 32], nonce: &[u8; 24], ciphertext: &[u8]) -> Result<InnerMessage> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let xnonce = XNonce::from_slice(nonce);

    let plaintext = cipher
        .decrypt(xnonce, ciphertext)
        .map_err(|e| anyhow!("Decrypt/Auth failed: {}", e))?;

    if plaintext.len() < 2 {
        return Err(anyhow!("Too short"));
    }
    let len = u16::from_le_bytes([plaintext[0], plaintext[1]]) as usize;
    if len > plaintext.len() - 2 {
        return Err(anyhow!("Invalid len"));
    }

    let msg = bincode_config().deserialize::<InnerMessage>(&plaintext[2..2 + len])?;
    Ok(msg)
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("╔═══════════════════════════════════════════════════╗");
    println!("║        p2p_secure_chat                            ║");
    println!("╚═══════════════════════════════════════════════════╝");

    print!("📍 Local Port: ");
    std::io::stdout().flush()?;
    let stdin = io::stdin();
    let mut reader = io::BufReader::new(stdin);
    let mut input = String::new();
    reader.read_line(&mut input).await?;
    let port: u16 = input.trim().parse().unwrap_or(7000);

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
    let socket = Arc::new(UdpSocket::bind(&addr).await?);
    println!("✅ Listening on {}", addr);

    let password = Zeroizing::new(rpassword::prompt_password("🔑 Shared Secret: ")?);
    let master_key = Arc::new(derive_master_key(&password));
    let hmac_key = derive_hmac_key(&master_key);

    let session = Arc::new(Mutex::new(PeerSession {
        session_key: SessionKey([0u8; 32]),
        peer_addr: None,
        is_established: false,
        next_send_seq: 1,
        replay_prot: Arc::new(Mutex::new(ReplayProtection::new())),
        handshake_pending: false,
        handshake_start_time: 0,
        last_handshake_payload: None,
        sas_fingerprint: None,
        my_sent_nonce: None,
    }));

    let history = Arc::new(Mutex::new(ChatHistory::new()));
    let my_secret = Arc::new(StaticSecret::random_from_rng(OsRng));
    let my_public = PublicKey::from(&*my_secret);

    let (tx_sender, mut tx_receiver) = mpsc::channel::<QueuedItem>(100);

    let sk_pacer = socket.clone();
    let mk_pacer = master_key.clone();
    let sess_pacer = session.clone();

    tokio::spawn(async move {
        let mut interval = interval(Duration::from_millis(TICK_RATE_MS));
        interval.set_missed_tick_behavior(MissedTickBehavior::Burst);

        loop {
            interval.tick().await;

            let mut msg_to_send: Option<QueuedItem> = None;
            let mut pending_handshake_item: Option<QueuedItem> = None;
            let mut should_send_noise = false;
            let peer_addr_cache;

            {
                let s = sess_pacer.lock().await;
                peer_addr_cache = s.peer_addr;

                if s.handshake_pending {
                    if let Some(target) = s.peer_addr {
                        let now = Utc::now().timestamp_millis();
                        if now - s.handshake_start_time > HANDSHAKE_RESEND_MS {
                            if let Some(ref payload) = s.last_handshake_payload {
                                pending_handshake_item = Some(QueuedItem {
                                    msg: payload.clone(),
                                    target,
                                    use_session_key: false,
                                });
                            }
                        }
                    }
                } else if s.is_established {
                    should_send_noise = true;
                }
            }

            if let Ok(item) = tx_receiver.try_recv() {
                msg_to_send = Some(item);
            } else if let Some(hs_item) = pending_handshake_item {
                msg_to_send = Some(hs_item);
            } else if should_send_noise {
                if let Some(addr) = peer_addr_cache {
                    msg_to_send = Some(QueuedItem {
                        msg: InnerMessage::Noise,
                        target: addr,
                        use_session_key: true,
                    });
                }
            }

            if let Some(item) = msg_to_send {
                let (enc_key, wire_token) = if !item.use_session_key {
                    let slot = Utc::now().timestamp() / 60;
                    let (tok, k) = derive_time_based_keys(&mk_pacer, slot);
                    (k, tok.to_vec())
                } else {
                    let s = sess_pacer.lock().await;
                    if s.is_established {
                        let slot = Utc::now().timestamp() / 60;
                        let (tok, _) = derive_time_based_keys(&mk_pacer, slot);
                        (Zeroizing::new(s.session_key.0), tok.to_vec())
                    } else {
                        continue;
                    }
                };

                if let Ok((nonce, ciphertext)) = encrypt_cbr(&enc_key, &item.msg) {
                    let mut wire = Vec::with_capacity(WIRE_PACKET_SIZE);
                    wire.extend(wire_token);
                    wire.extend(nonce);
                    wire.extend(ciphertext);

                    sk_pacer.send_to(&wire, item.target).await.ok();
                }
            }
        }
    });

    let sk_recv = socket.clone();
    let mk_recv = master_key.clone();
    let sess_recv = session.clone();
    let hk_recv = hmac_key.clone();
    let ms_recv = my_secret.clone();
    let hist_recv = history.clone();
    let tx_sender_recv = tx_sender.clone();

    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let mut nonce_cache = NonceCache::new();

        loop {
            let (len, addr) = match sk_recv.recv_from(&mut buf).await {
                Ok(x) => x,
                Err(_) => continue,
            };

            if len < WIRE_TOKEN_SIZE + WIRE_NONCE_SIZE {
                continue;
            }

            let token_bytes = &buf[0..8];
            let nonce_bytes = &buf[8..32];
            let ciphertext_bytes = &buf[32..len];

            let mut decrypted_msg: Option<InnerMessage> = None;
            let mut decrypt_source = DecryptedSource::MasterKey;

            {
                let s = sess_recv.lock().await;
                if s.is_established {
                    if let Ok(m) = decrypt_cbr(
                        &s.session_key.0,
                        nonce_bytes.try_into().unwrap(),
                        ciphertext_bytes,
                    ) {
                        decrypted_msg = Some(m);
                        decrypt_source = DecryptedSource::SessionKey;
                    }
                }
            }

            if decrypted_msg.is_none() {
                let slot = Utc::now().timestamp() / 60;
                for off in [-1, 0, 1] {
                    let (tok, k) = derive_time_based_keys(&mk_recv, slot + off);
                    if subtle::ConstantTimeEq::ct_eq(token_bytes, &tok).into() {
                        if let Ok(m) =
                            decrypt_cbr(&k, nonce_bytes.try_into().unwrap(), ciphertext_bytes)
                        {
                            decrypted_msg = Some(m);
                            decrypt_source = DecryptedSource::MasterKey;
                            break;
                        }
                    }
                }
            }

            let msg = match decrypted_msg {
                Some(m) => m,
                None => continue,
            };

            match msg {
                InnerMessage::Noise => {}

                InnerMessage::HandshakeInit(p) => {
                    let now = Utc::now().timestamp_micros();
                    if (now - p.timestamp_micros).abs() > NONCE_CACHE_TTL_SECS * 1_000_000 {
                        continue;
                    }

                    if !verify_handshake_hmac(
                        &hk_recv,
                        p.timestamp_micros,
                        &p.ephemeral_pub,
                        &p.nonce_handshake,
                        &p.hmac_signature,
                        b"INIT",
                    ) {
                        continue;
                    }
                    if !nonce_cache
                        .check_and_insert(p.nonce_handshake, p.timestamp_micros / 1_000_000)
                    {
                        continue;
                    }

                    let shared = ms_recv.diffie_hellman(&PublicKey::from(p.ephemeral_pub));
                    let mut n_resp = [0u8; 16];
                    OsRng.fill_bytes(&mut n_resp);

                    let mut s = sess_recv.lock().await;
                    s.session_key =
                        derive_session_key(shared.as_bytes(), &p.nonce_handshake, &n_resp);
                    s.peer_addr = Some(addr);
                    s.is_established = true;
                    s.replay_prot = Arc::new(Mutex::new(ReplayProtection::new()));
                    s.sas_fingerprint = Some(generate_sas(&s.session_key.0));
                    s.handshake_pending = false;

                    println!(
                        "\n🤝 Handshake Recv! SAS: [{}]",
                        s.sas_fingerprint.as_ref().unwrap()
                    );
                    drop(s);

                    let ts = Utc::now().timestamp_micros();
                    let h = compute_handshake_hmac(
                        &hk_recv,
                        ts,
                        &*my_public.as_bytes(),
                        &n_resp,
                        b"RESP",
                    );
                    let resp = InnerMessage::HandshakeResp(HandshakePayload {
                        timestamp_micros: ts,
                        ephemeral_pub: *my_public.as_bytes(),
                        hmac_signature: h,
                        nonce_handshake: n_resp,
                        version: PROTOCOL_VERSION,
                    });

                    tx_sender_recv
                        .send(QueuedItem {
                            msg: resp,
                            target: addr,
                            use_session_key: false,
                        })
                        .await
                        .ok();
                }

                InnerMessage::HandshakeResp(p) => {
                    let now = Utc::now().timestamp_micros();
                    if (now - p.timestamp_micros).abs() > NONCE_CACHE_TTL_SECS * 1_000_000 {
                        continue;
                    }
                    if !verify_handshake_hmac(
                        &hk_recv,
                        p.timestamp_micros,
                        &p.ephemeral_pub,
                        &p.nonce_handshake,
                        &p.hmac_signature,
                        b"RESP",
                    ) {
                        continue;
                    }

                    let mut s = sess_recv.lock().await;
                    if !s.handshake_pending {
                        continue;
                    }

                    let shared = ms_recv.diffie_hellman(&PublicKey::from(p.ephemeral_pub));
                    let my_nonce = s.my_sent_nonce.unwrap_or([0u8; 16]);
                    s.session_key =
                        derive_session_key(shared.as_bytes(), &my_nonce, &p.nonce_handshake);
                    s.peer_addr = Some(addr);
                    s.is_established = true;
                    s.handshake_pending = false;
                    s.last_handshake_payload = None;
                    s.replay_prot = Arc::new(Mutex::new(ReplayProtection::new()));
                    s.sas_fingerprint = Some(generate_sas(&s.session_key.0));

                    println!(
                        "\n🤝 Handshake Connected! SAS: [{}]",
                        s.sas_fingerprint.as_ref().unwrap()
                    );
                    drop(s);
                }

                InnerMessage::Data { seq, payload } => {
                    if decrypt_source != DecryptedSource::SessionKey {
                        println!("⚠️ SECURITY: Dropped DATA packet from Master Key path!");
                        continue;
                    }

                    let s = sess_recv.lock().await;
                    if !s.is_established {
                        continue;
                    }

                    let mut rp = s.replay_prot.lock().await;
                    let is_new = rp.check_and_update(seq);
                    drop(rp);

                    if is_new {
                        if let Ok(txt) = String::from_utf8(payload) {
                            let mut h = hist_recv.lock().await;
                            h.add(format!("Peer: {}", txt));
                            println!("\r\x1b[2K💬 Peer: {}\nYou: ", txt);
                            std::io::stdout().flush().unwrap();
                        }
                        let ack = InnerMessage::Ack { seq };
                        tx_sender_recv
                            .send(QueuedItem {
                                msg: ack,
                                target: addr,
                                use_session_key: true,
                            })
                            .await
                            .ok();
                    }
                }

                InnerMessage::Ack { seq: _ } => {
                    if decrypt_source != DecryptedSource::SessionKey {
                        continue;
                    }
                }
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(500)).await;

    loop {
        println!("🌍 Enter TARGET IP:PORT (or 'wait'):");
        print!("> ");
        std::io::stdout().flush()?;

        input.clear();
        reader.read_line(&mut input).await?;
        let cmd = input.trim();
        if cmd == "wait" {
            break;
        }

        if let Ok(target) = cmd.parse::<SocketAddr>() {
            let mut s = session.lock().await;
            s.peer_addr = Some(target);
            s.handshake_pending = true;
            s.handshake_start_time = Utc::now().timestamp_millis();
            s.is_established = false;

            let mut n = [0u8; 16];
            OsRng.fill_bytes(&mut n);
            s.my_sent_nonce = Some(n);

            println!("🔄 Starting handshake...");
            let ts = Utc::now().timestamp_micros();

            let h = compute_handshake_hmac(&hmac_key, ts, &*my_public.as_bytes(), &n, b"INIT");

            let msg = InnerMessage::HandshakeInit(HandshakePayload {
                timestamp_micros: ts,
                ephemeral_pub: *my_public.as_bytes(),
                hmac_signature: h,
                nonce_handshake: n,
                version: PROTOCOL_VERSION,
            });

            s.last_handshake_payload = Some(msg.clone());
            drop(s);

            tx_sender
                .send(QueuedItem {
                    msg,
                    target,
                    use_session_key: false,
                })
                .await
                .ok();
            break;
        }
    }

    loop {
        input.clear();
        if reader.read_line(&mut input).await.unwrap_or(0) == 0 {
            break;
        }
        let txt = input.trim().to_string();
        if txt.is_empty() {
            print!("You: ");
            std::io::stdout().flush()?;
            continue;
        }

        let mut s = session.lock().await;
        if s.is_established && s.peer_addr.is_some() {
            let seq = s.next_send_seq;
            s.next_send_seq += 1;
            let target = s.peer_addr.unwrap();
            drop(s);

            let msg = InnerMessage::Data {
                seq,
                payload: txt.into_bytes(),
            };
            tx_sender
                .send(QueuedItem {
                    msg,
                    target,
                    use_session_key: true,
                })
                .await
                .ok();
        } else {
            println!("⚠️ Connection not ready.");
        }
        print!("You: ");
        std::io::stdout().flush()?;
    }

    Ok(())
}
