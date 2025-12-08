# 🛡️ p2p_secure_chat

![Version](https://img.shields.io/badge/version-1.2.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Crypto](https://img.shields.io/badge/crypto-XChaCha20Poly1305-orange)
![Protocol](https://img.shields.io/badge/protocol-UDP%20%2B%20CBR-red)

**p2p_secure_chat** 是一个极简主义的、基于 UDP 的高强度端对端加密聊天终端工具。它专为在不可信网络环境中进行**短时、一次性**的秘密通信而设计。

本项目不依赖复杂的公钥基础设施（PKI），而是采用**预共享密钥（PSK）**结合 **SAS（短认证字符串）**验证机制，以极低的代码复杂度实现对国家级中间人攻击（MITM）和深度包检测（DPI）的防御。

> **⚠️ 警告**：本项目设计理念为“阅后即焚”。程序关闭后，内存中的密钥将立即被安全擦除（Zeroize），历史通信数据将无法解密（PFS）。

## ✨ 核心特性 (v1.2.0)

### 🔐 军工级加密架构
- **现代流加密**：全链路采用 **XChaCha20-Poly1305**（含 192-bit Nonce），比 AES 更高效且无硬件后门风险。
- **抗暴力破解**：密钥派生使用 **Argon2id** (内存硬化哈希) + **HKDF-SHA256**，极大增加字典攻击成本。
- **前向保密 (PFS)**：每次会话协商独立的 Ephemeral Session Key。会话结束即销毁密钥，即使未来主密码泄露也无法解密过去的历史流量。

### 👻 隐身与反分析 (Anti-DPI)
- **恒定比特率 (CBR)**：协议强制将所有数据包（包括握手、ACK、短消息）填充至 **1300 字节**，彻底隐藏真实载荷长度特征。
- **流量伪装 (Traffic Noise)**：连接建立后，空闲时段会自动发送加密的噪音包，混淆通信时序分析。
- **全加密头**：除极少量的握手元数据外，整个协议头均受加密保护，无明显明文特征。

### 🛡️ 认证与防御
- **SAS 验证**：握手完成后生成 8 字节可视化指纹（SAS），双方只需口头核对该字符串即可确信无中间人篡改。
- **抗重放 (Anti-Replay)**：基于滑动窗口（Sliding Window）机制，有效识别并丢弃重放攻击包。
- **HMAC 签名**：握手阶段受 PSK 派生的 HMAC 保护，非授权的探测包会被静默丢弃。

## 🛠️ 快速开始

### 1. 编译
建议使用 `release` 模式编译以获得最佳加解密性能：

```bash
# 假设你已克隆项目
cd p2p_secure_chat
cargo run --release