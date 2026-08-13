<h1 align="center">🔐 agent-keynl · 给 AI Agent 的密码本</h1>

<p align="center">
  <a href="CHANGELOG.md"><img src="https://img.shields.io/badge/📜-更新日志-8B5CF6?style=flat-square" alt="更新日志"></a>
  <a href="SKILL.md"><img src="https://img.shields.io/badge/🧠-AI技能-22C55E?style=flat-square" alt="AI技能"></a>
  <a href="references/deployment.md"><img src="https://img.shields.io/badge/📦-部署指南-3776AB?style=flat-square" alt="部署指南"></a>
  <a href="references/security-layers.md"><img src="https://img.shields.io/badge/🛡️-七层防护-F59E0B?style=flat-square" alt="七层防护"></a>
  <a href="references/shamir-sharing.md"><img src="https://img.shields.io/badge/🔀-分片方案-EF4444?style=flat-square" alt="分片方案"></a>
  <a href="references/hardware-binding.md"><img src="https://img.shields.io/badge/📍-硬件绑定-10B981?style=flat-square" alt="硬件绑定"></a>
  <a href="scripts/keynl.py"><img src="https://img.shields.io/badge/💻-源码-6B7280?style=flat-square" alt="源码"></a>
</p>

<p align="center">
  <strong>别再把密码发进聊天窗了。<br>一个加密的、硬件绑定的、AI 也能安全使用的密码本。</strong>
</p>

<p align="center">
  <sub>scrypt 派生 · HSM/TPM 硬件绑定 · SHA-384 完整性 · Fernet AES · ECC P-384 · 内存锁</sub>
</p>

<p align="center">
  <a href="#-为什么需要它">🤔 为什么</a> ·
  <a href="#-两种做法对比">⚖️ 两种做法</a> ·
  <a href="#-项目优势">💪 优势</a> ·
  <a href="#-七层防护">🛡️ 七层防护</a> ·
  <a href="#-快速开始">🚀 快速开始</a> ·
  <a href="#-给-ai-用">🤖 给 AI 用</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/scrypt-KDF-22C55E?style=flat-square" alt="scrypt">
  <img src="https://img.shields.io/badge/ECC-P--384-8B5CF6?style=flat-square" alt="ECC">
  <img src="https://img.shields.io/badge/Shamir-3--of--5-F59E0B?style=flat-square" alt="Shamir">
  <img src="https://img.shields.io/badge/跨平台-Win%2FLinux%2FAndroid-10B981?style=flat-square" alt="跨平台">
</p>

---

## 🤔 为什么需要它

2026 年，人人都在用 AI 干活——Claude、GPT、豆包、各种 Agent。你会让 AI 帮你配服务器、部署网站、调用 API……但很多操作需要密码。

**问题来了：密码怎么给 AI？**

## ⚖️ 两种做法对比

### ❌ 传统做法：把密码直接发进聊天窗

```
你: "帮我配服务器，密码是 Abc123456，数据库密码 Xyz789"
AI: "好的，已配置"
```

你以为方便，实际发生了什么：

| 隐患 | 后果 |
|:---|:---|
| 密码进了聊天记录 | 聊天记录会同步到云端、可能被截图 |
| 密码进了 AI 训练数据 | 你的密码可能变成别人的补全结果 |
| 密码被 AI 复述 | AI 回答时可能把密码原样打出来 |
| 无法撤回 | 发出去的密码收不回来 |

> **把密码发进聊天窗 = 把密码告诉所有能看到聊天记录的人 + AI 服务商 + 未来的训练模型。**

### ✅ 正确做法：给 AI 一个密码本

```
你: "keynl setpass"          ← 设一次主密码
你: "keynl add db_pass"      ← AI 执行，密码走 getpass 输入，不进聊天窗
你: "keynl get db_pass"      ← AI 执行，密码只在本地解密，不回显给你看
```

| 对比 | 发聊天窗 | 密码本(keynl) |
|:---|:---|:---|
| 密码进聊天记录 | ❌ 进了 | ✅ 不进 |
| 密码进 AI 训练数据 | ❌ 进了 | ✅ 不进 |
| 密码存储 | 明文躺在云端 | 本地加密 + 硬件绑定 |
| 密码泄露风险 | 高 | 极低 |

---

## 💪 项目优势

| 优势 | 说明 |
|:---|:---|
| 🔒 **密码不经过聊天窗** | AI 通过命令操作，密码走 getpass，不进入对话记录 |
| 🧱 **七层加密** | scrypt + SHA-384 + 硬件绑定 + AES + ECC + 权限隔离 |
| 📍 **硬件绑定** | 密文复制到别的机器直接失效 |
| ♻️ **丢密码可恢复** | Shamir(3,5) 分片，任意3份恢复主密码 |
| 🌍 **跨平台** | Windows / Linux / Android(Termux) 都能用 |
| ⚡ **一条命令装** | `curl \| bash` 秒装，零编译依赖 |

---

## 🛡️ 七层防护

| 层 | 技术 | 防什么 |
|:---|:---|:---|
| L1 | scrypt（内存密集型 KDF） | 暴力破解、GPU/ASIC 并行攻击 |
| L2 | SHA-384 完整性哈希 | 密文篡改 |
| L3 | 硬件指纹绑定 | 密文复制到别的设备 |
| L4 | Fernet AES（AES-CBC + HMAC） | 无密钥解密 |
| L5 | ECC P-384 数字签名 | 密文替换、伪造 |
| L6 | 文件权限隔离 | 非本人读取 |
| L7 | 内存锁 mlock | 防 swap 泄漏 |

---

## 🚀 快速开始

**Linux / macOS / Termux：**

```bash
curl -fsSL https://raw.githubusercontent.com/furrynaling/agent-keynl/main/install.sh | bash
```

**Windows（PowerShell）：**

```powershell
irm https://raw.githubusercontent.com/furrynaling/agent-keynl/main/install.ps1 | iex
```

**首次使用：**

```bash
keynl setpass               # 设主密码（≥12位）
keynl add db_pass           # 存密码（密码走 getpass，不进聊天窗）
keynl get db_pass           # 读密码
keynl list                  # 列出所有（值自动脱敏 ***）
```

---

## 🤖 给 AI 用

把 `SKILL.md` 喂给你的 AI（Claude Code / 通用 Agent），它就学会了：

```
AI 会做的:
  keynl setpass          设主密码
  keynl add <名> <值>    存密钥（密码走 getpass）
  keynl get <名>         读密钥（不回显到聊天窗）
  keynl list             列表
  keynl changepass       改密码
  keynl shards           生成分片
  keynl recover          从分片恢复
```

**核心：AI 永远不把密码打出来，只用命令存取。**

---

## 📁 项目结构

```
agent-keynl/
├── SKILL.md          ← AI 技能定义
├── README.md         ← 本文件
├── install.sh        ← Linux/macOS/Termux 一键安装
├── install.ps1       ← Windows 一键安装
├── scripts/keynl.py ← 核心代码
└── references/       ← 详解文档
```

---

## 📜 许可

MIT License
