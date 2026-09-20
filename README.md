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
| ⛓️ **区块链存证** | emoji 表情防篡改 + IPFS + 比特币时间戳 |

---

## 🛡️ 七层防护

| 层 | 技术 | 防什么 |
|:---|:---|:---|
| L1 | scrypt（内存密集型 KDF，混入 env.key） | 暴力破解、GPU/ASIC 并行攻击 |
| L2 | SHA-384 完整性哈希 | 密文篡改 |
| L3 | 硬件指纹绑定 | 密文复制到别的设备 |
| L4 | **AES-256-GCM**（AEAD，带认证标签；无 AES-NI 的机器自动用 ChaCha20-Poly1305） | 无密钥解密、密文被篡改 |
| L5 | ECC P-384 指纹绑定（库内嵌本机公钥指纹） | 库被换成另一份 |
| L6 | 文件权限隔离（0600/0700） | 非本人读取 |
| L7 | 内存锁 mlock | 防 swap 泄漏 |
| L8 | **纯本地：零上报** | 数据外泄（见下） |

**🔒 纯本地（v4.19.0 起）**：解密记录、调用记录、上链、审查中心**全部移除** —— 本工具不向任何服务器发送任何数据（连哈希都不发）。唯一的联网动作是你自己敲的 `keynl update`（从 GitHub 拉新版脚本）。

**🔐 库加密格式**：`GCM1:` = AES-256-GCM（默认）、`CHP1:` = ChaCha20-Poly1305（无 AES-NI 的机器自动选它）、无前缀 = 旧版 Fernet 格式（继续可读，改一次密码即自动升级为新格式）。

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
keynl doctor                # 🩺 库体检：不用主密码，验证分片还救不救得回主密码（生成分片后必跑）
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

### 🔥 阅后即焚调用（api-run）—— 给 AI 的正式姿势

别让 AI 把密钥打到屏幕上（会进对话记录、日志文件）。正确姿势：

```bash
# 密钥只注入子进程环境变量：不打印、不进日志、不落磁盘
keynl api-run smtp -- curl -u "$smtp_user:$smtp_pass" https://api.example.com/send

# 限次使用：跑 30 次自动销毁凭据（适合定时任务）
keynl api-run smtp --uses 30 -- ./定时任务.sh

# 阅后即焚：用一次就把凭据烧掉
keynl api-run smtp --once -- ./一次性脚本.sh
```

**"不会被软件抓到"的正确边界**（说实话）：

| | 情况 |
|:--|:--|
| ✅ | 密钥不出现在 stdout、AI 对话记录、日志文件、命令行参数（`ps` 里看不到） |
| ⚠️ | 子进程运行期间，**本机 root** 能从 `/proc/<pid>/environ` 读到（操作系统层面的，任何方案都躲不掉） |
| ✅ | 所以配合 `--uses N` / `--once` 用完即焚，把暴露窗口压到最小 |
| ✅ | 凭据是**窄范围**的：一份导出只含指定的几个键；吊销只删这对文件 |

---

## 🔏 库签名（防掉包）

每次保存库，都会用本机 **ECC P-384 私钥**给库文件盖一次章（ECDSA + SHA-384 → `vault.sig`）：

- 打开库时**自动验签**：签名对不上就**拒绝打开**（确认无误可 `KEYNL_FORCE=1` 强开）
- `keynl doctor` 显示签名状态 + **公钥指纹**
- `keynl setpass` 时会打印公钥指纹 → **建议抄走**（纸上/手机）

> ⚠️ 诚实说明：私钥就在本机，能拿下本机的人可以连私钥一起换掉。所以这道签名真正的价值是：**改了库文件会被当场发现** + **你把指纹抄走后，就防得住"库被整体掉包"**。

---

## 🩺 库体检（doctor）

**不用主密码**就能查清："这个库现在还开不开得起来？分片还救不救得回主密码？"

```bash
keynl doctor          # 或菜单里选 18
```

它会逐项检查并给出结论：

| 检查项 | 为什么会挂 |
|:---|:---|
| **环境密钥 env.key** | 丢了 = 库**永久**打不开（必须单独备份） |
| **硬件指纹 hw.bin** | 不一致 = 换了内核/网卡/主机名，或库来自别的机器 |
| **ECC 密钥** | 库内指纹校验的前提，丢了就解不开 |
| **库文件** | 是否存在、是否被改动（同时给出 8 个 emoji 指纹） |
| **分片（决定性检查）** | 任取 k 片还原口令 → **真的去解一次库**；解不开说明分片过期/损坏，**忘主密码时救不回来** |
| **多子集一致性** | 不同 k 片组合还原结果必须一致，不一致=分片相互矛盾 |

退出码：正常 `0`、有异常 `1` —— 可以挂到 cron 做静默体检（正常时不打扰，异常才报警）。

---

## 🔐 安全最佳实践（看完这几条再用）

1. **分片必须离开这台机器**：分片和库放在同一台机器/同一个目录 = 拿到磁盘的人能直接还原你的主密码，等于没设门禁。**3 片离线（纸上/U盘/另一台设备），本机最多留 2 片（低于门限就无害）**
2. **env.key 要单独备份**：它不参与密码校验，但**丢了库就永久打不开**（它和库分开放，才算真正的两道锁）
3. **硬件指纹是"软绑定"**：hw.bin 是个明文文件，有 root 的人可以改它绕过 → 它防的是"整份拷走到别的机器"，不防"本机被拿下"
4. **主密码是最后一道锁**：它没写在任何地方。服务器被接管时真正救你的只有——**别在被控的机器上输主密码** + 手上的离线分片
5. **日常自动化别留明文密码**：给脚本/服务用就 `keynl export` 生成 **AI token 类型**的窄范围导出（只含它需要的键），取用完即焚；服务端启动时把密钥投递到 `/dev/shm`（内存），磁盘不留
6. **撤销**：删掉 `export/<名>.enc` + `<名>.token` 即吊销该自动化凭据，不影响其它

---

## 👥 给朋友用（3 步上手）

```bash
# 1) 装
curl -fsSL https://raw.githubusercontent.com/furrynaling/agent-keynl/main/install.sh | bash

# 2) 建库（主密码 ≥12 位，自己记住，别存在任何地方）
keynl setpass

# 3) 生成分片 → 立刻体检 → 把分片抄走/拷到别的设备
keynl            # 菜单 7 生成分片
keynl doctor     # 必须看到「决定性检查：k 片还原出的口令能解开库」才算成功
```

> ⚠️ 看到分片健康告警**先别删任何东西**，把 doctor 的输出发出来一起看。

---

## 📁 项目结构

```
agent-keynl/
├── SKILL.md           ← AI 技能定义
├── README.md          ← 本文件
├── CHANGELOG.md       ← 更新日志
├── install.sh         ← Linux/macOS/Termux 一键安装
├── install.ps1        ← Windows 一键安装
├── scripts/keynl.py   ← 核心代码（单文件，仅依赖 cryptography）
└── references/        ← 详解文档
```

> 本机默认数据目录 `~/.agent-keynl/`（`vault.enc` 密文 + `env.key` + `hw.bin` + `shards/`）。
> 换目录：设环境变量 `KEYNL_DIR=<目录>`。

---

## 📜 许可

MIT License
