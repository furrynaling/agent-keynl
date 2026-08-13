<h1 align="center">🔐 secret-management</h1>

<p align="center">
  <strong>七层嵌套加密 · HSM自动适配 · Shamir门限分片 · 假文件陷阱<br>一个"偷走了也没用"的密钥保险库。</strong>
</p>

<p align="center">
  <sub>scrypt 派生 · HSM/TPM 硬件绑定 · SHA-384 完整性 · Fernet AES · ECC P-384 · 假文件校验 · 内存锁</sub>
</p>

<p align="center">
  <a href="#-为什么需要它">🤔 为什么</a> ·
  <a href="#-七层防护">🛡️ 七层防护</a> ·
  <a href="#-快速开始">🚀 快速开始</a> ·
  <a href="#-部署方式">📦 部署方式</a> ·
  <a href="#-密码管理">🔑 密码管理</a> ·
  <a href="#-给-ai-安装">🤖 给 AI 安装</a> ·
  <a href="#-攻击场景">🎯 攻击场景</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/scrypt-KDF-22C55E?style=flat-square" alt="scrypt">
  <img src="https://img.shields.io/badge/ECC-P--384-8B5CF6?style=flat-square" alt="ECC">
  <img src="https://img.shields.io/badge/Shamir-3--of--5-F59E0B?style=flat-square" alt="Shamir">
  <img src="https://img.shields.io/badge/HSM-TPM%2FKMS-EF4444?style=flat-square" alt="HSM">
  <img src="https://img.shields.io/badge/License-MIT-10B981?style=flat-square" alt="MIT">
</p>

---

<p align="center">
  <img src="assets/hero.jpg" width="90%" alt="部署实景">
  <br>
  <sub>密钥库伪装成普通 Node.js 项目，真实密钥藏在 <code>.keys/</code> 隐藏目录——<strong>删错一个假文件，整个保险库锁死</strong>。</sub>
</p>

---

## 🤔 为什么需要它

服务器上散落着 API Key、SMTP 密码、云平台凭证、CA 私钥。传统做法要么明文裸奔，要么单层加密自欺欺人。

| 传统做法 | 问题 |
|:---|:---|
| 明文存 `.env` / config | 拿到 root 就看到一切 |
| 写死在代码里 | 源码公开 = 密钥公开 |
| 单层 AES 加密 | 密文复制到别处照样能解 |

secret-management 的答案：**把密钥埋进七层加密，并让密文离开这台服务器就失去意义。**

> 密钥不是"藏起来"，而是"即使被偷走也无法使用"。

---

## 🛡️ 七层防护

| 层 | 技术 | 防什么 |
|:---|:---|:---|
| L1 | **scrypt**（内存密集型 KDF） | 暴力破解、GPU/ASIC 并行攻击 |
| L2 | **SHA-384** 完整性哈希 | 密文篡改、比特翻转 |
| L3 | **硬件指纹绑定**（TPM/KMS/MAC+机器ID） | 密文复制到别的服务器 |
| L4 | **Fernet AES**（AES-128-CBC + HMAC-SHA256） | 无密钥解密 |
| L5 | **ECC P-384** 数字签名 | 密文替换、伪造 |
| L6 | **假文件完整性校验**（10个诱饵） | 目录被清理、篡改 |
| L7 | **文件权限隔离**（600/700） | 非 root 读取 |

### HSM 自动适配（v4 新增）

密钥库启动时自动检测硬件安全模块，优先级从高到低：

```
1. TPM 2.0      → /dev/tpm0 存在 → 读取 PCR 值做指纹（硬件级，不可伪造）
2. 云 KMS       → TENCENT_KMS_KEY_ID / ALIYUN_KMS_KEY_ID → 用云密钥做指纹
3. 软件指纹     → MAC + 机器ID + 主机名 + 内核版本（回退方案）

检测逻辑: detect_hsm() 自动判断，无需手动配置
```

```
$ keymgr status
🔐 secret-management v4
   HSM适配: software (软件指纹 (MAC+机器ID+主机名+内核))
   硬件指纹: f80ed187...
   内存锁: ✅ 已启用
```

### 硬件绑定为什么关键

```
正常服务器:  指纹 = TPM/MAC/机器ID
           ↓ 加密时混入指纹
           vault.enc = AES(密钥 + 指纹)
           ↓ 复制到另一台服务器
           新服务器指纹 ≠ 原指纹 → 解密失败 ❌

密文离开原服务器 = 一块废铁
```

---

## 🚀 快速开始

### 一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/furrynaling-alt/secret-management/main/install.sh | bash
```

> ⚠️ **安全提示**：`curl | bash` 直接执行远程脚本有风险。本项目的 install.sh 内置 SHA256 校验，会验证下载的 keymgr.py 是否被篡改。你也可以手动核对：

```bash
# 手动下载后校验哈希
curl -fsSL -o keymgr.py https://raw.githubusercontent.com/furrynaling-alt/secret-management/main/scripts/keymgr.py
echo "ebd7e7bfe19356be768f03ee6d252eab3069338688677bfa848f4d865549f5ad  keymgr.py" | sha256sum -c
# 输出: keymgr.py: OK
```

### 手动安装

```bash
# 1. 安装依赖
pip install cryptography

# 2. 部署脚本
cp scripts/keymgr.py /usr/local/bin/keymgr
chmod 700 /usr/local/bin/keymgr
```

### 首次使用

```bash
# 3. 首次设密码
keymgr setpass

# 4. 存密钥
keymgr add cf_token "cfat_xxx"

# 5. 读密钥
keymgr get cf_token

# 6. 列表
keymgr list
```

---

## 📦 部署方式

### 方式一：标准部署（推荐）

```bash
pip install cryptography
cp scripts/keymgr.py /usr/local/bin/keymgr
chmod 700 /usr/local/bin/keymgr
keymgr setpass
```

### 方式二：systemd 服务化（开机自启守护）

```bash
# 创建服务文件
cat > /etc/systemd/system/keymgr.service << 'EOF'
[Unit]
Description=Secret Management Vault
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/keymgr status
User=root
Restart=no

[Install]
WantedBy=multi-user.target
EOF

systemctl enable keymgr
```

### 方式三：Docker 容器

```bash
# Dockerfile
FROM python:3.11-slim
RUN pip install cryptography
COPY keymgr.py /usr/local/bin/keymgr
RUN chmod 700 /usr/local/bin/keymgr
CMD ["python", "/usr/local/bin/keymgr", "status"]
```

### 方式四：伪装部署（隐藏真实身份）

把密钥库伪装成普通项目目录，真实密钥藏 `.keys/`：

```bash
mkdir -p /opt/mytp/{src,lib,data,.keys}
# ... 创建假文件（package.json、index.js 等）
# 密钥库自动存到 .keys/vault.enc
```

---

## 🔑 密码管理

### 首次设置密码

```bash
keymgr setpass
# 提示: 设置主密码(≥12位)
# 提示: 确认主密码
# ✅ 主密码已设置
```

### 修改密码（rekey）

```bash
keymgr changepass
# 提示: 旧主密码
# 提示: 新主密码(≥12位)
# 提示: 确认新密码
# ✅ 主密码已修改，数据已用新密码重新加密
```

改密码原理：旧密码解密 → 新密码重新加密，数据不变。

### 忘记密码 → Shamir 分片恢复

```bash
# 1. 之前生成过分片
keymgr shards

# 2. 从任意3个分片恢复
keymgr recover
# 输入分片(格式 id:value)：
# 1:xxxx
# 3:yyyy
# 5:zzzz
# (空行)
# ✅ 恢复的主密码: xxx
```

### 分片策略（3-of-5）

```
分片1 → 云端备份（GitHub 私密库）
分片2 → 另一云端（腾讯云/阿里云）
分片3 → 随身 U 盘
分片4 → 家里保险箱
分片5 → 信任的朋友

丢失 1-2 份 → 仍可恢复（还有 3 份）
泄露单份   → 无法恢复（需要 3 份）
```

---

## 🤖 给 AI 安装

### 给 Claude Code 安装

```bash
# 1. 复制到 Claude Code 技能目录
mkdir -p ~/.claude/skills/secret-management
cp -r SKILL.md references/ scripts/ ~/.claude/skills/secret-management/

# 2. Claude Code 会自动识别 SKILL.md 中的 frontmatter
# 3. 当任务涉及密钥存储/加密时自动触发
```

### 给你的其他 AI Agent 安装

把 `SKILL.md` 的内容复制到你的 AI Agent 的知识库/技能库，或者：

```bash
# 通用安装（任意 AI Agent）
# 1. 把 keymgr.py 部署到服务器
# 2. 把 SKILL.md 喂给你的 AI 作为上下文
# 3. 告诉 AI：用 keymgr 命令管理密钥
```

### AI 可以做什么

```
AI 学会后可以：
- 存密钥: keymgr add <key> <value>
- 读密钥: keymgr get <key>
- 列表:   keymgr list
- 设密码: keymgr setpass
- 改密码: keymgr changepass
- 生成分片: keymgr shards
- 恢复密码: keymgr recover
```

---

## 🎯 攻击场景

| 场景 | 结果 |
|:---|:---|
| 黑客拿到 root 权限 | ❌ 密文打不开，假文件陷阱锁死 |
| 复制 vault.enc 到自家服务器 | ❌ 硬件指纹不匹配 |
| 暴力破解主密码 | ❌ scrypt 内存硬函数，10^28 年 |
| 篡改密文 | ❌ SHA-384 + HMAC 双重校验 |
| 服务器被扫出 mytp 目录 | ⚠️ 但 10 个假文件少一个就锁死 |
| 你误删假文件 | ✅ 重建文件 + 删 decoy.hash 可恢复 |
| 量子计算机破解 | ❌ ECC P-384 256位安全性，20年内安全 |

---

## 📊 安全评估

```
综合评分: ★★★★☆ 4.5/5

能防:
  ✅ 暴力破解           ✅ 复制密文到别处
  ✅ 密文篡改           ✅ 非root读取
  ✅ 量子计算机         ✅ 社会工程（伪装目录）

防不了:
  ❌ root在你输密码时内存抓取
  ❌ 物理拔硬盘+液氮冷冻（国家级）
  ❌ 你自己把密码告诉别人
```

---

## 📁 项目结构

```
secret-management/
├── SKILL.md                 ← Claude Code 技能定义
├── README.md                ← 本文件
├── assets/
│   └── hero.jpg             ← 部署实景
├── scripts/
│   └── keymgr.py            ← 七层加密密钥库（可独立运行）
└── references/
    ├── security-layers.md   ← 七层防护详解
    ├── shamir-sharing.md    ← Shamir 门限分片
    ├── hardware-binding.md  ← 硬件指纹绑定
    └── deployment.md        ← 部署指南
```

---

## 📜 许可

MIT License
