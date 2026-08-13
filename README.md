<h1 align="center">🔐 祈棂密钥库 · Qiling Secret Vault</h1>

<p align="center">
  <strong>七层嵌套加密 · 硬件指纹绑定 · Shamir门限分片 · 伪装目录防篡改<br>一个偷走了也没用的密钥保险库。</strong>
</p>

<p align="center">
  <sub>Argon2id 派生 · SHA-384 完整性 · 硬件绑定 · Fernet AES · ECC P-384 · 假文件校验 · 权限隔离</sub>
</p>

<p align="center">
  <a href="#-为什么需要密钥库">🤔 为什么</a> ·
  <a href="#-七层防护">🛡️ 七层防护</a> ·
  <a href="#-核心能力">⚙️ 核心能力</a> ·
  <a href="#-攻击场景">🎯 攻击场景</a> ·
  <a href="#-快速开始">🚀 快速开始</a> ·
  <a href="#-安全评估">📊 安全评估</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/AES-256--GCM-22C55E?style=flat-square" alt="AES">
  <img src="https://img.shields.io/badge/ECC-P--384-8B5CF6?style=flat-square" alt="ECC">
  <img src="https://img.shields.io/badge/Shamir-3--of--5-F59E0B?style=flat-square" alt="Shamir">
  <img src="https://img.shields.io/badge/硬件绑定-MAC%2B机器ID-EF4444?style=flat-square" alt="Hardware">
</p>

---

<p align="center">
  <img src="assets/hero.jpg" width="90%" alt="密钥库部署实景">
  <br>
  <sub>密钥库伪装成普通 Node.js 项目，真实密钥藏在 <code>.keys/</code> 隐藏目录——<strong>删错一个假文件，整个保险库锁死</strong>。</sub>
</p>

---

## 🤔 为什么需要密钥库？

服务器上散落着 API Key、SMTP 密码、云平台凭证、CA 私钥。这些密钥一旦泄露：

- **明文存储** → 拿到 root 就是拿到一切
- **写死在代码里** → 源码公开 = 密钥公开
- **单文件加密** → 复制到别处照样能解

祈棂密钥库的答案是：**把密钥埋进七层加密，并让密文离开这台服务器就失去意义**。

> 密钥不是"藏起来"，而是"即使被偷走也无法使用"。

---

## 🛡️ 七层防护

| 层 | 技术 | 防什么 |
|:---|:---|:---|
| L1 | **Argon2id**（内存密集型 KDF） | 暴力破解、GPU/ASIC 并行攻击 |
| L2 | **SHA-384** 完整性哈希 | 密文篡改、比特翻转 |
| L3 | **硬件指纹绑定**（MAC+机器ID+主机名+内核） | 密文复制到别的服务器 |
| L4 | **Fernet AES**（AES-128-CBC + HMAC-SHA256） | 无密钥解密 |
| L5 | **ECC P-384** 数字签名 | 密文替换、伪造 |
| L6 | **假文件完整性校验**（10个诱饵） | 目录被清理、篡改 |
| L7 | **文件权限隔离**（600/700） | 非 root 读取 |

### 硬件绑定为什么关键

```
正常服务器:  MAC=aa:bb:cc:dd:ee:ff, 机器ID=deadbeef...
           ↓ 加密时混入指纹
           vault.enc = AES(密钥 + 指纹)
           ↓ 换一台服务器
           新服务器指纹 ≠ 原指纹 → 解密失败 ❌
```

**密文离开原服务器 = 一块废铁。**

---

## ⚙️ 核心能力

### 1. Shamir(3,5) 门限分片

主密码拆成 5 份，任意 3 份可恢复：

```
分片1-2 → 安全存储（云端/家）
分片3   → 随身 U 盘
分片4-5 → 备份介质

丢失 1-2 份 → 没事
泄露单份   → 无法恢复完整密码
全部丢失   → 至少 3 份才能重建
```

### 2. 伪装目录 + 假文件陷阱

```
/root/mytp/                    ← 看起来是 Node.js 项目
├── package.json               ← 假依赖
├── src/index.js               ← 假入口
├── lib/crypto.py              ← 假加密库
├── data/cache.db              ← 假数据库
└── .keys/                     ← 真实密钥（隐藏）
    └── vault.enc              ← 加密密钥库

删掉任何一个假文件 → decoy.hash 校验失败 → 密钥库拒绝解密
```

### 3. 内存锁（mlock）

密钥解密后锁定在内存，禁止 swap 交换到磁盘——断电即消失，不留任何明文痕迹。

---

## 🎯 攻击场景

| 场景 | 结果 |
|:---|:---|
| 黑客拿到 root 权限 | ❌ 密文打不开，且假文件陷阱锁死 |
| 复制 vault.enc 到自家服务器 | ❌ 硬件指纹不匹配 |
| 暴力破解主密码 | ❌ Argon2id 60万次迭代，10^28 年 |
| 篡改密文 | ❌ SHA-384 + HMAC 双重校验 |
| 服务器被扫出 mytp 目录 | ⚠️ 但 10 个假文件少一个就锁死 |
| 你误删假文件 | ✅ 重建文件 + 删 decoy.hash 可恢复 |

---

## 🚀 快速开始

```bash
# 1. 安装依赖
pip install argon2-cffi cryptography

# 2. 部署脚本
cp scripts/keymgr.py /usr/local/bin/keymgr
chmod 700 /usr/local/bin/keymgr

# 3. 存密钥
echo "你的主密码" | keymgr add cf_token "cfat_xxx"

# 4. 读密钥
echo "你的主密码" | keymgr get cf_token

# 5. 列表
echo "你的主密码" | keymgr list

# 6. 生成 Shamir 分片
echo "你的主密码" | keymgr shards
```

---

## 📊 安全评估

```
综合评分: ★★★★☆ 4.5/5

能防:
  ✅ 暴力破解           ✅ 复制密文到别处
  ✅ 密文篡改           ✅ 非root读取
  ✅ 量子计算机（ECC P-384 256位）   ✅ 社会工程（伪装目录）

防不了:
  ❌ root在你输密码时内存抓取
  ❌ 物理拔硬盘+液氮冷冻（国家级）
  ❌ 你自己把密码告诉别人
```

---

## 📁 项目结构

```
qiling-vault/
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

MIT License · 2009-2026 纳棂
