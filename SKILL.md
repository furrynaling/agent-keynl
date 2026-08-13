---
name: secret-management
description: "七层加密密钥库。在Linux服务器上安全存储API Key、SMTP密码、云平台凭证、CA私钥等敏感信息。核心能力：Argon2id内存密集型密钥派生（抗GPU/ASIC暴力破解）、硬件指纹绑定（MAC+机器ID+主机名+内核，密文复制到其他服务器即失效）、Shamir(3,5)门限分片（多钥匙恢复）、假文件完整性校验（删错诱饵文件即锁死）、伪装成Node.js项目目录（社会工程防护）、mlock内存锁（防swap泄漏）。当需要存储/读取/轮换密钥、搭建加密保险库、防范密钥泄露或勒索病毒时触发。"
allowed-tools: Bash Read Write Edit
when_to_use: "需要安全存储API密钥/密码/凭证时；搭建密钥保险库时；担心服务器被入侵后密钥泄露时；需要多钥匙恢复机制时；防范密钥被复制到其他服务器时。"
metadata:
  version: "3.0"
  platform: "linux-server"
  last_updated: "2026-08-13"
---

# 祈棂密钥库 (secret-management)

## 定位：密钥保险库，不是密码管理器

本 Skill 解决的核心问题：**服务器上的密钥如何"即使被偷走也无法使用"**。

与普通密码管理器（1Password/Bitwarden）的区别：
- 密码管理器：托管在云端，依赖第三方信任
- 本密钥库：跑在自己的服务器上，密钥永不离开机器，且绑定硬件指纹

## 核心理念

> 密钥不是"藏起来"，而是"即使被偷走也无法使用"。

传统做法的致命缺陷：

1. **明文存 .env / config** → 拿到 root 就看到一切
2. **写死在代码里** → 源码公开 = 密钥公开
3. **单层 AES 加密** → 密文复制到别的机器照样能解

本 Skill 的答案：**七层嵌套 + 硬件绑定 + 假文件陷阱**。

### 七层防护

| 层 | 技术 | 防什么 |
|:---|:---|:---|
| L1 | Argon2id（内存密集型 KDF） | 暴力破解、GPU/ASIC 并行攻击 |
| L2 | SHA-384 完整性哈希 | 密文篡改 |
| L3 | 硬件指纹绑定 | 密文复制到别的服务器 |
| L4 | Fernet AES（AES-128-CBC+HMAC-SHA256） | 无密钥解密 |
| L5 | ECC P-384 数字签名 | 密文替换、伪造 |
| L6 | 假文件完整性校验 | 目录被清理 |
| L7 | 文件权限隔离（600/700） | 非 root 读取 |

## 触发条件

1. 需要存储 API Key、SMTP 密码、云平台 SecretId/Key
2. 需要搭建密钥保险库 / 加密存储
3. 担心服务器被入侵后密钥泄露
4. 需要多钥匙恢复机制（防单密码丢失）
5. 需要防范密文被复制到其他服务器

## 核心工作流

### Step 1: 环境准备

```bash
pip install argon2-cffi cryptography
```

### Step 2: 部署 keymgr

```bash
cp scripts/keymgr.py /usr/local/bin/keymgr
chmod 700 /usr/local/bin/keymgr
```

### Step 3: 硬件指纹初始化

首次运行时自动采集并固化硬件指纹：
- MAC 地址
- 机器 ID（/etc/machine-id）
- 主机名
- 内核版本

四个值哈希混合 → 存入 hw.bin → 之后每次解密前比对。

### Step 4: 存储密钥

```bash
echo "主密码" | keymgr add cf_token "cfat_xxx"
echo "主密码" | keymgr add tc_secret "AKID_xxx"
```

### Step 5: 读取密钥

```bash
echo "主密码" | keymgr get cf_token
echo "主密码" | keymgr list
```

### Step 6: Shamir 分片（可选，推荐）

```bash
echo "主密码" | keymgr shards
```

生成 5 个分片，任意 3 个可恢复主密码。

## 关键决策

- **Argon2id 而非 PBKDF2**：内存密集型，抗 GPU/ASIC 并行攻击
- **硬件绑定而非纯密码**：密文离开原服务器即失效
- **Shamir(3,5) 而非单密码**：丢失 1-2 份分片仍可恢复，单份泄露无害
- **假文件陷阱而非隐藏**：伪装成 Node 项目 + 删除诱饵文件即锁死

## 常见坑

1. **换内核/换网卡** → 硬件指纹变化 → 解密失败。需提前重建 hw.bin
2. **误删假文件** → 密钥库锁死。重建被删文件 + 删 decoy.hash 恢复
3. **忘了主密码** → 无法恢复。必须用 Shamir 分片兜底
4. **Argon2id 内存参数过高** → 1GB 小内存服务器 OOM。建议 memory_cost=65536（64MB）

## 参考资料

- [security-layers.md](references/security-layers.md) — 七层防护详解
- [shamir-sharing.md](references/shamir-sharing.md) — Shamir 门限分片
- [hardware-binding.md](references/hardware-binding.md) — 硬件指纹绑定
- [deployment.md](references/deployment.md) — 部署指南
