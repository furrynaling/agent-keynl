# 硬件指纹绑定

## 核心思想

> 密文离开原服务器 = 一块废铁。

加密时把服务器的硬件指纹混入密钥派生，解密时重新采集比对。密文复制到任何其他机器都无法解密。

## HSM 自动适配（三级）

密钥库启动时自动检测硬件安全模块，优先级从高到低：

### 1. TPM 2.0（首选）

```
检测: /dev/tpm0 或 /dev/tpmrm0 存在
读取: tpm2_pcrread sha256:0 → PCR 寄存器值
特点: 硬件级，无法被软件伪造
```

```bash
# 确认有 TPM
ls /dev/tpm0 /dev/tpmrm0
# 读 PCR 值
tpm2_pcrread sha256:0
```

TPM 的 PCR 值在每次系统启动时由硬件生成，无法被软件伪造，是最可靠的指纹来源。

### 2. 云 KMS（云服务器）

```
检测: 环境变量 TENCENT_KMS_KEY_ID 或 ALIYUN_KMS_KEY_ID
读取: 云密钥 ID 做指纹
特点: 云厂商托管，适合云服务器
```

```bash
# 配置云 KMS
export TENCENT_KMS_KEY_ID="cmk-xxxxx"
# 或
export ALIYUN_KMS_KEY_ID="xxxxxxxx"
```

### 3. 软件指纹（回退方案）

无 TPM/云 KMS 时，回退到软件采集：

```python
def get_hw_fingerprint():
    parts = [
        # 1. 机器 ID（systemd 生成，重装系统才变）
        SHA256(open('/etc/machine-id').read())[:16],
        # 2. 主机名
        SHA256(hostname)[:16],
        # 3. 内核版本
        SHA256(uname -r)[:16],
        # 4. MAC 地址
        SHA256(ip link show eth0 | grep ether)[:16],
    ]
    return ''.join(parts)
```

## 查看当前适配

```bash
keynl status
# HSM适配: tpm / cloud-kms / software
```

## 攻击场景

| 场景 | 结果 |
|:---|:---|
| 复制 vault.enc 到另一台服务器 | ❌ 指纹不匹配 |
| 克隆整个磁盘到不同硬件 | ❌ MAC/机器ID/TPM 变化 |
| 换网卡 | ⚠️ MAC 变化 → 需重建 |
| 重装系统 | ⚠️ 机器ID 变化 → 需重建 |
| 升级内核 | ⚠️ 内核版本变化 → 需重建 |
| 伪造软件指纹 | ⚠️ 需同时获取4个值（软件指纹局限） |
| 伪造 TPM PCR 值 | ❌ 硬件级，无法伪造 |

## 迁移 / 恢复

需要迁移密钥库到新服务器时：

1. 新服务器 `keynl` 生成新指纹
2. 用 Shamir 分片恢复主密码
3. 新服务器用主密码重建 vault（自动绑定新指纹）

## 局限与应对

| 指纹类型 | 局限 | 应对 |
|:---|:---|:---|
| TPM 2.0 | 需物理硬件支持 | 云服务器通常无，用 KMS |
| 云 KMS | 依赖云厂商 | 配置环境变量 |
| 软件指纹 | 内核升级/换网卡会变 | 升级前用分片备份 |

## 安全等级对比

```
TPM 2.0    → ★★★★★ 硬件级，最可靠
云 KMS     → ★★★★☆ 云厂商托管，较可靠
软件指纹   → ★★★☆☆ 软件采集，可被伪造（但需同时获取4值）
```

条件允许时优先 TPM 2.0，其次云 KMS，最后软件指纹。
