#!/usr/bin/env python3
"""secret-management v4 · Argon2id + HSM自动适配 + Shamir + mlock"""
import os, sys, json, hashlib, base64, getpass, secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from argon2 import PasswordHasher
import ctypes

# 可配置路径（环境变量覆盖）
VAULT = os.environ.get("KEYMGR_VAULT", "/root/mytp/.keys/vault.enc")
ECC_KEY_FILE = os.environ.get("KEYMGR_ECC", "/root/mytp/.keys/ecc.key")
HW_FILE = os.environ.get("KEYMGR_HW", "/root/mytp/.keys/hw.bin")
SHAMIR_DIR = os.environ.get("KEYMGR_SHARDS", "/root/mytp/.keys/shards")
BASE_DIR = os.path.dirname(VAULT) or "/root/mytp/.keys"

# ===== Argon2id 密码哈希 =====
ph = PasswordHasher(time_cost=4, memory_cost=65536, parallelism=2, hash_len=32)

def derive_key(password):
    """Argon2id → 内存密集型 → 抗ASIC/GPU"""
    salt = b"secret_management_kdf_salt_v4"
    raw = ph.hash(password, salt=salt)
    return base64.urlsafe_b64encode(hashlib.sha256(raw.encode()).digest())

# ===== HSM / TPM 自动适配 =====
def detect_hsm():
    """检测硬件安全模块，返回 (类型, 指纹来源描述)"""
    # 1. TPM 2.0（Linux 内核暴露 /dev/tpm0 或 /dev/tpmrm0）
    if os.path.exists('/dev/tpm0') or os.path.exists('/dev/tpmrm0'):
        try:
            pcr = os.popen("tpm2_pcrread sha256:0 2>/dev/null || cat /sys/class/tpm/tpm0/pcr-sha256/0 2>/dev/null").read().strip()
            if pcr:
                return 'tpm', f"TPM 2.0 (PCR0={hashlib.sha256(pcr.encode()).hexdigest()[:12]}...)"
        except:
            pass
    
    # 2. 云 KMS（腾讯云/阿里云 KMS 通过环境变量）
    if os.environ.get('TENCENT_KMS_KEY_ID') or os.environ.get('ALIYUN_KMS_KEY_ID'):
        kms_id = os.environ.get('TENCENT_KMS_KEY_ID') or os.environ.get('ALIYUN_KMS_KEY_ID')
        return 'cloud-kms', f"云KMS ({kms_id[:8]}...)"
    
    # 3. 回退软件指纹
    return 'software', "软件指纹 (MAC+机器ID+主机名+内核)"

def get_hw_fingerprint():
    """硬件指纹：优先 TPM/KMS，回退软件指纹"""
    hsm_type, _ = detect_hsm()
    
    if hsm_type == 'tpm':
        try:
            pcr = os.popen("tpm2_pcrread sha256:0 2>/dev/null").read().strip()
            if pcr:
                return hashlib.sha256(('tpm:' + pcr).encode()).hexdigest()[:64]
        except:
            pass
    elif hsm_type == 'cloud-kms':
        kms_id = os.environ.get('TENCENT_KMS_KEY_ID') or os.environ.get('ALIYUN_KMS_KEY_ID', '')
        return hashlib.sha256(('kms:' + kms_id).encode()).hexdigest()[:64]
    
    # 软件指纹（回退）
    parts = []
    try:
        parts.append(hashlib.sha256(open('/etc/machine-id','rb').read().strip()).hexdigest()[:16])
    except: parts.append("0"*16)
    try:
        parts.append(hashlib.sha256(os.popen('hostname').read().strip().encode()).hexdigest()[:16])
    except: parts.append("0"*16)
    try:
        parts.append(hashlib.sha256(os.popen('uname -r').read().strip().encode()).hexdigest()[:16])
    except: parts.append("0"*16)
    try:
        mac = os.popen("ip link show eth0 2>/dev/null|grep ether|awk '{print $2}'").read().strip()
        parts.append(hashlib.sha256(mac.encode()).hexdigest()[:16])
    except: parts.append("0"*16)
    return ''.join(parts)

def check_hw():
    current = get_hw_fingerprint()
    if not os.path.exists(HW_FILE):
        os.makedirs(os.path.dirname(HW_FILE), exist_ok=True)
        with open(HW_FILE, 'w') as f: f.write(current)
        os.chmod(HW_FILE, 0o600); return True
    return current == open(HW_FILE).read().strip()

# ===== Shamir 门限分片（3/5） =====
def shamir_split(secret, n=5, k=3):
    prime = 2**127 - 1
    coeffs = [int.from_bytes(secret, 'big')] + [secrets.randbelow(prime) for _ in range(k-1)]
    def eval_poly(x): return sum(c * (x**i) % prime for i, c in enumerate(coeffs)) % prime
    return {i: eval_poly(i) for i in range(1, n+1)}

def shamir_recover(shares):
    prime = 2**127 - 1
    secret = 0
    for i, yi in shares.items():
        num = den = 1
        for j in shares:
            if i != j:
                num = num * (-j) % prime
                den = den * (i - j) % prime
        lagrange = yi * num * pow(den, -1, prime) % prime
        secret = (secret + lagrange) % prime
    return secret.to_bytes((secret.bit_length()+7)//8, 'big')

def save_shards(password):
    import json as _json
    shares = shamir_split(password.encode())
    os.makedirs(SHAMIR_DIR, exist_ok=True)
    for i, val in shares.items():
        with open(f"{SHAMIR_DIR}/shard_{i}.key", 'w') as f:
            _json.dump({"id": i, "value": val}, f)
    with open(f"{SHAMIR_DIR}/info.txt", 'w') as f:
        f.write("Shamir(3,5)门限\n分片1-2: 安全存储\n分片3: 随身U盘\n分片4-5: 备份")
    os.chmod(SHAMIR_DIR, 0o700)
    print("✅ 5个分片已生成")

# ===== 内存锁 =====
try:
    libc = ctypes.CDLL("libc.so.6")
    libc.mlockall(1 | 2)  # MCL_CURRENT | MCL_FUTURE
    MLOCK_OK = True
except:
    MLOCK_OK = False

# ===== ECC 密钥 =====
if os.path.exists(ECC_KEY_FILE):
    SERVER_ECC_KEY = serialization.load_pem_private_key(open(ECC_KEY_FILE,'rb').read(), password=None)
else:
    SERVER_ECC_KEY = ec.generate_private_key(ec.SECP384R1())
    os.makedirs(os.path.dirname(ECC_KEY_FILE), exist_ok=True)
    with open(ECC_KEY_FILE, 'wb') as f:
        f.write(SERVER_ECC_KEY.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))
    os.chmod(ECC_KEY_FILE, 0o600)

def get_ecc_fp():
    pub = SERVER_ECC_KEY.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha384(pub).hexdigest()[:24]

# ===== 假文件校验 =====
DECOY_FILES = [os.path.join(BASE_DIR, "..", f) for f in ["package.json","README.md","launcher.sh","src/index.js","src/config.js","lib/utils.py","lib/crypto.py","data/cache.db","data/sessions.bin","data/server.log"]]
DECOY_FILES = [os.path.abspath(f) for f in DECOY_FILES]
DECOY_HASH_FILE = os.path.join(BASE_DIR, "decoy.hash")

def check_decoys():
    hashes = []
    for f in sorted(DECOY_FILES):
        if not os.path.exists(f): raise Exception(f"❌ 伪装文件缺失: {f}")
        hashes.append(hashlib.sha256(open(f,'rb').read()).hexdigest()[:8])
    return ':'.join(hashes)

def verify_decoys():
    if not os.path.exists(DECOY_HASH_FILE):
        with open(DECOY_HASH_FILE,'w') as f: f.write(check_decoys()); return True
    if check_decoys() != open(DECOY_HASH_FILE).read().strip():
        raise Exception("❌ 伪装文件被篡改!")

# ===== 主接口 =====
def load_vault(password):
    if not os.path.exists(VAULT): return {}
    verify_decoys()
    if not check_hw(): raise Exception("❌ 硬件指纹不匹配! 密文可能被复制到其他服务器")
    key = derive_key(password)
    f = Fernet(key)
    data = json.loads(f.decrypt(open(VAULT,'rb').read()))
    if data.pop('_ecc_fp','') != get_ecc_fp(): raise Exception("❌ ECC指纹不匹配!")
    if data.pop('_sha384','') != hashlib.sha384(json.dumps({k:v for k,v in data.items() if not k.startswith('_')}, sort_keys=True).encode()).hexdigest():
        raise Exception("❌ 完整性校验失败!")
    return {k:v for k,v in data.items() if not k.startswith('_')}

def save_vault(password, data):
    clean = {k:v for k,v in data.items() if not k.startswith('_')}
    clean['_sha384'] = hashlib.sha384(json.dumps(clean, sort_keys=True).encode()).hexdigest()
    clean['_ecc_fp'] = get_ecc_fp()
    key = derive_key(password)
    f = Fernet(key)
    os.makedirs(os.path.dirname(VAULT), exist_ok=True)
    with open(VAULT, 'wb') as fh: fh.write(f.encrypt(json.dumps(clean).encode()))
    os.chmod(VAULT, 0o600)

def cmd_setpass():
    """首次设置主密码"""
    if os.path.exists(VAULT):
        print("❌ 密钥库已存在，用 changepass 修改密码")
        return
    p1 = getpass.getpass("🔑 设置主密码(≥12位): ")
    if len(p1) < 12:
        print("❌ 密码太短，至少12位")
        return
    p2 = getpass.getpass("🔑 确认主密码: ")
    if p1 != p2:
        print("❌ 两次输入不一致")
        return
    save_vault(p1, {})
    print("✅ 主密码已设置，密钥库已初始化")
    print("💡 建议立即生成分片: keymgr shards")

def cmd_changepass():
    """修改主密码"""
    if not os.path.exists(VAULT):
        print("❌ 密钥库不存在，用 setpass 初始化")
        return
    old = getpass.getpass("🔑 旧主密码: ")
    try:
        data = load_vault(old)
    except Exception as e:
        print(f"❌ 旧密码错误: {e}")
        return
    p1 = getpass.getpass("🔑 新主密码(≥12位): ")
    if len(p1) < 12:
        print("❌ 密码太短")
        return
    p2 = getpass.getpass("🔑 确认新密码: ")
    if p1 != p2:
        print("❌ 两次输入不一致")
        return
    save_vault(p1, data)
    print("✅ 主密码已修改，数据已用新密码重新加密")

def print_status():
    hsm_type, hsm_desc = detect_hsm()
    print("🔐 secret-management v4")
    print(f"   HSM适配: {hsm_type} ({hsm_desc})")
    print(f"   硬件指纹: {get_hw_fingerprint()[:32]}...")
    print(f"   内存锁: {'✅ 已启用' if MLOCK_OK else '⚠️ 未启用(swap可能泄漏)'}")
    print(f"   密钥库: {'✅ 已初始化' if os.path.exists(VAULT) else '❌ 未初始化(setpass)'}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_status()
        sys.exit(0)
    
    cmd, args = sys.argv[1], sys.argv[2:]
    
    if cmd == "setpass":
        cmd_setpass()
    elif cmd == "changepass":
        cmd_changepass()
    elif cmd == "status":
        print_status()
    else:
        password = getpass.getpass("🔑 主密码: ")
        if cmd == "add" and args:
            data = load_vault(password) if os.path.exists(VAULT) else {}
            data[args[0]] = ' '.join(args[1:]) if len(args)>1 else getpass.getpass(f"🔑 {args[0]} 的值: ")
            save_vault(password, data)
            print(f"✅ {args[0]}")
        elif cmd == "get" and args:
            print(load_vault(password).get(args[0], "❌"))
        elif cmd == "list":
            data = load_vault(password)
            if not data: print("  (空)")
            for k,v in sorted(data.items()):
                print(f"  {k}: {'***' if len(v)>20 else v}")
        elif cmd == "shards":
            save_shards(password); 
        elif cmd == "recover":
            # 从分片恢复密码
            print("输入分片(格式: id:value，空行结束):")
            shares = {}
            while True:
                line = input()
                if not line: break
                try:
                    i, v = line.split(':')
                    shares[int(i)] = int(v)
                except: print("格式错误，用 id:value")
            if len(shares) < 3:
                print("❌ 至少3个分片")
            else:
                recovered = shamir_recover(shares).decode()
                print(f"✅ 恢复的主密码: {recovered}")
        elif cmd == "delete" and args:
            data = load_vault(password)
            if args[0] in data: del data[args[0]]; save_vault(password, data); print(f"✅ {args[0]}")
