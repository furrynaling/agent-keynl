#!/usr/bin/env python3
"""祈棂密钥管理器 v3 · Argon2 + Shamir + mlock"""
import os, sys, json, hashlib, base64, getpass, secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import ctypes

VAULT = "/root/mytp/.keys/vault.enc"
ECC_KEY_FILE = "/root/mytp/.keys/ecc.key"
HW_FILE = "/root/mytp/.keys/hw.bin"
SHAMIR_DIR = "/root/mytp/.keys/shards"

# ===== Argon2id 密码哈希（升级PBKDF2） =====
ph = PasswordHasher(time_cost=4, memory_cost=65536, parallelism=2, hash_len=32)

def derive_key(password):
    """Argon2id → 内存密集型 → 抗ASIC/GPU"""
    salt = b"vault_kdf_salt"
    raw = ph.hash(password, salt=salt)
    # 提取hash输出
    key = base64.urlsafe_b64encode(hashlib.sha256(raw.encode()).digest())
    return key

# ===== Shamir密钥分片（3/5门限） =====
def shamir_split(secret, n=5, k=3):
    """Shamir's Secret Sharing - k of n 门限"""
    prime = 2**127 - 1  # 127位素数
    coeffs = [int.from_bytes(secret, 'big')] + [secrets.randbelow(prime) for _ in range(k-1)]
    def eval_poly(x): return sum(c * (x**i) % prime for i, c in enumerate(coeffs)) % prime
    return {i: eval_poly(i) for i in range(1, n+1)}

def shamir_recover(shares):
    """从k个分片恢复密钥"""
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
    """生成密码分片 → 存在不同位置"""
    import json as _json
    secret = password.encode()
    shares = shamir_split(secret)
    os.makedirs(SHAMIR_DIR, exist_ok=True)
    for i, val in shares.items():
        with open(f"{SHAMIR_DIR}/shard_{i}.key", 'w') as f:
            _json.dump({"id": i, "value": val}, f)
    with open(f"{SHAMIR_DIR}/info.txt", 'w') as f:
        f.write("Shamir(3,5)门限\n分片1-2: 安全存储\n分片3: 随身U盘\n分片4-5: 备份")
    os.chmod(SHAMIR_DIR, 0o700)

# ===== 内存锁（防swap泄漏） =====
try:
    libc = ctypes.CDLL("libc.so.6")
    MCL_CURRENT, MCL_FUTURE = 1, 2
    libc.mlockall(MCL_CURRENT | MCL_FUTURE)
    MLOCK_OK = True
except:
    MLOCK_OK = False

# ===== 硬件指纹 =====
def get_hw_fingerprint():
    parts = []
    try:
        mid = open('/etc/machine-id').read().strip()
        parts.append(hashlib.sha256(mid.encode()).hexdigest()[:16])
    except: parts.append("0"*16)
    try:
        hn = os.popen('hostname').read().strip()
        parts.append(hashlib.sha256(hn.encode()).hexdigest()[:16])
    except: parts.append("0"*16)
    try:
        kv = os.popen('uname -r').read().strip()
        parts.append(hashlib.sha256(kv.encode()).hexdigest()[:16])
    except: parts.append("0"*16)
    try:
        mac = os.popen("ip link show eth0 2>/dev/null|grep ether|awk '{print $2}'").read().strip()
        parts.append(hashlib.sha256(mac.encode()).hexdigest()[:16])
    except: parts.append("0"*16)
    return ''.join(parts)

def check_hw():
    current = get_hw_fingerprint()
    if not os.path.exists(HW_FILE):
        with open(HW_FILE, 'w') as f: f.write(current)
        os.chmod(HW_FILE, 0o600); return True
    return current == open(HW_FILE).read().strip()

# ===== ECC密钥 =====
if os.path.exists(ECC_KEY_FILE):
    SERVER_ECC_KEY = serialization.load_pem_private_key(open(ECC_KEY_FILE,'rb').read(), password=None)
else:
    SERVER_ECC_KEY = ec.generate_private_key(ec.SECP384R1())
    os.makedirs(os.path.dirname(ECC_KEY_FILE), exist_ok=True)
    with open(ECC_KEY_FILE, 'wb') as f:
        f.write(SERVER_ECC_KEY.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))

def get_ecc_fp():
    pub = SERVER_ECC_KEY.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha384(pub).hexdigest()[:24]

# ===== 假文件校验 =====
DECOY_FILES = ["/root/mytp/package.json","/root/mytp/README.md","/root/mytp/launcher.sh","/root/mytp/src/index.js","/root/mytp/src/config.js","/root/mytp/lib/utils.py","/root/mytp/lib/crypto.py","/root/mytp/data/cache.db","/root/mytp/data/sessions.bin","/root/mytp/data/server.log"]
DECOY_HASH_FILE = "/root/mytp/.keys/decoy.hash"

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
    if not check_hw(): raise Exception("❌ 硬件指纹不匹配!")
    
    key = derive_key(password)
    f = Fernet(key)
    data = json.loads(f.decrypt(open(VAULT,'rb').read()))
    if data.pop('_ecc_fp','') != get_ecc_fp(): raise Exception("❌ ECC指纹!")
    if data.pop('_sha384','') != hashlib.sha384(json.dumps({k:v for k,v in data.items() if not k.startswith('_')}, sort_keys=True).encode()).hexdigest():
        raise Exception("❌ 完整性校验!")
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

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("🔐 祈棂密钥管理器 v3")
        print(f"   硬件指纹: {get_hw_fingerprint()[:32]}...")
        print(f"   内存锁: {'✅' if MLOCK_OK else '⚠️'}")
        sys.exit(0)
    
    password = getpass.getpass("🔑 主密码: ")
    cmd, args = sys.argv[1], sys.argv[2:]
    
    if cmd == "add" and args:
        data = load_vault(password) if os.path.exists(VAULT) else {}
        data[args[0]] = ' '.join(args[1:]) if len(args)>1 else input("值: ")
        save_vault(password, data)
        print(f"✅ {args[0]}")
    elif cmd == "get" and args:
        print(load_vault(password).get(args[0], "❌"))
    elif cmd == "list":
        for k,v in sorted(load_vault(password).items()):
            print(f"  {k}: {'***' if len(v)>20 else v}")
    elif cmd == "shards":
        save_shards(password); print("✅ 5个分片已生成")
    elif cmd == "delete" and args:
        data = load_vault(password)
        if args[0] in data: del data[args[0]]; save_vault(password, data); print(f"✅ {args[0]}")
