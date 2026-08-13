#!/usr/bin/env python3
"""secret-management v5 · scrypt + HSM + Shamir + 跨平台(Win/Linux/Android)"""
VERSION = "3.2.0"
import os, sys, json, hashlib, base64, getpass, secrets, platform, ctypes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# ===== 跨平台默认目录 =====
def default_base_dir():
    """根据平台返回可写目录"""
    if os.environ.get("KEYMGR_DIR"):
        return os.environ["KEYMGR_DIR"]
    home = os.path.expanduser("~")
    if platform.system() == "Windows":
        # Windows: %APPDATA%\secret-management
        return os.path.join(os.environ.get("APPDATA", home), "secret-management")
    elif os.environ.get("PREFIX") and "termux" in os.environ.get("PREFIX", "").lower():
        # Termux: $HOME/.secret-management
        return os.path.join(home, ".secret-management")
    else:
        # Linux/macOS
        return os.path.join(home, ".secret-management")

BASE_DIR = default_base_dir()
os.makedirs(BASE_DIR, exist_ok=True)
VAULT = os.environ.get("KEYMGR_VAULT", os.path.join(BASE_DIR, "vault.enc"))
ECC_KEY_FILE = os.environ.get("KEYMGR_ECC", os.path.join(BASE_DIR, "ecc.key"))
HW_FILE = os.environ.get("KEYMGR_HW", os.path.join(BASE_DIR, "hw.bin"))
SHAMIR_DIR = os.environ.get("KEYMGR_SHARDS", os.path.join(BASE_DIR, "shards"))

# ===== scrypt 密码哈希 =====
def derive_key(password):
    salt = b"secret_management_kdf_salt_v5"
    raw = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return base64.urlsafe_b64encode(raw)

# ===== 跨平台硬件指纹 =====
def _sh(s, maxlen=16):
    return hashlib.sha256(s.encode()).hexdigest()[:maxlen] if s else "0"*maxlen

def get_machine_id():
    """机器ID：Linux machine-id / Windows MachineGuid / Mac IOPlatformUUID"""
    sys = platform.system()
    try:
        if sys == "Windows":
            import subprocess
            out = subprocess.run(['reg','query','HKLM\\SOFTWARE\\Microsoft\\Cryptography','/v','MachineGuid'],
                capture_output=True, text=True, timeout=5).stdout
            for line in out.splitlines():
                if 'MachineGuid' in line:
                    return line.split()[-1]
        elif sys == "Darwin":
            return os.popen("ioreg -rd1 -c IOPlatformExpertDevice | grep IOPlatformUUID").read().strip()
        else:
            # Linux / Android / Termux
            if os.path.exists('/etc/machine-id'):
                return open('/etc/machine-id').read().strip()
            # Android 无 machine-id，用 PREFIX 或 android id
            return os.environ.get("PREFIX", "") or os.popen("getprop ro.serialno 2>/dev/null").read().strip()
    except:
        pass
    return ""

def get_hostname():
    return platform.node()

def get_kernel():
    # release=稳定版本号(如6.8.0-101)，version含构建时间戳会随小更新变化
    return platform.release() or platform.version()

def get_mac():
    """MAC 地址：Linux ip / Windows getmac / Mac ifconfig"""
    sys = platform.system()
    try:
        if sys == "Windows":
            out = os.popen("getmac /fo csv /nh 2>/dev/null").read()
            for line in out.splitlines():
                mac = line.split(',')[0].strip('"')
                if ':' in mac:
                    return mac
        elif sys == "Darwin":
            out = os.popen("ifconfig en0 2>/dev/null | grep ether").read()
            if 'ether' in out:
                return out.split()[1]
        else:
            out = os.popen("ip link show 2>/dev/null | grep 'link/ether' | head -1").read()
            if 'link/ether' in out:
                return out.split()[1]
    except:
        pass
    return ""

def detect_hsm():
    """检测硬件安全模块"""
    if platform.system() != "Windows" and (os.path.exists('/dev/tpm0') or os.path.exists('/dev/tpmrm0')):
        try:
            pcr = os.popen("tpm2_pcrread sha256:0 2>/dev/null || cat /sys/class/tpm/tpm0/pcr-sha256/0 2>/dev/null").read().strip()
            if pcr:
                return 'tpm', f"TPM 2.0 (PCR0={_sh(pcr, 12)}...)"
        except:
            pass
    if os.environ.get('TENCENT_KMS_KEY_ID') or os.environ.get('ALIYUN_KMS_KEY_ID'):
        kms_id = os.environ.get('TENCENT_KMS_KEY_ID') or os.environ.get('ALIYUN_KMS_KEY_ID')
        return 'cloud-kms', f"云KMS ({kms_id[:8]}...)"
    return 'software', "软件指纹 (机器ID+主机名+内核+MAC)"

def get_hw_fingerprint():
    hsm_type, _ = detect_hsm()
    if hsm_type == 'tpm':
        try:
            pcr = os.popen("tpm2_pcrread sha256:0 2>/dev/null").read().strip()
            if pcr:
                return hashlib.sha256(('tpm:'+pcr).encode()).hexdigest()[:64]
        except:
            pass
    elif hsm_type == 'cloud-kms':
        kms_id = os.environ.get('TENCENT_KMS_KEY_ID') or os.environ.get('ALIYUN_KMS_KEY_ID', '')
        return hashlib.sha256(('kms:'+kms_id).encode()).hexdigest()[:64]
    # 软件指纹（跨平台）
    return _sh(get_machine_id()) + _sh(get_hostname()) + _sh(get_kernel()) + _sh(get_mac())

def check_hw():
    current = get_hw_fingerprint()
    if not os.path.exists(HW_FILE):
        os.makedirs(os.path.dirname(HW_FILE), exist_ok=True)
        with open(HW_FILE, 'w') as f: f.write(current)
        try: os.chmod(HW_FILE, 0o600)
        except: pass
        return True
    return current == open(HW_FILE).read().strip()

# ===== Shamir 门限分片（3/5） =====
def shamir_split(secret, n=5, k=3):
    if len(secret) > 65:
        raise ValueError(f"密码太长({len(secret)}字节)，最多65字节")
    prime = 2**521 - 1  # Mersenne素数M521，可容纳65字节
    coeffs = [int.from_bytes(secret, 'big')] + [secrets.randbelow(prime) for _ in range(k-1)]
    def eval_poly(x): return sum(c * (x**i) % prime for i, c in enumerate(coeffs)) % prime
    return {i: eval_poly(i) for i in range(1, n+1)}

def shamir_recover(shares):
    prime = 2**521 - 1
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
    shares = shamir_split(password.encode())
    os.makedirs(SHAMIR_DIR, exist_ok=True)
    for i, val in shares.items():
        with open(os.path.join(SHAMIR_DIR, f"shard_{i}.key"), 'w') as f:
            json.dump({"id": i, "value": val}, f)
    with open(os.path.join(SHAMIR_DIR, "info.txt"), 'w') as f:
        f.write("Shamir(3,5)门限\n任意3个分片可恢复主密码")
    print("✅ 5个分片已生成")

# ===== 内存锁（跨平台） =====
MLOCK_OK = False
try:
    if platform.system() != "Windows":
        libc = ctypes.CDLL("libc.so.6")
        libc.mlockall(1 | 2)
        MLOCK_OK = True
except:
    pass

# ===== ECC 密钥（惰性初始化，避免模块加载时写文件） =====
SERVER_ECC_KEY = None

def get_ecc_key():
    global SERVER_ECC_KEY
    if SERVER_ECC_KEY is None:
        if os.path.exists(ECC_KEY_FILE):
            SERVER_ECC_KEY = serialization.load_pem_private_key(open(ECC_KEY_FILE,'rb').read(), password=None)
        else:
            SERVER_ECC_KEY = ec.generate_private_key(ec.SECP384R1())
            os.makedirs(os.path.dirname(ECC_KEY_FILE), exist_ok=True)
            with open(ECC_KEY_FILE, 'wb') as f:
                f.write(SERVER_ECC_KEY.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()))
            try: os.chmod(ECC_KEY_FILE, 0o600)
            except: pass
    return SERVER_ECC_KEY

def get_ecc_fp():
    pub = get_ecc_key().public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha384(pub).hexdigest()[:24]

# ===== 主接口 =====
def load_vault(password):
    if not os.path.exists(VAULT): return {}
    if not check_hw(): raise Exception("❌ 硬件指纹不匹配! 密文可能被复制到其他设备")
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
    try: os.chmod(VAULT, 0o600)
    except: pass

def cmd_setpass():
    if os.path.exists(VAULT):
        print("❌ 密钥库已存在，用 changepass 修改密码")
        return
    p1 = getpass.getpass("🔑 设置主密码(≥12位): ")
    if len(p1) < 12:
        print("❌ 密码太短，至少12位"); return
    p2 = getpass.getpass("🔑 确认主密码: ")
    if p1 != p2:
        print("❌ 两次输入不一致"); return
    save_vault(p1, {})
    print("✅ 主密码已设置，密钥库已初始化")
    print("💡 建议立即生成分片: keymgr shards")

def cmd_changepass():
    if not os.path.exists(VAULT):
        print("❌ 密钥库不存在，用 setpass 初始化"); return
    old = getpass.getpass("🔑 旧主密码: ")
    try:
        data = load_vault(old)
    except Exception as e:
        print(f"❌ 旧密码错误: {e}"); return
    p1 = getpass.getpass("🔑 新主密码(≥12位): ")
    if len(p1) < 12:
        print("❌ 密码太短"); return
    p2 = getpass.getpass("🔑 确认新密码: ")
    if p1 != p2:
        print("❌ 两次输入不一致"); return
    save_vault(p1, data)
    print("✅ 主密码已修改，数据已用新密码重新加密")

def print_status():
    hsm_type, hsm_desc = detect_hsm()
    print(f"🔐 secret-management v{VERSION}")
    print(f"   平台: {platform.system()} ({platform.machine()})")
    print(f"   HSM适配: {hsm_type} ({hsm_desc})")
    print(f"   硬件指纹: {get_hw_fingerprint()[:32]}...")
    print(f"   内存锁: {'✅ 已启用' if MLOCK_OK else '⚠️ 未启用'}")
    print(f"   存储目录: {BASE_DIR}")
    print(f"   密钥库: {'✅ 已初始化' if os.path.exists(VAULT) else '❌ 未初始化(setpass)'}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_status(); sys.exit(0)
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "setpass":
        cmd_setpass()
    elif cmd == "changepass":
        cmd_changepass()
    elif cmd == "status":
        print_status()
    elif cmd in ("-v", "--version", "version", "-V"):
        print(f"secret-management v{VERSION}")
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
            save_shards(password)
        elif cmd == "recover":
            print("输入分片(格式 id:value，空行结束):")
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
                print(f"✅ 恢复的主密码: {shamir_recover(shares).decode()}")
        elif cmd == "delete" and args:
            data = load_vault(password)
            if args[0] in data: del data[args[0]]; save_vault(password, data); print(f"✅ {args[0]}")
