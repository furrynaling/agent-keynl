#!/usr/bin/env python3
"""secret-management v3.3 · scrypt + HSM + Shamir + 跨平台 + 交互菜单"""
import os, sys, json, hashlib, base64, getpass, secrets, platform, ctypes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

VERSION = "3.4.0"

# ===== 跨平台默认目录 =====
def default_base_dir():
    if os.environ.get("KEYNL_DIR"):
        return os.environ["KEYNL_DIR"]
    home = os.path.expanduser("~")
    if platform.system() == "Windows":
        return os.path.join(os.environ.get("APPDATA", home), "secret-management")
    return os.path.join(home, ".secret-management")

BASE_DIR = default_base_dir()
os.makedirs(BASE_DIR, exist_ok=True)
VAULT = os.environ.get("KEYNL_VAULT", os.path.join(BASE_DIR, "vault.enc"))
ECC_KEY_FILE = os.environ.get("KEYNL_ECC", os.path.join(BASE_DIR, "ecc.key"))
HW_FILE = os.environ.get("KEYNL_HW", os.path.join(BASE_DIR, "hw.bin"))
SHAMIR_DIR = os.environ.get("KEYNL_SHARDS", os.path.join(BASE_DIR, "shards"))
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")

# ===== 配置文件（加密强度 + 分片方案） =====
DEFAULT_CONFIG = {"scrypt_n": 2**14, "scrypt_r": 8, "shard_n": 5, "shard_k": 3}

def load_config():
    try:
        if os.path.exists(CONFIG_FILE):
            return json.load(open(CONFIG_FILE))
    except:
        pass
    return dict(DEFAULT_CONFIG)

def save_config(cfg):
    os.makedirs(BASE_DIR, exist_ok=True)
    json.dump(cfg, open(CONFIG_FILE, 'w'))
    try: os.chmod(CONFIG_FILE, 0o600)
    except: pass

# ===== scrypt 密码哈希（强度可配置） =====
def derive_key(password):
    cfg = load_config()
    n = cfg.get("scrypt_n", 2**14)
    r = cfg.get("scrypt_r", 8)
    salt = b"secret_management_kdf_salt_v5"
    raw = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=1, dklen=32)
    return base64.urlsafe_b64encode(raw)

# ===== 跨平台硬件指纹 =====
def _sh(s, maxlen=16):
    return hashlib.sha256(s.encode()).hexdigest()[:maxlen] if s else "0"*maxlen

def get_machine_id():
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
            if os.path.exists('/etc/machine-id'):
                return open('/etc/machine-id').read().strip()
            return os.environ.get("PREFIX", "") or os.popen("getprop ro.serialno 2>/dev/null").read().strip()
    except:
        pass
    return ""

def get_hostname():
    return platform.node()

def get_kernel():
    return platform.release() or platform.version()

def get_mac():
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

# ===== Shamir 门限分片（数量可配置） =====
def shamir_split(secret, n=None, k=None):
    cfg = load_config()
    n = n or cfg.get("shard_n", 5)
    k = k or cfg.get("shard_k", 3)
    if len(secret) > 65:
        raise ValueError(f"密码太长({len(secret)}字节)，最多65字节")
    prime = 2**521 - 1  # Mersenne素数M521
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
    cfg = load_config()
    n, k = cfg.get("shard_n", 5), cfg.get("shard_k", 3)
    shares = shamir_split(password.encode(), n, k)
    os.makedirs(SHAMIR_DIR, exist_ok=True)
    for i, val in shares.items():
        with open(os.path.join(SHAMIR_DIR, f"shard_{i}.key"), 'w') as f:
            json.dump({"id": i, "value": val}, f)
    with open(os.path.join(SHAMIR_DIR, "info.txt"), 'w') as f:
        f.write(f"Shamir({k},{n})门限\n任意{k}个分片可恢复主密码")
    print(f"✅ {n}个分片已生成（任意{k}个可恢复）")

# ===== 内存锁 =====
MLOCK_OK = False
try:
    if platform.system() != "Windows":
        libc = ctypes.CDLL("libc.so.6")
        libc.mlockall(1 | 2)
        MLOCK_OK = True
except:
    pass

# ===== ECC 密钥（惰性初始化） =====
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
        print("❌ 密钥库已存在，用改密码(6)")
        return
    p1 = getpass.getpass("🔑 设置主密码(≥12位): ")
    if len(p1) < 12:
        print("❌ 密码太短，至少12位"); return
    p2 = getpass.getpass("🔑 确认主密码: ")
    if p1 != p2:
        print("❌ 两次输入不一致"); return
    save_vault(p1, {})
    print("✅ 主密码已设置")
    print("💡 建议立即生成分片(7)")

def cmd_changepass():
    if not os.path.exists(VAULT):
        print("❌ 密钥库不存在，先设置主密码(1)"); return
    old = getpass.getpass("🔑 旧主密码: ")
    try:
        data = load_vault(old)
    except Exception as e:
        print(f"❌ 旧密码错误"); return
    p1 = getpass.getpass("🔑 新主密码(≥12位): ")
    if len(p1) < 12:
        print("❌ 密码太短"); return
    p2 = getpass.getpass("🔑 确认新密码: ")
    if p1 != p2:
        print("❌ 两次输入不一致"); return
    save_vault(p1, data)
    print("✅ 主密码已修改")

def _input_password():
    return getpass.getpass("🔑 主密码: ")

def cmd_add():
    password = _input_password()
    data = load_vault(password) if os.path.exists(VAULT) else {}
    name = input("密钥名称: ").strip()
    if not name:
        print("❌ 名称不能为空"); return
    val = getpass.getpass(f"🔑 {name} 的值: ")
    data[name] = val
    save_vault(password, data)
    print(f"✅ {name}")

def cmd_get():
    password = _input_password()
    name = input("密钥名称: ").strip()
    val = load_vault(password).get(name)
    if val is None:
        print("❌ 不存在")
    else:
        print(f"{name} = {val}")

def cmd_list():
    password = _input_password()
    data = load_vault(password)
    if not data:
        print("  (空)"); return
    for k, v in sorted(data.items()):
        print(f"  {k}: {'***' if len(v)>20 else v}")

def cmd_delete():
    password = _input_password()
    name = input("密钥名称: ").strip()
    data = load_vault(password)
    if name in data:
        del data[name]; save_vault(password, data)
        print(f"✅ {name}")
    else:
        print("❌ 不存在")

def cmd_recover():
    cfg = load_config()
    k = cfg.get("shard_k", 3)
    print(f"输入分片(格式 id:value，空行结束，需至少{k}个):")
    shares = {}
    while True:
        line = input()
        if not line: break
        try:
            i, v = line.split(':')
            shares[int(i)] = int(v)
        except:
            print("格式错误，用 id:value")
    if len(shares) < k:
        print(f"❌ 至少{k}个分片")
    else:
        print(f"✅ 恢复的主密码: {shamir_recover(shares).decode()}")

def cmd_set_strength():
    cfg = load_config()
    cur = cfg.get("scrypt_n", 2**14)
    print(f"当前加密强度: {cur}")
    print("  1. 快速   (8MB内存, 低配设备)")
    print("  2. 标准   (16MB内存, 默认)")
    print("  3. 高强度 (16MB内存, 迭代翻倍, 更安全)")
    choice = input("选择 [1-3]: ").strip()
    mapping = {"1": (2**13, 8), "2": (2**14, 8), "3": (2**15, 4)}
    if choice not in mapping:
        print("❌ 无效选择"); return
    new_n, new_r = mapping[choice]
    if os.path.exists(VAULT):
        password = getpass.getpass("🔑 主密码(用于重新加密): ")
        try:
            data = load_vault(password)
        except:
            print("❌ 密码错误"); return
        cfg["scrypt_n"] = new_n
        cfg["scrypt_r"] = new_r
        save_config(cfg)
        save_vault(password, data)
        print(f"✅ 加密强度已改为 n={new_n} r={new_r}（数据已重新加密）")
    else:
        cfg["scrypt_n"] = new_n
        cfg["scrypt_r"] = new_r
        save_config(cfg)
        print(f"✅ 加密强度已改为 n={new_n} r={new_r}")

def cmd_set_shards():
    cfg = load_config()
    n, k = cfg.get("shard_n", 5), cfg.get("shard_k", 3)
    print(f"当前分片方案: {k}-of-{n}")
    print("  1. 3-of-5  (默认)")
    print("  2. 3-of-7")
    print("  3. 5-of-7")
    print("  4. 5-of-9")
    choice = input("选择 [1-4]: ").strip()
    mapping = {"1": (5,3), "2": (7,3), "3": (7,5), "4": (9,5)}
    if choice not in mapping:
        print("❌ 无效选择"); return
    n, k = mapping[choice]
    cfg["shard_n"] = n
    cfg["shard_k"] = k
    save_config(cfg)
    print(f"✅ 分片方案已改为 {k}-of-{n}")

def cmd_update():
    """检查并更新到最新版"""
    print("🔍 检查更新...")
    try:
        import urllib.request, re, shutil
        url = "https://raw.githubusercontent.com/furrynaling/secret-management/main/scripts/keynl.py"
        req = urllib.request.Request(url, headers={"User-Agent": "keynl-update"})
        latest_code = urllib.request.urlopen(req, timeout=10).read().decode()
        m = re.search(r'VERSION = "([^"]+)"', latest_code)
        if not m:
            print("❌ 无法获取最新版本信息"); return
        latest_ver = m.group(1)
        if latest_ver == VERSION:
            print(f"✅ 已是最新版本 v{VERSION}")
            return
        print(f"🆕 发现新版本 v{latest_ver}（当前 v{VERSION}）")
        self_path = os.path.abspath(sys.argv[0])
        shutil.copy(self_path, self_path + ".bak")
        with open(self_path, 'w') as f:
            f.write(latest_code)
        print(f"✅ 已更新到 v{latest_ver}（旧版备份为 .bak，重启后生效）")
    except Exception as e:
        print(f"❌ 更新失败: {e}")

def print_status():
    hsm_type, hsm_desc = detect_hsm()
    cfg = load_config()
    print(f"🔐 secret-management v{VERSION}")
    print(f"   平台: {platform.system()} ({platform.machine()})")
    print(f"   HSM适配: {hsm_type} ({hsm_desc})")
    print(f"   加密强度: scrypt n={cfg.get('scrypt_n', 2**14)}")
    print(f"   分片方案: {cfg.get('shard_k',3)}-of-{cfg.get('shard_n',5)}")
    print(f"   内存锁: {'✅' if MLOCK_OK else '⚠️'}")
    print(f"   存储目录: {BASE_DIR}")
    print(f"   密钥库: {'✅ 已初始化' if os.path.exists(VAULT) else '❌ 未初始化'}")
    print(f"   ─────────────────────────────")
    print(f"   TO：纳棂 · furrynaling@outlook.com")

# ===== 交互式菜单 =====
MENU = """━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔐 secret-management 主菜单
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  1. 设置主密码
  2. 存密钥
  3. 读密钥
  4. 列出所有密钥
  5. 删除密钥
  6. 修改主密码
  7. 生成分片
  8. 从分片恢复
  9. 修改加密强度
  10. 修改分片数量
  11. 查看状态
  12. 检查更新
  0. 退出
━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""

def interactive_menu():
    print(MENU)
    while True:
        try:
            choice = input("请选择 [0-12]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print(); break
        if choice == "0":
            print("👋 再见"); break
        elif choice == "1": cmd_setpass()
        elif choice == "2": cmd_add()
        elif choice == "3": cmd_get()
        elif choice == "4": cmd_list()
        elif choice == "5": cmd_delete()
        elif choice == "6": cmd_changepass()
        elif choice == "7": 
            password = _input_password(); save_shards(password)
        elif choice == "8": cmd_recover()
        elif choice == "9": cmd_set_strength()
        elif choice == "10": cmd_set_shards()
        elif choice == "11": print_status()
        elif choice == "12": cmd_update()
        else: print("❌ 无效选择")
        print()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        interactive_menu()
        sys.exit(0)
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd in ("-v", "--version", "version", "-V"):
        print(f"secret-management v{VERSION}")
    elif cmd == "setpass":
        cmd_setpass()
    elif cmd == "changepass":
        cmd_changepass()
    elif cmd == "status":
        print_status()
    elif cmd == "strength":
        cmd_set_strength()
    elif cmd == "shardcfg":
        cmd_set_shards()
    elif cmd == "update":
        cmd_update()
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
            cmd_recover()
        elif cmd == "delete" and args:
            data = load_vault(password)
            if args[0] in data: del data[args[0]]; save_vault(password, data); print(f"✅ {args[0]}")
