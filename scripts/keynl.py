#!/usr/bin/env python3
"""agent-keynl v3.3 · scrypt + HSM + Shamir + 跨平台 + 交互菜单"""
import os, sys, json, hashlib, base64, getpass, secrets, platform, ctypes, time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

VERSION = "4.7.0"

# ===== 跨平台默认目录 =====
def default_base_dir():
    if os.environ.get("KEYNL_DIR"):
        return os.environ["KEYNL_DIR"]
    home = os.path.expanduser("~")
    if platform.system() == "Windows":
        return os.path.join(os.environ.get("APPDATA", home), "agent-keynl")
    return os.path.join(home, ".agent-keynl")

BASE_DIR = default_base_dir()
os.makedirs(BASE_DIR, exist_ok=True)
VAULT = os.environ.get("KEYNL_VAULT", os.path.join(BASE_DIR, "vault.enc"))
ECC_KEY_FILE = os.environ.get("KEYNL_ECC", os.path.join(BASE_DIR, "ecc.key"))
HW_FILE = os.environ.get("KEYNL_HW", os.path.join(BASE_DIR, "hw.bin"))
SHAMIR_DIR = os.environ.get("KEYNL_SHARDS", os.path.join(BASE_DIR, "shards"))
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
ENV_KEY_FILE = os.path.join(BASE_DIR, "env.key")
ACCESS_LOG = os.path.join(BASE_DIR, "access.log")

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

# ===== 环境密钥（每个安装实例独立，初始化时生成） =====
def get_env_key():
    """获取或生成环境密钥，每个 keynl 安装实例独立"""
    if os.path.exists(ENV_KEY_FILE):
        return open(ENV_KEY_FILE, 'rb').read()
    env_key = secrets.token_bytes(32)
    os.makedirs(BASE_DIR, exist_ok=True)
    with open(ENV_KEY_FILE, 'wb') as f:
        f.write(env_key)
    try: os.chmod(ENV_KEY_FILE, 0o600)
    except: pass
    return env_key

# ===== scrypt 密码哈希（强度可配置，混入环境密钥） =====
def derive_key(password):
    cfg = load_config()
    n = cfg.get("scrypt_n", 2**14)
    r = cfg.get("scrypt_r", 8)
    salt = b"secret_management_kdf_salt_v5"
    maxmem = max(32*1024*1024, 128 * n * r * 2)  # 自动放宽内存限制
    raw = hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=1, maxmem=maxmem, dklen=32)
    env_key = get_env_key()  # 混入环境密钥，初始化即环境绑定
    combined = hashlib.sha256(raw + env_key).digest()
    return base64.urlsafe_b64encode(combined)

# ===== 哈希 → emoji 表情映射（防篡改可视化） =====
EMOJI_TABLE = ["💛","🏹","🎂","🏅","🇧🇷","🦺","🆚","🛎️","🔥","💎","🌙","⭐","🎯","🦄","🚀","👑"]

def hash_to_emoji(hash_hex, count=8):
    """哈希值(hex) → count个emoji表情（每4bit映射一个）"""
    result = ""
    for i in range(min(count, len(hash_hex))):
        idx = int(hash_hex[i], 16)
        result += EMOJI_TABLE[idx]
    return result

# ===== 解密审计日志 =====
_last_access = [0.0]

def log_access(action="解密"):
    """记录一次成功解密（60秒内去重）"""
    global _last_access
    now = time.time()
    if now - _last_access[0] < 60:
        return
    _last_access[0] = now
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    try:
        with open(ACCESS_LOG, 'a') as f:
            f.write(f"{ts} | {action} | {platform.node()}\n")
    except:
        pass

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
            # Linux
            if os.path.exists('/etc/machine-id'):
                return open('/etc/machine-id').read().strip()
            # Android/Termux：优先设备唯一标识，而非 PREFIX（所有设备相同）
            serial = os.popen("getprop ro.serialno 2>/dev/null").read().strip()
            if serial and serial not in ("", "unknown", "UNKNOWN"):
                return serial
            aid = os.popen("settings get secure android_id 2>/dev/null").read().strip()
            if aid and aid not in ("", "null", "unknown"):
                return aid
            # 最后回退（弱，仅兜底）
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
            # Android 6+ 隐藏 MAC，尝试其他来源
            out2 = os.popen("cat /sys/class/net/wlan0/address 2>/dev/null || cat /sys/class/net/eth0/address 2>/dev/null").read().strip()
            if out2:
                return out2
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

def _shard_fernet():
    """分片加密密钥（基于环境密钥，独立于主密码）"""
    env_key = get_env_key()
    key = base64.urlsafe_b64encode(hashlib.sha256(b"keynl-shard:" + env_key).digest())
    return Fernet(key)

def _read_shard(path):
    """读取并解密分片文件"""
    f = _shard_fernet()
    decrypted = f.decrypt(open(path, 'rb').read())
    return json.loads(decrypted)

def save_shards(password):
    cfg = load_config()
    n, k = cfg.get("shard_n", 5), cfg.get("shard_k", 3)
    shares = shamir_split(password.encode(), n, k)
    os.makedirs(SHAMIR_DIR, exist_ok=True)
    f = _shard_fernet()
    for i, val in shares.items():
        data = json.dumps({"id": i, "value": val}).encode()
        with open(os.path.join(SHAMIR_DIR, f"shard_{i}.key"), 'wb') as fh:
            fh.write(f.encrypt(data))
    with open(os.path.join(SHAMIR_DIR, "info.txt"), 'w') as f:
        f.write(f"Shamir({k},{n})门限\n任意{k}个分片可恢复主密码")
    print(f"✅ {n}个分片已生成（任意{k}个可恢复）")
    print(f"   分片目录: {SHAMIR_DIR}")
    print(f"   恢复方法: keynl recover → 输入 shard_1.key,shard_3.key,shard_5.key")

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
    log_access()
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
    print("✅ 主密码已设置，环境密钥已生成")
    print(f"   🔑 环境密钥: {ENV_KEY_FILE}")
    print("   ⚠️ 请备份 env.key，丢失则密钥库永久无法解密")
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

_cached_password = None

def _get_password():
    """获取主密码（优先用会话缓存的密码）"""
    global _cached_password
    if _cached_password:
        return _cached_password
    return getpass.getpass("🔑 主密码: ")

def _load_safe(password):
    """安全加载 vault，出错返回 None + 友好提示"""
    if not os.path.exists(VAULT):
        return {}
    try:
        return load_vault(password)
    except Exception:
        print("❌ 主密码错误，或密钥库已损坏")
        return None

def cmd_authorize():
    """授权本次终端窗口免密"""
    global _cached_password
    p = getpass.getpass("🔑 主密码: ")
    if not os.path.exists(VAULT):
        print("❌ 密钥库未初始化，先设置主密码(1)"); return
    try:
        load_vault(p)
    except Exception:
        print("❌ 主密码错误"); return
    _cached_password = p
    print("✅ 已授权，本次终端窗口内免密操作")

def cmd_about():
    print(f"🔐 agent-keynl v{VERSION}")
    print("   一个给 AI Agent 的加密密码本")
    print("")
    print("   作者: 纳棂")
    print("   邮箱: furrynaling@outlook.com")
    print("   网站: furrynaling.com · naling.net")
    print("   仓库: github.com/furrynaling/agent-keynl")

def cmd_add():
    password = _get_password()
    data = _load_safe(password)
    if data is None: return
    name = input("密钥名称: ").strip()
    if not name:
        print("❌ 名称不能为空"); return
    print("输入字段(格式 字段名=值，单字段可直接输入值，空行结束):")
    fields = {}
    first = input("  > ").strip()
    if not first:
        print("❌ 不能为空"); return
    if '=' in first:
        k, v = first.split('=', 1)
        fields[k.strip()] = v.strip()
        while True:
            line = input("  > ").strip()
            if not line: break
            if '=' in line:
                k2, v2 = line.split('=', 1)
                fields[k2.strip()] = v2.strip()
    else:
        # 单字段
        data[name] = first
        save_vault(password, data)
        print(f"✅ {name}")
        return
    # 多字段存 JSON
    data[name] = json.dumps(fields, ensure_ascii=False)
    save_vault(password, data)
    print(f"✅ {name} ({len(fields)}个字段)")

def cmd_get():
    password = _get_password()
    name = input("密钥名称: ").strip()
    data = _load_safe(password)
    if data is None: return
    val = data.get(name)
    if val is None:
        print("❌ 不存在")
        return
    try:
        fields = json.loads(val)
        if isinstance(fields, dict):
            for k, v in fields.items():
                print(f"  {k} = {v}")
        else:
            print(f"{name} = {val}")
    except:
        print(f"{name} = {val}")

def cmd_list():
    password = _get_password()
    data = _load_safe(password)
    if data is None: return
    if not data:
        print("  (空)"); return
    for k, v in sorted(data.items()):
        print(f"  {k}: {'***' if len(v)>20 else v}")

def cmd_delete():
    password = _get_password()
    name = input("密钥名称: ").strip()
    data = _load_safe(password)
    if data is None: return
    if name in data:
        del data[name]; save_vault(password, data)
        print(f"✅ {name}")
    else:
        print("❌ 不存在")

def cmd_recover():
    cfg = load_config()
    k = cfg.get("shard_k", 3)
    print(f"分片目录: {SHAMIR_DIR}")
    print(f"需要任意 {k} 个分片文件")
    print("输入分片文件名(逗号分隔，如 shard_1.key,shard_3.key,shard_5.key):")
    raw = input("> ").strip()
    if not raw:
        print("已取消"); return
    shares = {}
    for name in raw.split(','):
        name = name.strip()
        if not name: continue
        # 自动拼接目录（支持文件名或完整路径）
        path = name if os.path.isabs(name) else os.path.join(SHAMIR_DIR, name)
        if not os.path.exists(path):
            print(f"❌ 文件不存在: {path}")
            continue
        try:
            d = _read_shard(path)
            shares[int(d["id"])] = int(d["value"])
            print(f"✅ 已读取分片 {d['id']}")
        except Exception as e:
            print(f"❌ 无法解密: {name}")
    if len(shares) < k:
        print(f"❌ 需要至少{k}个分片，当前只读到{len(shares)}个")
    else:
        print(f"✅ 恢复的主密码: {shamir_recover(shares).decode()}")

def _auto_recover():
    """自动恢复：扫描分片目录自动恢复主密码"""
    cfg = load_config()
    k = cfg.get("shard_k", 3)
    if not os.path.exists(SHAMIR_DIR):
        print("❌ 无分片目录，先到菜单7生成分片"); return
    files = sorted([f for f in os.listdir(SHAMIR_DIR) if f.endswith('.key')])
    if len(files) < k:
        print(f"❌ 分片不足（{len(files)}/{k}个）"); return
    shares = {}
    for f in files[:k]:
        try:
            d = _read_shard(os.path.join(SHAMIR_DIR, f))
            shares[int(d["id"])] = int(d["value"])
            print(f"✅ 读取 {f}")
        except:
            print(f"⚠️ 跳过 {f}")
    if len(shares) < k:
        print(f"❌ 有效分片不足（{len(shares)}/{k}）"); return
    print(f"✅ 恢复的主密码: {shamir_recover(shares).decode()}")

def _add_backup():
    """增加备用区：把分片备份到额外位置"""
    import shutil
    if not os.path.exists(SHAMIR_DIR):
        print("❌ 无分片，先到菜单7生成分片"); return
    files = [f for f in os.listdir(SHAMIR_DIR) if f.endswith('.key')]
    if not files:
        print("❌ 无分片"); return
    print(f"当前 {len(files)} 个分片")
    dest = input("备份到目录(如 /sdcard/backup 或 U盘路径): ").strip()
    if not dest:
        print("已取消"); return
    try:
        os.makedirs(dest, exist_ok=True)
        count = 0
        for f in files:
            shutil.copy(os.path.join(SHAMIR_DIR, f), os.path.join(dest, f))
            count += 1
        print(f"✅ 已备份 {count} 个分片到 {dest}")
        print("   ⚠️ 分片是解锁密码的钥匙，请妥善保管备份位置")
    except Exception as e:
        print(f"❌ 备份失败: {e}")

def _delete_shards():
    """删除区：删除指定分片"""
    if not os.path.exists(SHAMIR_DIR):
        print("❌ 无分片"); return
    files = sorted([f for f in os.listdir(SHAMIR_DIR) if f.endswith('.key')])
    if not files:
        print("❌ 无分片"); return
    for i, f in enumerate(files, 1):
        print(f"  {i}. {f}")
    print("⚠️ 删除分片会降低密码恢复能力")
    choice = input("输入要删除的分片编号(逗号分隔)，回车取消: ").strip()
    if not choice:
        print("已取消"); return
    try:
        idxs = [int(x)-1 for x in choice.split(',') if x.strip()]
    except:
        print("❌ 格式错误"); return
    for idx in idxs:
        if 0 <= idx < len(files):
            os.remove(os.path.join(SHAMIR_DIR, files[idx]))
            print(f"✅ 已删除 {files[idx]}")

def cmd_shards_manage():
    """分片管理子菜单（需密码验证）"""
    if os.path.exists(VAULT):
        password = _get_password()
        if _load_safe(password) is None:
            print("❌ 主密码错误，无法进入分片管理")
            return
        print("✅ 已验证")
    else:
        print("⚠️ 密钥库未初始化，分片可能用于恢复")
    while True:
        print("━━━━ 分片管理 ━━━━")
        print("  1. 自动恢复（扫描目录自动恢复）")
        print("  2. 手动恢复（输入文件名）")
        print("  3. 增加备用区（备份分片）")
        print("  4. 删除区（删除分片）")
        print("  0. 返回")
        try:
            choice = input("选择 [0-4]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print(); break
        if choice == "0":
            break
        elif choice == "1":
            _auto_recover()
        elif choice == "2":
            cmd_recover()
        elif choice == "3":
            _add_backup()
        elif choice == "4":
            _delete_shards()
        else:
            print("❌ 无效选择")
        print()

def cmd_set_strength():
    cfg = load_config()
    cur = cfg.get("scrypt_n", 2**14)
    print(f"当前加密强度: {cur}")
    print("  1. 快速   (8MB内存, 低配设备)")
    print("  2. 标准   (16MB内存, 默认)")
    print("  3. 高强度 (32MB内存, 更安全)")
    print("  4. 极高   (64MB内存, 最强)")
    choice = input("选择 [1-4]: ").strip()
    mapping = {"1": (2**13, 8), "2": (2**14, 8), "3": (2**15, 8), "4": (2**16, 8)}
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
    print("  5. 自定义(输入 n,k)")
    choice = input("选择 [1-5]: ").strip()
    mapping = {"1": (5,3), "2": (7,3), "3": (7,5), "4": (9,5)}
    if choice == "5":
        raw = input("输入总分片数n,门限k (如 7,3): ").strip()
        try:
            n, k = raw.split(',')
            n, k = int(n), int(k)
        except:
            print("❌ 格式错误，用 n,k"); return
        if k >= n or n < 2 or k < 2:
            print("❌ 需满足 2 ≤ k < n"); return
    elif choice in mapping:
        n, k = mapping[choice]
    else:
        print("❌ 无效选择"); return
    cfg["shard_n"] = n
    cfg["shard_k"] = k
    save_config(cfg)
    print(f"✅ 分片方案已改为 {k}-of-{n}")

def cmd_update():
    """检查并更新到最新版"""
    print("🔍 检查更新...")
    try:
        import urllib.request, re, shutil
        url = "https://raw.githubusercontent.com/furrynaling/agent-keynl/main/scripts/keynl.py"
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

def _api_key(password, bind_hw):
    """生成 API 加密密钥（环境密钥 + 可选硬件绑定）"""
    env_key = get_env_key()
    if bind_hw:
        hw = get_hw_fingerprint()
        raw = hashlib.sha256(b"keynl-api:" + password.encode() + b":" + hw.encode() + b":" + env_key).digest()
    else:
        raw = hashlib.sha256(b"keynl-api:" + password.encode() + b":" + env_key).digest()
    return base64.urlsafe_b64encode(raw)

def cmd_export():
    """导出加密 API 文件给 AI 调用（硬件绑定，复制到别处失效）"""
    password = _get_password()
    data = _load_safe(password)
    if data is None: return
    if not data:
        print("❌ 密钥库为空"); return
    print("可导出的密钥:")
    keys = sorted(data.keys())
    for i, k in enumerate(keys, 1):
        v = data[k]
        preview = "***" if len(v) > 15 else v
        print(f"  {i}. {k} = {preview}")
    choice = input("选择编号(逗号分隔，如 1,3): ").strip()
    try:
        idxs = [int(x)-1 for x in choice.split(',') if x.strip()]
    except:
        print("❌ 格式错误"); return
    selected = {keys[i]: data[keys[i]] for i in idxs if 0 <= i < len(keys)}
    if not selected:
        print("❌ 未选中"); return
    # 选加密类型
    print("加密类型:")
    print("  1. 本机绑定 (硬件指纹，最安全，复制到别处无法解密)")
    print("  2. 密码加密 (仅主密码，可复制但需密码)")
    enc_type = input("选择 [1-2]: ").strip()
    api_name = input("API文件名(默认 api_key): ").strip() or "api_key"
    export_dir = os.path.join(BASE_DIR, "export")
    os.makedirs(export_dir, exist_ok=True)
    api_file = os.path.join(export_dir, api_name + ".enc")
    payload = json.dumps(selected, ensure_ascii=False).encode()
    bind = (enc_type == "1")
    key = _api_key(password, bind)
    f = Fernet(key)
    encrypted = f.encrypt(payload)
    # 文件头标记加密类型
    tag = b"HW:" if bind else b"PW:"
    with open(api_file, 'wb') as fh:
        fh.write(tag + encrypted)
    print(f"✅ 已导出: file://{api_file}")
    if bind:
        print(f"   🔒 本机绑定：只能在当前设备解密，复制到别处失效")
        print(f"   AI调用: keynl api-get {api_name}")
    else:
        print(f"   🔐 密码加密：需主密码解密")
        print(f"   AI调用: keynl api-get {api_name}")

def cmd_api_get(args):
    """解密读取导出的 API 文件"""
    if not args:
        print("用法: keynl api-get <API名>")
        return
    api_name = args[0]
    export_dir = os.path.join(BASE_DIR, "export")
    api_file = os.path.join(export_dir, api_name + ".enc")
    if not os.path.exists(api_file):
        print(f"❌ 文件不存在: {api_file}")
        return
    raw = open(api_file, 'rb').read()
    if raw.startswith(b"HW:"):
        bind = True
        encrypted = raw[3:]
    elif raw.startswith(b"PW:"):
        bind = False
        encrypted = raw[3:]
    else:
        encrypted = raw
        bind = False
    password = _get_password()
    key = _api_key(password, bind)
    f = Fernet(key)
    try:
        payload = f.decrypt(encrypted)
    except:
        if bind:
            print("❌ 解密失败：可能不在原设备，或密码错误")
        else:
            print("❌ 主密码错误")
        return
    selected = json.loads(payload)
    for k, v in selected.items():
        try:
            fields = json.loads(v)
            if isinstance(fields, dict):
                print(f"  {k}:")
                for k2, v2 in fields.items():
                    print(f"    {k2} = {v2}")
                continue
        except:
            pass
        print(f"  {k} = {v}")

def cmd_chain():
    """上链校验：上传哈希到服务器，返回比对链接"""
    password = _get_password()
    data = _load_safe(password)
    if data is None: return
    if not data:
        print("❌ 密钥库为空，先存密钥"); return
    data_str = json.dumps(data, sort_keys=True, ensure_ascii=False)
    data_hash = hashlib.sha256(data_str.encode()).hexdigest()
    emojis = hash_to_emoji(data_hash)
    print("本地表情: " + " ".join(emojis))
    print("⏳ 上传服务器...")
    try:
        import urllib.request
        payload = json.dumps({"hash": data_hash, "emojis": "".join(emojis)}).encode()
        req = urllib.request.Request("https://furrynaling.com/api/chain/upload",
            data=payload, headers={"Content-Type": "application/json", "User-Agent": "agent-keynl/4.3"})
        resp = json.loads(urllib.request.urlopen(req, timeout=10).read().decode())
        if resp.get("url"):
            print(f"✅ 已上链: {resp['url']}")
            if resp.get("ipfs"):
                print(f"   📦 IPFS备份: {resp['ipfs']}")
            if resp.get("ots"):
                print(f"   ⛓️ 比特币存证: {resp['ots']}")
            if resp.get("signature"):
                print(f"   ✍️ ECC签名: {resp['signature'][:24]}...")
            print("   打开链接，比对表情是否一致")
        else:
            print(f"⚠️ {resp.get('error', '上链失败')}")
    except Exception as e:
        print(f"❌ 上传失败(服务器链端点未部署): {str(e)[:60]}")

def cmd_query():
    """泄露查询：列出上链记录，选择一条查询/比对"""
    import urllib.request
    print("⏳ 拉取链上记录...")
    try:
        req = urllib.request.Request("https://furrynaling.com/api/chain/list",
            headers={"User-Agent": "agent-keynl/4.6"})
        resp = json.loads(urllib.request.urlopen(req, timeout=10).read().decode())
        items = resp.get("items", [])
        if not items:
            print("📭 链上暂无记录，先用菜单16上链"); return
        print(f"共 {len(items)} 条上链记录:")
        for i, it in enumerate(items, 1):
            print(f"  {i}. {it['emojis']}  {it['created_at']}")
            print(f"     哈希: {it['full_hash']}")
        print()
        choice = input("选择要查询的编号(回车=对比本地当前数据): ").strip()
        if choice:
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(items):
                    it = items[idx]
                    print(f"链上表情(这条记录上链时): {it['emojis']}")
                    print(f"完整哈希: {it['full_hash']}")
                    print(f"链上页面: https://furrynaling.com/chain/{it['full_hash'][:32]}.html")
                    print(f"上链时间: {it['created_at']}")
                    password = _get_password()
                    data = _load_safe(password)
                    if data is not None and data:
                        data_hash = hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
                        local_emojis = "".join(hash_to_emoji(data_hash))
                        print(f"当前本地表情(现在的数据): {' '.join(hash_to_emoji(data_hash))}")
                        print()
                        if local_emojis == it['emojis']:
                            print("✅ 一致：当前数据与这条记录一致，未被篡改")
                        else:
                            print("⚠️ 不一致：数据自这条记录后已变动")
                            print("   （正常现象，说明你上链后又改过密钥）")
                else:
                    print("❌ 编号无效")
            except:
                print("❌ 格式错误")
        else:
            password = _get_password()
            data = _load_safe(password)
            if data is None: return
            if not data:
                print("❌ 密钥库为空"); return
            data_hash = hashlib.sha256(json.dumps(data, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
            print(f"本地表情: {' '.join(hash_to_emoji(data_hash))}")
            print(f"链上页面: https://furrynaling.com/chain/{data_hash[:32]}.html")
    except Exception as e:
        print(f"❌ 查询失败(链服务器未部署): {str(e)[:60]}")

def cmd_wipe():
    """抹除式更新：删除本地所有密钥，用于版本过低/不许可更新的强制重置"""
    print("⚠️ 抹除式更新")
    print("   用途: 云端版本不许可更新，或本地版本过低时强制重置")
    print("   后果: 删除本地所有密钥、环境密钥、分片、配置")
    confirm = input("输入 nlyes 确认: ").strip()
    if confirm != "nlyes":
        print("❌ 已取消"); return
    import shutil
    removed = 0
    for f in [VAULT, ECC_KEY_FILE, HW_FILE, CONFIG_FILE, ENV_KEY_FILE]:
        if os.path.exists(f):
            os.remove(f)
            print(f"  已删除: {os.path.basename(f)}")
            removed += 1
    if os.path.exists(SHAMIR_DIR):
        shutil.rmtree(SHAMIR_DIR)
        print("  已删除: shards/")
    if os.path.exists(os.path.join(BASE_DIR, "export")):
        shutil.rmtree(os.path.join(BASE_DIR, "export"))
        print("  已删除: export/")
    print(f"✅ 已抹除 {removed} 个文件，重新运行 keynl 初始化")

def cmd_chain_file():
    """任意文件/文件夹上链校验"""
    path = input("文件或文件夹路径: ").strip()
    if not path or not os.path.exists(path):
        print("❌ 路径不存在"); return
    h = hashlib.sha256()
    try:
        if os.path.isdir(path):
            files = []
            for root, dirs, fs in os.walk(path):
                for f in fs:
                    files.append(os.path.join(root, f))
            files.sort()
            for fp in files:
                rel = os.path.relpath(fp, path)
                h.update(rel.encode())
                with open(fp, 'rb') as f:
                    for chunk in iter(lambda: f.read(8192), b''):
                        h.update(chunk)
            desc = f"文件夹 {os.path.basename(path)} ({len(files)}个文件)"
        else:
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    h.update(chunk)
            desc = f"文件 {os.path.basename(path)}"
    except Exception as e:
        print(f"❌ 读取失败: {e}"); return
    file_hash = h.hexdigest()
    emojis = hash_to_emoji(file_hash)
    print(f"对象: {desc}")
    print(f"原始哈希: {file_hash}")
    print(f"表情: {' '.join(emojis)}")
    print("⏳ 上传服务器...")
    try:
        import urllib.request
        payload = json.dumps({"hash": file_hash, "emojis": "".join(emojis)}).encode()
        req = urllib.request.Request("https://furrynaling.com/api/chain/upload",
            data=payload, headers={"Content-Type": "application/json", "User-Agent": "agent-keynl/4.3"})
        resp = json.loads(urllib.request.urlopen(req, timeout=10).read().decode())
        if resp.get("url"):
            print(f"✅ 已上链: {resp['url']}")
            if resp.get("ipfs"):
                print(f"   📦 IPFS备份: {resp['ipfs']}")
            if resp.get("ots"):
                print(f"   ⛓️ 比特币存证: {resp['ots']}")
        else:
            print(f"⚠️ {resp.get('error', '上链失败')}")
    except Exception as e:
        print(f"❌ 上传失败: {str(e)[:60]}")

def cmd_access_audit():
    """解密审计：查看解密记录 + 可选上链存证"""
    if not os.path.exists(ACCESS_LOG):
        print("📭 无解密记录（尚未成功解密过）"); return
    lines = open(ACCESS_LOG).read().strip().split('\n')
    print(f"共 {len(lines)} 次解密记录:")
    for line in lines[-20:]:
        print(f"  {line}")
    print()
    choice = input("将解密日志上链存证? (y/n): ").strip().lower()
    if choice != 'y':
        return
    h = hashlib.sha256(open(ACCESS_LOG, 'rb').read()).hexdigest()
    emojis = hash_to_emoji(h)
    print(f"日志哈希: {h}")
    print(f"表情: {' '.join(emojis)}")
    print("⏳ 上链...")
    try:
        import urllib.request
        payload = json.dumps({"hash": h, "emojis": "".join(emojis)}).encode()
        req = urllib.request.Request("https://furrynaling.com/api/chain/upload",
            data=payload, headers={"Content-Type": "application/json", "User-Agent": "agent-keynl/4.7"})
        resp = json.loads(urllib.request.urlopen(req, timeout=10).read().decode())
        if resp.get("url"):
            print(f"✅ 解密日志已上链: {resp['url']}")
        else:
            print(f"⚠️ {resp.get('error', '上链失败')}")
    except Exception as e:
        print(f"❌ 上链失败: {str(e)[:60]}")

def cmd_ots_verify():
    """验证 OTS 时间戳证明（需本机 ots CLI 或在线）"""
    import shutil, subprocess
    if not shutil.which("ots"):
        print("⚠️ 本机未安装 ots CLI")
        print("   安装: pip install opentimestamps-client")
        print("   或在线验证: https://opentimestamps.org")
        return
    path = input("输入 .ots 证明文件路径: ").strip()
    if not path or not os.path.exists(path):
        print("❌ 文件不存在"); return
    print("⏳ 验证时间戳证明（可能需联网查询比特币链）...")
    try:
        result = subprocess.run(["ots", "verify", path], capture_output=True, text=True, timeout=90)
        out = result.stdout + result.stderr
        print(out.strip() if out.strip() else "✅ 验证完成")
    except Exception as e:
        print(f"❌ 验证失败: {e}")

def cmd_mychain():
    """我的链上密钥：查看上链记录 + 选择抹除"""
    import urllib.request
    print("⏳ 查询链上记录...")
    try:
        req = urllib.request.Request("https://furrynaling.com/api/chain/list", headers={"User-Agent": "agent-keynl/4.3"})
        resp = json.loads(urllib.request.urlopen(req, timeout=10).read().decode())
        items = resp.get("items", [])
        if not items:
            print("📭 链上暂无记录")
            return
        print(f"共 {resp.get('count', len(items))} 条链上记录:")
        for i, it in enumerate(items, 1):
            print(f"  {i}. {it['emojis']}  {it['created_at']}")
            print(f"     哈希: {it['full_hash']}")
        print()
        choice = input("输入要抹除的编号(逗号分隔，如 1,3)，直接回车取消: ").strip()
        if not choice:
            print("已取消"); return
        idxs = [int(x)-1 for x in choice.split(',') if x.strip()]
        for i in idxs:
            if 0 <= i < len(items):
                full_hash = items[i]["full_hash"]
                payload = json.dumps({"hash": full_hash}).encode()
                req2 = urllib.request.Request("https://furrynaling.com/api/chain/delete",
                    data=payload, headers={"Content-Type": "application/json", "User-Agent": "agent-keynl/4.3"})
                r2 = json.loads(urllib.request.urlopen(req2, timeout=10).read().decode())
                if r2.get("success"):
                    print(f"✅ 已抹除: {items[i]['emojis']}")
                else:
                    print(f"⚠️ {r2.get('error', '删除失败')}")
    except Exception as e:
        print(f"❌ 查询失败(链服务器未部署): {str(e)[:60]}")

def print_status():
    hsm_type, hsm_desc = detect_hsm()
    cfg = load_config()
    print(f"🔐 agent-keynl v{VERSION}")
    print(f"   平台: {platform.system()} ({platform.machine()})")
    print(f"   HSM适配: {hsm_type} ({hsm_desc})")
    print(f"   加密强度: scrypt n={cfg.get('scrypt_n', 2**14)}")
    print(f"   分片方案: {cfg.get('shard_k',3)}-of-{cfg.get('shard_n',5)}")
    print(f"   内存锁: {'✅' if MLOCK_OK else '⚠️'}")
    print(f"   存储目录: {BASE_DIR}")
    print(f"   环境密钥: {'✅ 已生成' if os.path.exists(ENV_KEY_FILE) else '❌ 未生成'}")
    print(f"   密钥库: {'✅ 已初始化' if os.path.exists(VAULT) else '❌ 未初始化'}")
    print(f"   ─────────────────────────────")
    print(f"   TO：纳棂 · furrynaling@outlook.com")

# ===== 交互式菜单 =====
MENU = """━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔐 agent-keynl 主菜单
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  1. 设置主密码       2. 存密钥
  3. 读密钥          4. 列出所有密钥
  5. 删除密钥        6. 修改主密码
  7. 生成分片        8. 分片管理
  9. 修改加密强度     10. 修改分片数量
  11. 查看状态        12. 检查更新
  13. 授权窗口免密    14. 关于作者
  15. 导出API给AI     16. 上链校验
  17. 泄露查询        18. 抹除式更新
  19. 我的链上密钥     20. 文件上链
  21. 验证OTS存证     22. 解密审计
  a. 重新列出菜单表   b. 固定菜单表
  0. 退出
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""

FIXED_MENU = False

def interactive_menu():
    global FIXED_MENU
    print(MENU)
    while True:
        try:
            choice = input("请选择 [0-22, a重列菜单, b固定菜单]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print(); break
        if choice == "0":
            print("👋 再见"); break
        elif choice == "a":
            print(MENU); continue
        elif choice == "b":
            FIXED_MENU = not FIXED_MENU
            print(f"固定菜单表: {'✅ 已开启（每次操作完自动显示）' if FIXED_MENU else '❌ 已关闭（按a手动显示）'}")
            continue
        elif choice == "1": cmd_setpass()
        elif choice == "2": cmd_add()
        elif choice == "3": cmd_get()
        elif choice == "4": cmd_list()
        elif choice == "5": cmd_delete()
        elif choice == "6": cmd_changepass()
        elif choice == "7": 
            password = _get_password(); save_shards(password)
        elif choice == "8": cmd_shards_manage()
        elif choice == "9": cmd_set_strength()
        elif choice == "10": cmd_set_shards()
        elif choice == "11": print_status()
        elif choice == "12": cmd_update()
        elif choice == "13": cmd_authorize()
        elif choice == "14": cmd_about()
        elif choice == "15": cmd_export()
        elif choice == "16": cmd_chain()
        elif choice == "17": cmd_query()
        elif choice == "18": cmd_wipe()
        elif choice == "19": cmd_mychain()
        elif choice == "20": cmd_chain_file()
        elif choice == "21": cmd_ots_verify()
        elif choice == "22": cmd_access_audit()
        else: print("❌ 无效选择")
        print()
        if FIXED_MENU:
            print(MENU)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        interactive_menu()
        sys.exit(0)
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd in ("-v", "--version", "version", "-V"):
        print(f"agent-keynl v{VERSION}")
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
    elif cmd == "authorize":
        cmd_authorize()
    elif cmd == "about":
        cmd_about()
    elif cmd == "export":
        cmd_export()
    elif cmd == "api-get":
        cmd_api_get(args)
    elif cmd == "chain":
        cmd_chain()
    elif cmd == "query":
        cmd_query()
    elif cmd == "wipe":
        cmd_wipe()
    elif cmd == "mychain":
        cmd_mychain()
    elif cmd == "chain-file":
        cmd_chain_file()
    elif cmd == "ots-verify":
        cmd_ots_verify()
    elif cmd == "access-log":
        cmd_access_audit()
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
        elif cmd == "shards-manage":
            cmd_shards_manage()
        elif cmd == "delete" and args:
            data = load_vault(password)
            if args[0] in data: del data[args[0]]; save_vault(password, data); print(f"✅ {args[0]}")
