#!/usr/bin/env python3
"""agent-keynl v3.3 · scrypt + HSM + Shamir + 跨平台 + 交互菜单"""
import os, sys, json, hashlib, base64, getpass, secrets, platform, ctypes, time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

VERSION = "4.22.0"

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
EMOJI_TABLE = ["😂", "😱", "🌚", "😭", "🌝", "😒", "🙄", "🤔", "😳", "😛", "🙃", "😅", "😊", "🙈", "😍", "🙊", "😘", "🙉", "😏", "🌸", "🍀", "🤟", "🫶", "🫵", "🫰", "🫦", "🤌", "👍", "👌", "🌷", "🌹", "💪", "👏", "🥚", "🦄", "🤙", "🥟", "💅", "💎", "🐔", "💄", "🍺", "💋", "🐮", "🉑", "🐻", "🐶", "💰", "🐼", "🌈", "🐖", "🖤", "🦞", "🐇", "🐟", "🦌", "🧸", "🐕", "🐈", "🐴", "💚", "💙", "🌏", "💕", "🔥", "⚡", "🎁", "✨", "🧧", "🌟", "🎉", "💫", "🎊", "🙋", "⭐", "🙆", "🌙", "👰", "🌛", "😉", "😌", "😡", "😴", "😷", "🥱", "💯", "🌂", "☔", "💦", "💤", "😎", "💊", "🤓", "🍉", "🥳", "🍔", "🥺", "🍋", "🥰", "🥭", "🤒", "🍓", "🤐", "🥒", "🤭", "🥠", "👿", "🍇", "👻", "⚽", "💩", "🏀", "🏓", "🚆", "🛀", "🃏", "🚀", "🎲", "🀄", "🔮", "🎹", "🎧", "📢", "🚗", "🚢", "🦲", "🤶", "🎅"]

def hash_to_emoji(hash_hex, count=8):
    """哈希 → count个emoji（每7bit映射128个表情之一）"""
    h = int(hash_hex, 16)
    result = ""
    for i in range(count):
        idx = (h >> (i * 7)) & 0x7F
        result += EMOJI_TABLE[idx]
    return result

# ===== 解密审计日志 =====
_last_access = [0.0]

def get_env_id():
    """环境标识（环境密钥哈希前16位），用于链上身份绑定"""
    env_key = get_env_key()
    return hashlib.sha256(b"keynl-envid:" + env_key).hexdigest()[:16]

def get_auth_token():
    """生成/读取上链认证令牌（绑定环境密钥，防陌生人上传）"""
    cfg = load_config()
    if "auth_token" not in cfg:
        cfg["auth_token"] = secrets.token_hex(32)
        save_config(cfg)
    return cfg["auth_token"]

def get_device_name():
    """获取设备名：Android用getprop设备型号，其他用platform.node"""
    try:
        model = os.popen("getprop ro.product.model 2>/dev/null").read().strip()
        if model:
            return model
    except:
        pass
    try:
        model = os.popen("getprop ro.product.device 2>/dev/null").read().strip()
        if model:
            return model
    except:
        pass
    return platform.node()

def report_decrypt():
    """已移除（纯本地化 v4.21.0）：不再向任何服务器上报解密记录"""
    return


def report_api(api_name, agent_name=""):
    """已移除（纯本地化 v4.21.0）：不再向任何服务器上报 AI 调用记录"""
    return


def cmd_audit_manage():
    """解密审查中心 —— v4.19.0 起移除（纯本地，不上传任何数据）"""
    print("ℹ️ 解密审查中心已在 v4.19.0 移除：本工具纯本地，不向任何服务器发送数据")
    print("   想看「谁在什么时候解过库」→ 本机 access.log")


def _audit_init(cfg):
    print("ℹ️ 该功能已移除（纯本地化）")


def _audit_menu(cfg):
    print("ℹ️ 该功能已移除（纯本地化）")


def _audit_reset(cfg, keyword):
    print("ℹ️ 该功能已移除（纯本地化）")


def log_access(action="解密"):
    """记录一次成功解密（60秒内去重）"""
    global _last_access
    now = time.time()
    if now - _last_access[0] < 60:
        return
    _last_access[0] = now
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    record = f"{ts} | {action} | {platform.node()}"
    try:
        f = _shard_fernet()
        encrypted = base64.b64encode(f.encrypt(record.encode())).decode()
        with open(ACCESS_LOG, 'a') as fh:
            fh.write(encrypted + "\n")
    except:
        pass
    report_decrypt()

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
# ===== 库签名（ECDSA P-384 + SHA-384，v4.22.0）=====
# 作用：给库文件盖本机私钥的章 → 有人把库换成另一份 / 偷偷改字节，能被当场发现。
# 诚实说明：私钥 ecc.key 就在本机，**能拿下本机的攻击者可以连私钥一起换掉**；
# 所以真正的"防掉包"要靠你把「签名公钥指纹」抄走（纸上/手机），对不上就是被换过。
SIG_FILE = os.path.join(BASE_DIR, "vault.sig")

def _vault_sha(blob=None):
    blob = blob if blob is not None else open(VAULT, "rb").read()
    return hashlib.sha384(blob).hexdigest()

def sign_vault():
    """给库文件盖章 → vault.sig（每次保存库时自动执行）"""
    if not os.path.exists(VAULT):
        return None
    key = get_ecc_key()
    blob = open(VAULT, "rb").read()
    sig = key.sign(_vault_sha(blob).encode(), ec.ECDSA(hashes.SHA384()))
    rec = {"v": 1, "algo": "ECDSA-P384-SHA384", "fp": get_ecc_fp(),
           "sha384": _vault_sha(blob), "sig": base64.b64encode(sig).decode(),
           "t": int(time.time())}
    os.makedirs(BASE_DIR, exist_ok=True)
    with open(SIG_FILE, "w") as fh:
        json.dump(rec, fh)
    try: os.chmod(SIG_FILE, 0o600)
    except Exception: pass
    return rec

def verify_vault_sig():
    """返回 (状态, 说明)。状态: ok / missing / tampered / keychanged"""
    if not os.path.exists(VAULT):
        return "missing", "还没有库文件"
    if not os.path.exists(SIG_FILE):
        return "missing", "该库还没有签名（下次保存会自动补上）"
    try:
        rec = json.loads(open(SIG_FILE).read())
        blob = open(VAULT, "rb").read()
        if rec.get("sha384") != _vault_sha(blob):
            return "tampered", "库文件内容与签名记录不一致 → 被改过"
        key = get_ecc_key()
        key.public_key().verify(base64.b64decode(rec["sig"]), _vault_sha(blob).encode(),
                                ec.ECDSA(hashes.SHA384()))
        if rec.get("fp") != get_ecc_fp():
            return "keychanged", f"签名是另一把钥匙盖的（记录 {rec.get('fp','?')[:12]}… / 现在 {get_ecc_fp()[:12]}…）"
        return "ok", f"签名有效 · 公钥指纹 {get_ecc_fp()[:16]}…"
    except Exception as e:
        return "tampered", f"签名校验失败（{type(e).__name__}）→ 库可能被替换或损坏"

# ===== 库加密（AEAD，v4.21.0）：AES-256-GCM 优先；无 AES-NI 的机器用 ChaCha20-Poly1305 =====
# 文件头：GCM1:=AES-256-GCM   CHP1:=ChaCha20-Poly1305   无前缀=旧版 Fernet（继续可读）
_AAD = b"agent-keynl-vault-v1"

def _aead_key(password):
    """主密码 → 32 字节原始密钥（scrypt+env.key 派生后取 SHA-256）"""
    return hashlib.sha256(derive_key(password)).digest()

def _pick_cipher():
    """有 AES-NI 用 AES-256-GCM；否则 ChaCha20-Poly1305（手机/老 ARM 更快）"""
    forced = os.environ.get("KEYNL_CIPHER", "").lower()
    if forced in ("aes", "gcm"): return "GCM1:"
    if forced in ("chacha", "chacha20"): return "CHP1:"
    try:
        if "aes" in open("/proc/cpuinfo").read(): return "GCM1:"
    except Exception:
        pass
    return "CHP1:"

def _seal(password, raw: bytes) -> bytes:
    key = _aead_key(password)
    tag = _pick_cipher()
    nonce = os.urandom(12)
    if tag == "GCM1:":
        return tag.encode() + nonce + AESGCM(key).encrypt(nonce, raw, _AAD)
    return tag.encode() + nonce + ChaCha20Poly1305(key).encrypt(nonce, raw, _AAD)

def _unseal(password, blob: bytes) -> bytes:
    key = _aead_key(password)
    if blob.startswith(b"GCM1:"):
        return AESGCM(key).decrypt(blob[5:17], blob[17:], _AAD)
    if blob.startswith(b"CHP1:"):
        return ChaCha20Poly1305(key).decrypt(blob[5:17], blob[17:], _AAD)
    return Fernet(derive_key(password)).decrypt(blob)      # v4.20 及以前的旧库

def load_vault(password):
    if not os.path.exists(VAULT): return {}
    if not check_hw(): raise Exception("❌ 硬件指纹不匹配! 密文可能被复制到其他设备")
    st, msg = verify_vault_sig()
    if st == "tampered" and os.environ.get("KEYNL_FORCE") != "1":
        raise Exception(f"❌ {msg}（确认无误可设 KEYNL_FORCE=1 强开）")
    data = json.loads(_unseal(password, open(VAULT,'rb').read()))
    if data.pop('_ecc_fp','') != get_ecc_fp(): raise Exception("❌ ECC指纹不匹配!")
    if data.pop('_sha384','') != hashlib.sha384(json.dumps({k:v for k,v in data.items() if not k.startswith('_')}, sort_keys=True).encode()).hexdigest():
        raise Exception("❌ 完整性校验失败!")
    log_access()
    return {k:v for k,v in data.items() if not k.startswith('_')}

def save_vault(password, data):
    clean = {k:v for k,v in data.items() if not k.startswith('_')}
    clean['_sha384'] = hashlib.sha384(json.dumps(clean, sort_keys=True).encode()).hexdigest()
    clean['_ecc_fp'] = get_ecc_fp()
    os.makedirs(os.path.dirname(VAULT), exist_ok=True)
    with open(VAULT, 'wb') as fh: fh.write(_seal(password, json.dumps(clean).encode()))
    try: sign_vault()
    except Exception: pass
    try: os.chmod(VAULT, 0o600)
    except: pass

# ===== 🩺 库体检（doctor）：不需要主密码，能证明"分片还救不救得回来" =====
def cmd_doctor():
    ok = True
    print("🩺 agent-keynl 库体检")
    print(f"   目录: {BASE_DIR}")
    print("─" * 36)

    # 1) 环境密钥
    if os.path.exists(ENV_KEY_FILE) and os.path.getsize(ENV_KEY_FILE) == 32:
        print("✅ 环境密钥 env.key 正常（32 字节）")
    else:
        print("❌ 环境密钥 env.key 缺失/异常 → 库无法解密（先从备份恢复）")
        ok = False

    # 2) 硬件指纹
    cur = get_hw_fingerprint()
    if not os.path.exists(HW_FILE):
        print("⚠️ hw.bin 缺失（下次开库会自动重建为当前机器 → 等于没绑定）")
        ok = False
    elif open(HW_FILE).read().strip() == cur:
        print("✅ 硬件指纹匹配（库绑定本机：机器ID+主机名+内核+MAC）")
    else:
        print("❌ 硬件指纹不匹配 → 换过内核/网卡/主机名，或这份库来自别的机器")
        ok = False

    # 3) ECC 密钥
    try:
        get_ecc_key()
        print("✅ ECC 密钥可加载（库内指纹校验的前提）")
    except Exception as e:
        print(f"❌ ECC 密钥加载失败: {type(e).__name__}")
        ok = False

    # 4) 库文件
    if not os.path.exists(VAULT):
        print("⚠️ 还没有库文件 vault.enc")
        ok = False
    else:
        print(f"✅ 库文件存在（{os.path.getsize(VAULT)} 字节密文）")
        st, msg = verify_vault_sig()
        if st == "ok":
            print(f"✅ 库签名有效（ECDSA P-384 + SHA-384）· 公钥指纹 {get_ecc_fp()[:16]}…")
        elif st == "missing":
            print(f"⚠️ {msg}")
        else:
            print(f"❌ {msg}")
            ok = False

    # 5) 分片体检（核心：不输主密码也能验证"忘密码能不能救回"）
    cfg = load_config()
    k = cfg.get("shard_k", 3)
    files = sorted(f for f in os.listdir(SHAMIR_DIR) if f.endswith(".key")) if os.path.isdir(SHAMIR_DIR) else []
    if not files:
        print(f"⚠️ 本机没有分片（离线那份若存够 {k} 片以上就正常）")
        print("   → 想验离线分片：KEYNL_SHARDS=/你放分片的目录 keynl doctor")
    elif len(files) < k:
        print(f"❌ 本机分片只有 {len(files)} 个，少于门限 {k} → 忘密码救不回来")
        ok = False
    else:
        shares, bad = {}, []
        for f in files:
            try:
                d = _read_shard(os.path.join(SHAMIR_DIR, f))
                shares[int(d["id"])] = int(d["value"])
            except Exception:
                bad.append(f)
        if bad:
            print(f"❌ 有分片解不开：{', '.join(bad)}（env.key 变了或文件损坏）")
            ok = False
        if len(shares) < k:
            print(f"❌ 可用分片不足（{len(shares)}/{k}）")
            ok = False
        else:
            ids = sorted(shares)
            tried = [ids[:k], ids[-k:]]
            if len(ids) >= k + 1:
                tried.append([ids[0]] + ids[k:])
            secrets = set()
            for s in tried:
                if len(s) >= k:
                    secrets.add(shamir_recover({i: shares[i] for i in s}))
            if len(secrets) > 1:
                print("❌ 分片互相矛盾（不是同一批生成的）→ 恢复必失败")
                ok = False
            else:
                print(f"✅ {len(shares)} 片互相自洽（任意 {k} 片还原结果一致）")
            if len(secrets) == 1 and os.path.exists(VAULT):
                try:
                    blob = _unseal(next(iter(secrets)).decode(), open(VAULT, "rb").read())
                    cnt = len([x for x in json.loads(blob) if not x.startswith("_")])
                    print(f"✅ 决定性检查：{k} 片还原出的口令能解开库（{cnt} 条）→ 分片备份有效")
                except Exception:
                    print(f"❌ 决定性检查失败：{k} 片还原出的口令打不开当前库")
                    print("   → 分片是旧的/坏的，忘密码时救不回来，请重新生成分片（菜单 7）")
                    ok = False

    print("─" * 36)
    print("🩺 结论：" + ("全部正常 ✅" if ok else "有 ❌ 项，见上（别急着删东西）"))
    if ok and os.path.exists(VAULT):
        try:
            em = hash_to_emoji(hashlib.sha256(open(VAULT, "rb").read()).hexdigest(), 8)
            print(f"   🔖 库文件表情指纹（以后变了 = 文件被改动过）: {em}")
        except Exception:
            pass
    return ok


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
    check_hw()          # 立刻把本机硬件指纹落盘（从出生就绑定）
    print("✅ 主密码已设置，密钥已生成，库已签名")
    print(f"   🔏 签名公钥指纹: {get_ecc_fp()[:24]}…")
    print("      ↳ 建议抄下来存好：以后这个指纹变了 = 库被人换过")
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
        print(f"  {k}: *** ({len(v)} 字符)")
    print("  ℹ️ 想看明文：keynl get <名称>")

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

def _token_key(token):
    """AI token 派生密钥（token + 环境密钥，绑定环境）"""
    env_key = get_env_key()
    raw = hashlib.sha256(b"keynl-token:" + token.encode() + b":" + env_key).digest()
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
    print("  3. AI token (给AI直接调用，无需主密码)")
    enc_type = input("选择 [1-3]: ").strip()
    api_name = input("API文件名(默认 api_key): ").strip() or "api_key"
    export_dir = os.path.join(BASE_DIR, "export")
    os.makedirs(export_dir, exist_ok=True)
    api_file = os.path.join(export_dir, api_name + ".enc")
    payload = json.dumps(selected, ensure_ascii=False).encode()
    if enc_type == "3":
        # AI token 类型
        token = secrets.token_hex(32)
        key = _token_key(token)
        f = Fernet(key)
        encrypted = f.encrypt(payload)
        tag = b"TK:"
        with open(api_file, 'wb') as fh:
            fh.write(tag + encrypted)
        token_file = os.path.join(export_dir, api_name + ".token")
        with open(token_file, 'w') as fh:
            fh.write(token)
        try: os.chmod(token_file, 0o600)
        except: pass
        print(f"✅ 已导出: file://{api_file}")
        print(f"   🤖 AI token: {token}")
        print(f"   AI调用: keynl api-get {api_name}")
        print(f"   （本机自动读取token，AI无需主密码）")
        return
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

def _api_decode(api_name, token=None):
    """解密 export/<名>.enc → dict。TK 类型免主密码；失败抛异常"""
    export_dir = os.path.join(BASE_DIR, "export")
    api_file = os.path.join(export_dir, api_name + ".enc")
    if not os.path.exists(api_file):
        raise FileNotFoundError(f"export/{api_name}.enc 不存在（先跑 keynl export）")
    raw = open(api_file, "rb").read()
    if raw.startswith(b"TK:"):
        tok = token
        tf = os.path.join(export_dir, api_name + ".token")
        if not tok and os.path.exists(tf):
            tok = open(tf).read().strip()
        if not tok:
            raise ValueError("无 token（需要 export/%s.token）" % api_name)
        return json.loads(Fernet(_token_key(tok)).decrypt(raw[3:]))
    if raw.startswith(b"HW:"):
        return json.loads(Fernet(_api_key(_get_password(), True)).decrypt(raw[3:]))
    if raw.startswith(b"PW:"):
        return json.loads(Fernet(_api_key(_get_password(), False)).decrypt(raw[3:]))
    return json.loads(Fernet(_api_key(_get_password(), False)).decrypt(raw))

def cmd_api_get(args):
    """keynl api-get <名> [--show]  （不带 --show 只加载环境变量、不回显明文）"""
    if not args:
        print("用法: keynl api-get <API名> [--show]"); return
    api_name = args[0]
    try:
        selected = _api_decode(api_name)
    except FileNotFoundError as e:
        print(f"❌ {e}"); return
    except Exception as e:
        print(f"❌ 解密失败（token 错误 / 不在原环境 / 密码错误）: {type(e).__name__}"); return
    show = "--show" in args
    env_names = []
    for k, v in selected.items():
        try:
            fields = json.loads(v)
            if isinstance(fields, dict):
                for k2, v2 in fields.items():
                    os.environ[k2] = str(v2); env_names.append(k2)
                continue
        except Exception:
            pass
        os.environ[k] = str(v); env_names.append(k)
    if show:
        for k, v in selected.items():
            try:
                fields = json.loads(v)
                if isinstance(fields, dict):
                    print(f"  {k}:")
                    for k2, v2 in fields.items(): print(f"    {k2} = {v2}")
                    continue
            except Exception:
                pass
            print(f"  {k} = {v}")
    else:
        print(f"✅ 已加载 {len(env_names)} 个密钥到环境变量（未回显明文）")
        print(f"   变量: {', '.join(env_names)}")
        print(f"   AI可用 $变量名 引用，无需看到密钥")

def cmd_api_run(args):
    """keynl api-run <名> [--once] [--var 变量名] -- <命令...>
    密钥只注入子进程环境变量：不打印、不进日志、不落磁盘（阅后即焚）。
    --once: 跑完就把该凭据（.enc+.token）销毁，下次要用得重新导出。
    """
    import subprocess
    if not args:
        export_dir = os.path.join(BASE_DIR, "export")
        names = sorted(f[:-4] for f in os.listdir(export_dir) if f.endswith(".enc")) if os.path.isdir(export_dir) else []
        print("🔐 阅后即焚调用（api-run）：密钥只进子进程内存，不打印、不进日志")
        if not names:
            print("   （还没有导出凭据：先用 keynl export 生成）"); return
        print(f"   可用凭据: {', '.join(names)}")
        print("   用法: keynl api-run <凭据名> [--once] -- <命令>")
        print("   例:   keynl api-run smtp --once -- curl -u \"$SMTP_USER:$SMTP_PASS\" https://api.example.com/send")
        return
    api_name = args[0]
    rest = args[1:]
    once = "--once" in rest
    rest = [a for a in rest if a != "--once"]
    uses = 1 if once else 0
    if "--uses" in rest:
        i = rest.index("--uses")
        try: uses = int(rest[i + 1])
        except Exception: uses = 0
        del rest[i:i + 2]
    var = None
    if "--var" in rest:
        i = rest.index("--var"); var = rest[i + 1]; del rest[i:i + 2]
    if "--" in rest:
        cmdv = rest[rest.index("--") + 1:]
    else:
        cmdv = rest
    if not cmdv:
        print("❌ 缺少要执行的命令：keynl api-run <名> -- <命令...>"); return
    try:
        selected = _api_decode(api_name)
    except Exception as e:
        print(f"❌ 取不到凭据（{type(e).__name__}）"); return
    env = dict(os.environ)
    injected = []
    for k, v in selected.items():
        vals = {}
        try:
            f = json.loads(v)
            if isinstance(f, dict): vals = {str(a): str(b) for a, b in f.items()}
        except Exception:
            pass
        if vals: env.update(vals); injected += list(vals)
        else:
            env[k] = str(v); injected.append(k)
    print(f"▶️ 执行（已注入 {len(injected)} 个变量：{', '.join(injected)}；值不回显）")
    try:
        rc = subprocess.call(cmdv, env=env)
    except Exception as e:
        print(f"❌ 执行失败: {e}"); return
    # 阅后即焚：--once 用一次就销毁；--uses N 限次（跑完计数 -1，归零即焚）
    burn = False
    if uses > 0:
        cnt_file = os.path.join(BASE_DIR, "export", api_name + ".uses")
        left = uses
        if os.path.exists(cnt_file):
            try: left = int(open(cnt_file).read().strip())
            except Exception: left = uses
        left -= 1
        if left <= 0:
            burn = True
        else:
            with open(cnt_file, "w") as fh: fh.write(str(left))
            try: os.chmod(cnt_file, 0o600)
            except Exception: pass
    if burn:
        for ext in (".enc", ".token", ".uses"):
            f = os.path.join(BASE_DIR, "export", api_name + ext)
            try:
                if os.path.exists(f):
                    os.system(f"shred -u '{f}' 2>/dev/null || rm -f '{f}'")
            except Exception:
                pass
        print(f"🔥 阅后即焚：{api_name} 的凭据已销毁（下次要用先重新 export）")
    elif uses > 0:
        print(f"🔒 剩余可用次数：{left}（归零自动销毁）")
    print(f"✅ 命令结束（退出码 {rc}）")


def cmd_chain(*a, **kw):
    """上链校验 —— v4.19.0 起移除（纯本地化，不向任何服务器发送数据）"""
    print("ℹ️ 上链校验 已移除：本工具纯本地，不上传任何数据")


def cmd_query():
    """泄露查询（原：对比链上记录）—— v4.19.0 起移除（纯本地化）"""
    print("ℹ️ 泄露/链上查询已移除：本工具纯本地，不上链、不上传")
    print("   想检查库文件有没有被改动：keynl doctor 会打印 8 个 emoji 指纹，变了就是被改过")


def cmd_wipe():
    """抹除式更新：删除本地所有密钥，用于版本过低/不许可更新的强制重置（需主密码验证）"""
    if os.path.exists(VAULT):
        password = _get_password()
        if _load_safe(password) is None:
            print("❌ 主密码错误，无法抹除")
            return
        print("✅ 主密码验证通过")
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

def cmd_chain_file(*a, **kw):
    """文件上链 —— v4.19.0 起移除（纯本地化，不向任何服务器发送数据）"""
    print("ℹ️ 文件上链 已移除：本工具纯本地，不上传任何数据")


def cmd_access_audit(*a, **kw):
    """云端访问审计 —— v4.19.0 起移除（纯本地化，不向任何服务器发送数据）"""
    print("ℹ️ 云端访问审计 已移除：本工具纯本地，不上传任何数据")


def _file_hash(path):
    """计算文件/文件夹的哈希"""
    h = hashlib.sha256()
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
    return h.hexdigest(), desc

def cmd_file_check():
    """本地文件篡改查询：重新算哈希，对比链上锚点"""
    path = input("文件或文件夹路径: ").strip()
    if not path or not os.path.exists(path):
        print("❌ 路径不存在"); return
    try:
        file_hash, desc = _file_hash(path)
    except Exception as e:
        print(f"❌ 读取失败: {e}"); return
    emojis = hash_to_emoji(file_hash)
    print(f"对象: {desc}")
    print(f"原始哈希: {file_hash}")
    print(f"本地表情: {' '.join(emojis)}")
    print("本地比对：与上次记下的表情一致=未篡改，不一致=文件被改过")
    print("（本工具不上链、不联网；要看库文件的指纹跑 keynl doctor）")

def cmd_ots_verify(*a, **kw):
    """OpenTimestamps 验证 —— v4.19.0 起移除（纯本地化，不向任何服务器发送数据）"""
    print("ℹ️ OpenTimestamps 验证 已移除：本工具纯本地，不上传任何数据")


def cmd_uninstall():
    """卸载 keynl：删除程序 + 所有数据（需主密码验证）"""
    if os.path.exists(VAULT):
        password = _get_password()
        if _load_safe(password) is None:
            print("❌ 主密码错误，无法卸载")
            return
        print("✅ 主密码验证通过")
    print("⚠️ 卸载 keynl")
    print("   将删除: 程序文件 + 所有密钥/分片/配置/解密记录")
    print("   此操作【不可逆】！")
    confirm = input("输入 UNINSTALL 确认: ").strip()
    if confirm != "UNINSTALL":
        print("❌ 已取消"); return
    import shutil
    # 1. 删除数据目录
    if os.path.exists(BASE_DIR):
        shutil.rmtree(BASE_DIR)
        print(f"✅ 已删除数据目录: {BASE_DIR}")
    # 2. 删除程序文件
    self_path = os.path.abspath(sys.argv[0])
    removed = []
    candidates = [self_path, self_path + ".bak",
                  "/usr/local/bin/keynl", os.path.expanduser("~/.local/bin/keynl")]
    for p in candidates:
        if os.path.exists(p) and p not in removed:
            try:
                os.remove(p)
                removed.append(p)
            except:
                pass
    for p in removed:
        print(f"✅ 已删除: {p}")
    print("✅ keynl 已卸载")
    print("   重装: curl -fsSL https://raw.githubusercontent.com/furrynaling/agent-keynl/main/install.sh | bash")

def cmd_mychain(*a, **kw):
    """链上记录管理 —— v4.19.0 起移除（纯本地化，不向任何服务器发送数据）"""
    print("ℹ️ 链上记录管理 已移除：本工具纯本地，不上传任何数据")


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
def _pad(text, width):
    """中文宽度对齐"""
    w = sum(2 if ord(c) > 127 else 1 for c in text)
    return text + ' ' * max(0, width - w)

def _menu_rows():
    rows = [
        ("1. 设置主密码", "2. 存密钥"),
        ("3. 读密钥", "4. 列出所有密钥"),
        ("5. 删除密钥", "6. 修改主密码"),
        ("7. 生成分片", "8. 分片管理"),
        ("9. 修改加密强度", "10. 修改分片数量"),
        ("11. 查看状态", "12. 检查更新"),
        ("13. 授权窗口免密", "14. 关于作者"),
        ("15. 导出API给AI", "16. 抹除式更新"),
        ("17. 卸载keynl", "18. 库体检(doctor)"),
        ("19. 阅后即焚调用", ""),
        ("a. 重新列出菜单表", "b. 固定菜单表"),
        ("0. 退出", ""),
    ]
    lines = []
    for left, right in rows:
        if right:
            lines.append("  " + _pad(left, 21) + right)
        else:
            lines.append("  " + left)
    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    return "\n".join(lines)

def get_menu():
    """动态菜单：已初始化审查中心则显示云上菜单"""
    cfg = load_config()
    header = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n🔐 agent-keynl 主菜单 · 纯本地\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    return header + "\n" + _menu_rows()

FIXED_MENU = False

def interactive_menu():
    global FIXED_MENU
    print(get_menu())
    while True:
        try:
            choice = input("请选择 [0-25, a重列菜单, b固定菜单]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print(); break
        if choice == "0":
            print("👋 再见"); break
        elif choice == "a":
            print(get_menu()); continue
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
        elif choice == "16": cmd_wipe()
        elif choice == "17": cmd_uninstall()
        elif choice == "18": cmd_doctor()
        elif choice == "19": cmd_api_run([])
        else: print("❌ 无效选择")
        print()
        if FIXED_MENU:
            print(get_menu())

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
    elif cmd == "wipe":
        cmd_wipe()
    elif cmd == "uninstall":
        cmd_uninstall()
    elif cmd == "api-run":
        cmd_api_run(args)
    elif cmd == "doctor":
        sys.exit(0 if cmd_doctor() else 1)
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
                print(f"  {k}: *** ({len(v)} 字符)")
            if data: print("  ℹ️ 想看明文：keynl get <名称>")
        elif cmd == "shards":
            save_shards(password)
        elif cmd == "recover":
            cmd_recover()
        elif cmd == "shards-manage":
            cmd_shards_manage()
        elif cmd == "delete" and args:
            data = load_vault(password)
            if args[0] in data: del data[args[0]]; save_vault(password, data); print(f"✅ {args[0]}")
