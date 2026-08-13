#!/bin/bash
# secret-management 一键安装脚本（含 SHA256 校验）
set -e

echo "🔐 正在安装 secret-management..."

# keymgr.py 的 SHA256 哈希（防传输篡改）
EXPECTED_SHA256="ebd7e7bfe19356be768f03ee6d252eab3069338688677bfa848f4d865549f5ad"

# 1. 检查 Python
if ! command -v python3 &>/dev/null; then
    echo "❌ 需要 Python 3.11+，请先安装"
    exit 1
fi

# 2. 安装依赖
echo "📦 安装依赖 (argon2-cffi, cryptography)..."
pip3 install argon2-cffi cryptography -q 2>/dev/null || \
  pip3 install --user argon2-cffi cryptography -q

# 3. 下载 keymgr
echo "⬇️ 下载 keymgr..."
TMPFILE=$(mktemp)
curl -fsSL "https://raw.githubusercontent.com/furrynaling-alt/secret-management/main/scripts/keymgr.py" -o "$TMPFILE"

# 4. SHA256 校验
echo "🔍 校验文件完整性..."
ACTUAL_SHA256=$(sha256sum "$TMPFILE" | awk '{print $1}')
if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
    echo "❌ 校验失败！文件可能被篡改"
    echo "   期望: $EXPECTED_SHA256"
    echo "   实际: $ACTUAL_SHA256"
    rm -f "$TMPFILE"
    exit 1
fi
echo "✅ 哈希校验通过"

# 5. 安装到系统
sudo mv "$TMPFILE" /usr/local/bin/keymgr 2>/dev/null || \
  (mkdir -p "$HOME/.local/bin" && mv "$TMPFILE" "$HOME/.local/bin/keymgr")
chmod 700 /usr/local/bin/keymgr 2>/dev/null || chmod 700 "$HOME/.local/bin/keymgr"

# 6. 验证
echo ""
echo "✅ 安装完成！"
echo ""
keymgr status 2>/dev/null || "$HOME/.local/bin/keymgr" status
echo ""
echo "下一步: keymgr setpass   # 设置主密码"
