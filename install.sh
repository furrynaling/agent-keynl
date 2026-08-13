#!/bin/bash
# secret-management 一键安装脚本
set -e

echo "🔐 正在安装 secret-management..."

# 1. 检查 Python
if ! command -v python3 &>/dev/null; then
    echo "❌ 需要 Python 3.11+"
    exit 1
fi

# 2. 安装依赖（带进度提示）
echo "📦 安装依赖 cryptography（首次可能较慢，请耐心等待）..."
pip3 install cryptography 2>&1 | tail -3 || {
    echo "⚠️ pip3 安装失败，尝试用户目录安装..."
    pip3 install --user cryptography 2>&1 | tail -3
}

# 3. 下载 keymgr（用 mktemp 跨平台临时文件，避免 /tmp 不可写）
echo "⬇️ 下载 keymgr..."
TMPFILE=$(mktemp)
curl -fsSL "https://raw.githubusercontent.com/furrynaling-alt/secret-management/main/scripts/keymgr.py" -o "$TMPFILE"

# 4. 安装到系统（优先 /usr/local/bin，回退 ~/.local/bin）
if [ -w /usr/local/bin ] || command -v sudo &>/dev/null; then
    sudo mv "$TMPFILE" /usr/local/bin/keymgr 2>/dev/null || mv "$TMPFILE" /usr/local/bin/keymgr
    INSTALL_PATH="/usr/local/bin/keymgr"
else
    mkdir -p "$HOME/.local/bin"
    mv "$TMPFILE" "$HOME/.local/bin/keymgr"
    INSTALL_PATH="$HOME/.local/bin/keymgr"
    echo "⚠️ 安装到 ~/.local/bin/keymgr"
fi
chmod 700 "$INSTALL_PATH"

# 5. 验证
echo ""
echo "✅ 安装完成！"
echo ""
"$INSTALL_PATH" status 2>/dev/null || keymgr status
echo ""
echo "下一步: keymgr setpass   # 设置主密码"
