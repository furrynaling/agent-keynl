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

# 3. 下载 keymgr
echo "⬇️ 下载 keymgr..."
curl -fsSL "https://raw.githubusercontent.com/furrynaling-alt/secret-management/main/scripts/keymgr.py" -o /tmp/keymgr_tmp

# 4. 安装到系统
sudo mv /tmp/keymgr_tmp /usr/local/bin/keymgr 2>/dev/null || {
    mkdir -p "$HOME/.local/bin"
    mv /tmp/keymgr_tmp "$HOME/.local/bin/keymgr"
    echo "⚠️ 无sudo权限，安装到 ~/.local/bin/keymgr"
}
chmod 700 /usr/local/bin/keymgr 2>/dev/null || chmod 700 "$HOME/.local/bin/keymgr"

# 5. 验证
echo ""
echo "✅ 安装完成！"
echo ""
keymgr status 2>/dev/null || "$HOME/.local/bin/keymgr" status
echo ""
echo "下一步: keymgr setpass   # 设置主密码"
