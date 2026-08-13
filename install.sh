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

# 3. 下载 keynl（用 mktemp 跨平台临时文件）
echo "⬇️ 下载 keynl..."
TMPFILE=$(mktemp)
curl -fsSL "https://raw.githubusercontent.com/furrynaling/secret-management/main/scripts/keynl.py" -o "$TMPFILE"

# 4. 安装路径判断
#    Termux: $PREFIX/bin（一定在 PATH 里）
#    有 root: /usr/local/bin
#    无 root: ~/.local/bin（需要手动加 PATH）
if [ -n "$PREFIX" ] && [ -d "$PREFIX/bin" ]; then
    # Termux 环境
    mv "$TMPFILE" "$PREFIX/bin/keynl"
    chmod 700 "$PREFIX/bin/keynl"
    INSTALL_PATH="$PREFIX/bin/keynl"
    echo "📱 检测到 Termux，安装到 $PREFIX/bin/keynl"
elif [ -w /usr/local/bin ] || command -v sudo &>/dev/null; then
    sudo mv "$TMPFILE" /usr/local/bin/keynl 2>/dev/null || mv "$TMPFILE" /usr/local/bin/keynl
    chmod 700 /usr/local/bin/keynl
    INSTALL_PATH="/usr/local/bin/keynl"
else
    mkdir -p "$HOME/.local/bin"
    mv "$TMPFILE" "$HOME/.local/bin/keynl"
    chmod 700 "$HOME/.local/bin/keynl"
    INSTALL_PATH="$HOME/.local/bin/keynl"
    # 加 PATH
    grep -q '\.local/bin' "$HOME/.bashrc" 2>/dev/null || \
      echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
    echo "⚠️ 安装到 ~/.local/bin/keynl（已加入 PATH，重开终端生效）"
fi

# 5. 验证 + 使用说明
echo ""
echo "✅ 安装完成！"
echo ""
"$INSTALL_PATH" status 2>/dev/null
echo ""
echo ""
echo "TO：纳棂 · furrynaling@outlook.com"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📖 使用说明"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  1. 设主密码:      keynl setpass"
echo "  2. 存密钥:        keynl add <名称> <值>"
echo "     例:            keynl add cf_token \"cfat_xxx\""
echo "  3. 读密钥:        keynl get <名称>"
echo "  4. 列出所有:      keynl list"
echo "  5. 删除密钥:      keynl delete <名称>"
echo "  6. 改密码:        keynl changepass"
echo "  7. 生成分片:      keynl shards"
echo "  8. 从分片恢复:    keynl recover"
echo "  9. 查看状态:      keynl status"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
