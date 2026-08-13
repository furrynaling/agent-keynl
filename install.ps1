# secret-management Windows 一键安装
# PowerShell 运行: irm https://.../install.ps1 | iex
Write-Host "🔐 正在安装 secret-management (Windows)..."

# 1. 检查 Python
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "❌ 需要 Python 3.11+，请先安装 https://python.org" -ForegroundColor Red
    exit 1
}

# 2. 安装依赖
Write-Host "📦 安装依赖 cryptography..."
pip install cryptography 2>&1 | Select-Object -Last 2

# 3. 下载 keymgr.py
Write-Host "⬇️ 下载 keymgr..."
$installDir = Join-Path $env:APPDATA "secret-management"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/furrynaling-alt/secret-management/main/scripts/keymgr.py" `
    -OutFile (Join-Path $installDir "keymgr.py") -UseBasicParsing

# 4. 创建 wrapper 脚本
$wrapper = Join-Path $installDir "keymgr.cmd"
@"
@echo off
python "$installDir\keymgr.py" %*
"@ | Out-File -FilePath $wrapper -Encoding ASCII

# 5. 加入 PATH
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$installDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$installDir", "User")
    Write-Host "⚠️ 已加入 PATH，重开终端生效"
}

Write-Host ""
Write-Host "✅ 安装完成！" -ForegroundColor Green
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
Write-Host "📖 使用说明"
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
Write-Host ""
Write-Host "  1. 设主密码:      keymgr setpass"
Write-Host "  2. 存密钥:        keymgr add <名称> <值>"
Write-Host "  3. 读密钥:        keymgr get <名称>"
Write-Host "  4. 列出所有:      keymgr list"
Write-Host "  5. 删除密钥:      keymgr delete <名称>"
Write-Host "  6. 改密码:        keymgr changepass"
Write-Host "  7. 生成分片:      keymgr shards"
Write-Host "  8. 查看状态:      keymgr status"
