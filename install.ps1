# agent-keynl Windows 一键安装
# PowerShell 运行: irm https://.../install.ps1 | iex
Write-Host "🔐 正在安装 agent-keynl (Windows)..."

# 1. 检查 Python
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "❌ 需要 Python 3.11+，请先安装 https://python.org" -ForegroundColor Red
    exit 1
}

# 2. 安装依赖
Write-Host "📦 安装依赖 cryptography..."
pip install cryptography 2>&1 | Select-Object -Last 2

# 3. 下载 keynl.py
Write-Host "⬇️ 下载 keynl..."
$installDir = Join-Path $env:APPDATA "agent-keynl"
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/furrynaling/agent-keynl/main/scripts/keynl.py" `
    -OutFile (Join-Path $installDir "keynl.py") -UseBasicParsing

# 4. 创建 wrapper 脚本
$wrapper = Join-Path $installDir "keynl.cmd"
@"
@echo off
python "$installDir\keynl.py" %*
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
Write-Host "  1. 设主密码:      keynl setpass"
Write-Host "  2. 存密钥:        keynl add <名称> <值>"
Write-Host "  3. 读密钥:        keynl get <名称>"
Write-Host "  4. 列出所有:      keynl list"
Write-Host "  5. 删除密钥:      keynl delete <名称>"
Write-Host "  6. 改密码:        keynl changepass"
Write-Host "  7. 生成分片:      keynl shards"
Write-Host "  8. 查看状态:      keynl status"
