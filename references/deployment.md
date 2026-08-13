# 部署指南

## 环境要求

```
Python 3.11+
依赖: cryptography, cryptography
内存: ≥ 128MB（scrypt 需要 64MB）
```

## 安装

```bash
# 1. 安装依赖
pip install cryptography cryptography

# 2. 复制脚本
cp scripts/keymgr.py /usr/local/bin/keymgr
chmod 700 /usr/local/bin/keymgr

# 3. 验证
keymgr   # 应显示硬件指纹
```

## 首次使用

```bash
# 初始化（自动采集硬件指纹）
echo "你的主密码" | keymgr add first_key "test"

# 验证
echo "你的主密码" | keymgr list
# 应输出: first_key: test
```

## 伪装目录

密钥库默认存储在 `/root/mytp/`，伪装成 Node.js 项目：

```
/root/mytp/
├── package.json          ← 假依赖声明
├── README.md             ← 假说明
├── launcher.sh           ← 假启动脚本
├── src/
│   ├── index.js          ← 假入口
│   └── config.js         ← 假配置
├── lib/
│   ├── utils.py          ← 假工具
│   └── crypto.py         ← 假加密库
├── data/
│   ├── cache.db          ← 假数据库
│   ├── sessions.bin      ← 假缓存
│   └── server.log        ← 假日志
└── .keys/                ← 真实密钥（隐藏）
    ├── vault.enc         ← 加密密钥库
    ├── ecc.key           ← ECC 私钥
    ├── hw.bin            ← 硬件指纹
    ├── decoy.hash        ← 假文件校验
    └── shards/           ← Shamir 分片
```

## 日常操作

```bash
# 存密钥
echo "主密码" | keymgr add <key> <value>

# 读密钥
echo "主密码" | keymgr get <key>

# 列表
echo "主密码" | keymgr list

# 删除
echo "主密码" | keymgr delete <key>

# 生成分片
echo "主密码" | keymgr shards
```

## 故障恢复

### 误删假文件

```bash
# 1. 重建被删的假文件
echo 'module.exports={...}' > /root/mytp/src/config.js

# 2. 删除校验缓存
rm /root/mytp/.keys/decoy.hash

# 3. 重新访问 → 自动重建校验
echo "主密码" | keymgr list
```

### 忘了主密码

用 Shamir 分片恢复（需至少 3 份）。

### 换服务器迁移

1. 新服务器安装 keymgr
2. 用分片恢复主密码
3. 新服务器重建 vault

## 安全建议

1. **主密码 ≥ 16 位**，混合大小写+数字+符号
2. **立即生成 Shamir 分片**，分散保存
3. **定期轮换密钥**（API Key 建议 90 天）
4. **别把主密码写进任何脚本/文档**
5. **别在共享终端输入主密码**（防 history 泄露）
