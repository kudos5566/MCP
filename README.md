# MCP kali安全工具集成平台

一个集成了多种安全扫描工具的渗透测试平台，支持Excel报告生成和MCP协议集成。

## 🚀 项目特性

### 核心功能
- **多工具集成**: 集成Nmap、Gobuster、Nikto、URLFinder、WPScan、Enum4linux等主流安全工具


- **Excel报告生成**: 自动生成专业的安全扫描Excel报告，包含漏洞详情和修复建议
- **MCP协议支持**: 兼容Model Context Protocol
- **CVE漏洞查询**: 集成NVD数据库，提供详细的CVE漏洞信息和修复建议

### 技术特性
- **RESTful API**: 提供完整的REST API接口，支持程序化调用
- **异步执行**: 支持长时间运行的扫描任务，避免超时问题
- **结果缓存**: 智能缓存扫描结果，提高查询效率


## 📋 系统要求

### 操作系统
- Kali Linux (推荐)
- Ubuntu/Debian (需手动安装安全工具)
- 其他Linux发行版 (需手动安装依赖)

### 必需工具
- `nmap` - 网络扫描
- `gobuster` - 目录/文件爆破
- `nikto` - Web漏洞扫描
- `URLFinder` - URL发现工具 (需要手动安装，加入Kali Linux的环境变量)
- `wpscan` - WordPress扫描 (可选)
- `enum4linux` - SMB枚举 (可选)


## 🛠️ 安装配置

### 1. 克隆项目
```bash
git clone <repository-url>
cd shiyan
```

### 2. 安装Python依赖
```bash
pip install -r requirements.txt
```

### 3. 安装安全工具 (Kali Linux)
```bash
# 大部分工具在Kali Linux中已预装
sudo apt update
sudo apt install nmap gobuster nikto wpscan enum4linux-ng

# 安装URLFinder (如果未安装)
# 请根据URLFinder的官方文档进行安装
```

### 4. 配置环境变量
复制并编辑环境配置文件：
```bash
cp .env.example .env
```

编辑 `.env` 文件进行必要的配置。

## 🚀 使用方法

### 启动服务器
```bash
# 第一步kali虚拟机启动
python kali_server_modular.py

# 第二步物理机启动
python kali_mcp_client.py --server http://kali的地址:5000 

# 配置Trea的MCP
{
  "mcpServers": {
    "kali_mcp": {
      "command": "cmd",
      "args": [
        "/c",
        "python",
        "本地server路径", #比如：C:/xx/xx/kali_server.py
        "--server",
        "http://kaliIP:5000" # kali的地址
      ]
    }
  }
}


## 📊 Excel报告功能

生成的Excel报告包含以下工作表：

1. **扫描摘要**: 目标信息、扫描统计、风险概览
2. **详细扫描结果**: 各工具的执行详情和输出
3. **发现的漏洞**: 漏洞分类、风险等级、修复建议
4. **二次扫描结果**: 深度扫描发现的问题


## 🔧 配置选项

### 环境变量配置
项目支持通过 `.env` 文件进行详细配置。以下是完整的配置选项：

```bash
# ===========================================
# 服务器配置
# ===========================================
API_PORT=5000                    # API服务器端口
DEBUG_MODE=0                     # 调试模式 (0=关闭, 1=开启)
COMMAND_TIMEOUT=300              # 命令执行超时时间（秒）

# ===========================================
# 扫描配置
# ===========================================
MAX_SCAN_HISTORY=100            # 最大扫描历史记录数

MAX_CVE_CACHE_DAYS=7             # CVE缓存有效期（天）

# ===========================================
# 安全配置
# ===========================================
API_KEY=your_secure_api_key_here # API访问密钥（可选）
ALLOWED_IPS=127.0.0.1,localhost # 允许访问的IP地址
ENABLE_DANGEROUS_COMMANDS=0      # 是否允许危险命令（0=禁用, 1=启用）

# ===========================================
# 目录配置
# ===========================================
CACHE_DIR=./cache               # 缓存目录
REPORTS_DIR=./reports           # 报告存储目录

# ===========================================
# NVD API配置
# ===========================================
NVD_API_URL=https://services.nvd.nist.gov/rest/json/cves/2.0
NVD_REQUEST_TIMEOUT=30          # NVD API请求超时时间（秒）

# ===========================================
# 工具默认参数
# ===========================================
NMAP_DEFAULT_ARGS=-sV -sC -T4 -Pn              # Nmap默认参数
GOBUSTER_DEFAULT_WORDLIST=/usr/share/wordlists/dirb/common.txt  # Gobuster默认字典
NIKTO_DEFAULT_ARGS=-ask no                      # Nikto默认参数
```

### 扫描配置详解

#### 基本扫描参数
- **超时控制**：`COMMAND_TIMEOUT` 控制单个命令的最大执行时间
- **历史管理**：`MAX_SCAN_HISTORY` 限制内存中保存的扫描记录数量


#### 安全配置
- **API密钥**：设置 `API_KEY` 启用API访问控制
- **IP白名单**：`ALLOWED_IPS` 限制可访问的客户端IP
- **危险命令**：`ENABLE_DANGEROUS_COMMANDS` 控制是否允许执行潜在危险的系统命令

#### 工具特定配置
- **Nmap**：`NMAP_DEFAULT_ARGS` 设置默认扫描参数
- **Gobuster**：`GOBUSTER_DEFAULT_WORDLIST` 指定目录枚举字典文件
- **Nikto**：`NIKTO_DEFAULT_ARGS` 配置漏洞扫描选项

### 性能优化配置

#### 内存管理
```bash
# 控制内存使用
MAX_SCAN_HISTORY=50              # 减少历史记录以节省内存

```

#### 扫描速度优化
```bash
# 加快扫描速度
COMMAND_TIMEOUT=180              # 减少超时时间
NMAP_DEFAULT_ARGS=-sS -T5 -Pn   # 使用更快的Nmap参数
```

#### 缓存优化
```bash
# CVE缓存配置
MAX_CVE_CACHE_DAYS=30            # 延长缓存时间以减少API调用
CACHE_DIR=/tmp/kali_cache        # 使用更快的存储位置
```

## 版本管理

### 当前版本
- **版本号**: 1.2.2
- **发布日期**: 2025-07-11
- **Python要求**: >=3.11

### 版本查询API
```bash
# 获取详细版本信息
curl http://localhost:5000/api/version
```


## 🛡️ 安全注意事项

1. **授权扫描**: 仅对授权目标进行扫描，遵守相关法律法规
2. **网络隔离**: 建议在隔离的测试环境中运行
3. **日志管理**: 定期清理扫描日志和缓存文件

## 🔍 故障排除

### 常见问题

**1. 工具未找到错误**
```bash
# 检查工具是否安装
which nmap gobuster nikto

# 安装缺失的工具
sudo apt install <tool-name>
```


## 📄 许可证

本项目采用 MIT 许可证，详见 LICENSE 文件。

## 🤝 贡献

欢迎提交Issue和Pull Request来改进项目！

## 📞 支持

如有问题或建议，请通过以下方式联系：
- 提交GitHub Issue
- 发送邮件至项目维护者

---

**免责声明**: 本工具仅用于授权的安全测试和教育目的。使用者需遵守当地法律法规，对使用本工具产生的任何后果承担责任。
