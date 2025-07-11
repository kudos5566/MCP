#!/usr/bin/env python3
"""
配置管理模块

集中管理所有配置参数，包括环境变量加载、默认值设置、
安全配置、目录配置等。
"""

import os
import logging
import sys
from typing import Dict, Any, List
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

class Config:
    """
    配置管理类
    
    集中管理所有应用配置，支持环境变量覆盖默认值
    """
    
    def __init__(self):
        """初始化配置"""
        self._load_basic_config()
        self._load_security_config()
        self._load_directory_config()
        self._load_api_config()
        self._load_tool_config()
        self._setup_directories()
        self._setup_logging()
    
    def _load_basic_config(self):
        """加载基础配置"""
        # API服务配置
        self.API_PORT = int(os.environ.get("API_PORT", 5000))
        self.DEBUG_MODE = os.environ.get("DEBUG_MODE", "false").lower() in ("1", "true", "yes", "y")
        
        # 执行配置
        self.COMMAND_TIMEOUT = int(os.environ.get("COMMAND_TIMEOUT", 180))
        self.MAX_SCAN_HISTORY = int(os.environ.get("MAX_SCAN_HISTORY", 100))
        
        # 缓存配置
        self.MAX_CVE_CACHE_DAYS = int(os.environ.get("MAX_CVE_CACHE_DAYS", 7))
    
    def _load_security_config(self):
        """加载安全配置"""
        self.API_KEY = os.environ.get("API_KEY", "")
        self.ALLOWED_IPS = os.environ.get("ALLOWED_IPS", "127.0.0.1,192.168.0.0/16").split(",")
        self.ENABLE_DANGEROUS_COMMANDS = os.environ.get("ENABLE_DANGEROUS_COMMANDS", "false").lower() in ("1", "true", "yes", "y")
    
    def _load_directory_config(self):
        """加载目录配置"""
        self.CACHE_DIR = os.environ.get("CACHE_DIR", "./cve_cache")
        self.REPORTS_DIR = os.environ.get("REPORTS_DIR", "./reports")
    
    def _load_api_config(self):
        """加载API配置"""
        # NVD API配置
        self.NVD_API_URL = os.environ.get("NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
        self.NVD_REQUEST_TIMEOUT = int(os.environ.get("NVD_REQUEST_TIMEOUT", 30))
    
    def _load_tool_config(self):
        """加载工具默认参数配置"""
        self.NMAP_DEFAULT_ARGS = os.environ.get("NMAP_DEFAULT_ARGS", "-T4 -Pn")
        self.GOBUSTER_DEFAULT_WORDLIST = os.environ.get("GOBUSTER_DEFAULT_WORDLIST", "/usr/share/wordlists/dirb/common.txt")
        self.NIKTO_DEFAULT_ARGS = os.environ.get("NIKTO_DEFAULT_ARGS", "-C all")
        self.NIKTO_DEFAULT_PLUGINS = os.environ.get("NIKTO_DEFAULT_PLUGINS", "@@ALL")
        self.JOHN_DEFAULT_WORDLIST = os.environ.get("JOHN_DEFAULT_WORDLIST", "/usr/share/wordlists/rockyou.txt")
        self.URLFINDER_DEFAULT_DEPTH = int(os.environ.get("URLFINDER_DEFAULT_DEPTH", "3"))
        self.SQLMAP_DEFAULT_LEVEL = int(os.environ.get("SQLMAP_DEFAULT_LEVEL", "1"))
        self.SQLMAP_DEFAULT_RISK = int(os.environ.get("SQLMAP_DEFAULT_RISK", "1"))
        self.WPSCAN_API_TOKEN = os.environ.get("WPSCAN_API_TOKEN", "")
        self.HYDRA_DEFAULT_USERLIST = os.environ.get("HYDRA_DEFAULT_USERLIST", "/usr/share/wordlists/metasploit/unix_users.txt")
        self.HYDRA_DEFAULT_PASSLIST = os.environ.get("HYDRA_DEFAULT_PASSLIST", "/usr/share/wordlists/metasploit/unix_passwords.txt")
    
    def _setup_directories(self):
        """创建必要的目录"""
        try:
            os.makedirs(self.CACHE_DIR, exist_ok=True)
            os.makedirs(self.REPORTS_DIR, exist_ok=True)
        except Exception as e:
            print(f"创建目录失败: {str(e)}")
            raise
    
    def _setup_logging(self):
        """设置日志配置"""
        logging.basicConfig(
            level=logging.DEBUG if self.DEBUG_MODE else logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            handlers=[logging.StreamHandler(sys.stdout)]
        )
        self.logger = logging.getLogger(__name__)
        
        # 记录配置加载完成
        self.logger.info(f"配置加载完成: API端口={self.API_PORT}, 调试模式={self.DEBUG_MODE}, 命令超时={self.COMMAND_TIMEOUT}秒")
    
    def get_config_dict(self) -> Dict[str, Any]:
        """获取配置字典，用于调试和监控"""
        return {
            "api_port": self.API_PORT,
            "debug_mode": self.DEBUG_MODE,
            "command_timeout": self.COMMAND_TIMEOUT,
            "max_scan_history": self.MAX_SCAN_HISTORY,
            "max_cve_cache_days": self.MAX_CVE_CACHE_DAYS,
            "cache_dir": self.CACHE_DIR,
            "reports_dir": self.REPORTS_DIR,
            "nvd_api_url": self.NVD_API_URL,
            "nvd_request_timeout": self.NVD_REQUEST_TIMEOUT,
            "nmap_default_args": self.NMAP_DEFAULT_ARGS,
            "gobuster_default_wordlist": self.GOBUSTER_DEFAULT_WORDLIST,
            "nikto_default_args": self.NIKTO_DEFAULT_ARGS,
            "enable_dangerous_commands": self.ENABLE_DANGEROUS_COMMANDS,
            "allowed_ips_count": len(self.ALLOWED_IPS),
            "api_key_configured": bool(self.API_KEY)
        }
    
    def validate_config(self) -> List[str]:
        """验证配置的有效性，返回警告列表"""
        warnings = []
        
        # 检查端口范围
        if not (1 <= self.API_PORT <= 65535):
            warnings.append(f"API端口 {self.API_PORT} 不在有效范围内 (1-65535)")
        
        # 检查超时设置
        if self.COMMAND_TIMEOUT < 10:
            warnings.append(f"命令超时时间 {self.COMMAND_TIMEOUT} 秒可能过短")
        elif self.COMMAND_TIMEOUT > 600:
            warnings.append(f"命令超时时间 {self.COMMAND_TIMEOUT} 秒可能过长")
        
        # 检查缓存设置
        if self.MAX_CVE_CACHE_DAYS < 1:
            warnings.append("CVE缓存天数不能小于1天")
        
        # 检查目录权限
        if not os.access(self.CACHE_DIR, os.W_OK):
            warnings.append(f"缓存目录 {self.CACHE_DIR} 不可写")
        
        if not os.access(self.REPORTS_DIR, os.W_OK):
            warnings.append(f"报告目录 {self.REPORTS_DIR} 不可写")
        
        # 安全检查
        if self.DEBUG_MODE:
            warnings.append("调试模式已启用，生产环境请关闭")
        
        if not self.API_KEY:
            warnings.append("未设置API密钥，建议在生产环境中配置")
        
        if self.ENABLE_DANGEROUS_COMMANDS:
            warnings.append("危险命令执行已启用，请谨慎使用")
        
        return warnings
    
    def update_from_args(self, args):
        """从命令行参数更新配置"""
        if hasattr(args, 'debug') and args.debug:
            self.DEBUG_MODE = True
            os.environ["DEBUG_MODE"] = "1"
            # 重新设置日志级别
            logging.getLogger().setLevel(logging.DEBUG)
        
        if hasattr(args, 'port') and args.port != self.API_PORT:
            self.API_PORT = args.port
            self.logger.info(f"从命令行参数更新API端口: {self.API_PORT}")


# 全局配置实例
config = Config()

# 为了向后兼容，导出常用配置变量
API_PORT = config.API_PORT
DEBUG_MODE = config.DEBUG_MODE
COMMAND_TIMEOUT = config.COMMAND_TIMEOUT
MAX_SCAN_HISTORY = config.MAX_SCAN_HISTORY
MAX_CVE_CACHE_DAYS = config.MAX_CVE_CACHE_DAYS
API_KEY = config.API_KEY
ALLOWED_IPS = config.ALLOWED_IPS
ENABLE_DANGEROUS_COMMANDS = config.ENABLE_DANGEROUS_COMMANDS
CACHE_DIR = config.CACHE_DIR
REPORTS_DIR = config.REPORTS_DIR
NVD_API_URL = config.NVD_API_URL
NVD_REQUEST_TIMEOUT = config.NVD_REQUEST_TIMEOUT
NMAP_DEFAULT_ARGS = config.NMAP_DEFAULT_ARGS
GOBUSTER_DEFAULT_WORDLIST = config.GOBUSTER_DEFAULT_WORDLIST
NIKTO_DEFAULT_ARGS = config.NIKTO_DEFAULT_ARGS
NIKTO_DEFAULT_PLUGINS = config.NIKTO_DEFAULT_PLUGINS
JOHN_DEFAULT_WORDLIST = config.JOHN_DEFAULT_WORDLIST
URLFINDER_DEFAULT_DEPTH = config.URLFINDER_DEFAULT_DEPTH
SQLMAP_DEFAULT_LEVEL = config.SQLMAP_DEFAULT_LEVEL
SQLMAP_DEFAULT_RISK = config.SQLMAP_DEFAULT_RISK
WPSCAN_API_TOKEN = config.WPSCAN_API_TOKEN
HYDRA_DEFAULT_USERLIST = config.HYDRA_DEFAULT_USERLIST
HYDRA_DEFAULT_PASSLIST = config.HYDRA_DEFAULT_PASSLIST

# 导出logger
logger = config.logger

def get_config() -> Config:
    """获取配置实例"""
    return config

def load_configuration() -> Config:
    """加载配置（别名函数）"""
    return config

def validate_configuration() -> List[str]:
    """验证当前配置"""
    return config.validate_config()

if __name__ == "__main__":
    # 配置模块测试
    print("=== 配置管理模块测试 ===")
    print(f"API端口: {config.API_PORT}")
    print(f"调试模式: {config.DEBUG_MODE}")
    print(f"命令超时: {config.COMMAND_TIMEOUT}秒")
    print(f"缓存目录: {config.CACHE_DIR}")
    print(f"报告目录: {config.REPORTS_DIR}")
    
    # 验证配置
    warnings = config.validate_config()
    if warnings:
        print("\n配置警告:")
        for warning in warnings:
            print(f"  - {warning}")
    else:
        print("\n配置验证通过")
    
    print("\n完整配置:")
    import json
    print(json.dumps(config.get_config_dict(), indent=2, ensure_ascii=False))