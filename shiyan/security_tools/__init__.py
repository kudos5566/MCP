#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
安全工具包装器模块

提供统一的安全工具接口，每个工具都有独立的包装器
支持标准化的参数处理、结果解析和错误处理

主要工具包装器:
- NmapWrapper: Nmap网络扫描工具
- GobusterWrapper: Gobuster目录扫描工具
- NiktoWrapper: Nikto Web漏洞扫描工具
- URLFinderWrapper: URLFinder URL发现工具
- SQLMapWrapper: SQLMap SQL注入检测工具
- WPScanWrapper: WPScan WordPress扫描工具
- HydraWrapper: Hydra暴力破解工具
- JohnWrapper: John the Ripper密码破解工具
"""

from .nmap_wrapper import NmapWrapper
from .gobuster_wrapper import GobusterWrapper
from .nikto_wrapper import NiktoWrapper
from .urlfinder_wrapper import URLFinderWrapper
from .sqlmap_wrapper import SQLMapWrapper
from .wpscan_wrapper import WPScanWrapper
from .hydra_wrapper import HydraWrapper
from .john_wrapper import JohnWrapper

__version__ = "1.0.0"
__author__ = "Kali Security Tools Team"
__description__ = "安全工具包装器模块集合"

# 所有可用的工具包装器
AVAILABLE_TOOLS = {
    'nmap': NmapWrapper,
    'gobuster': GobusterWrapper,
    'nikto': NiktoWrapper,
    'urlfinder': URLFinderWrapper,
    'sqlmap': SQLMapWrapper,
    'wpscan': WPScanWrapper,
    'hydra': HydraWrapper,
    'john': JohnWrapper
}


def get_tool_wrapper(tool_name: str):
    """
    获取指定工具的包装器类
    
    Args:
        tool_name: 工具名称
        
    Returns:
        对应的工具包装器类，如果不存在则返回None
    """
    return AVAILABLE_TOOLS.get(tool_name.lower())


def list_available_tools():
    """
    列出所有可用的工具
    
    Returns:
        可用工具名称列表
    """
    return list(AVAILABLE_TOOLS.keys())


def create_tool_instance(tool_name: str, **kwargs):
    """
    创建工具实例
    
    Args:
        tool_name: 工具名称
        **kwargs: 传递给工具构造函数的参数
        
    Returns:
        工具实例，如果工具不存在则返回None
    """
    wrapper_class = get_tool_wrapper(tool_name)
    if wrapper_class:
        return wrapper_class(**kwargs)
    return None


__all__ = [
    'NmapWrapper',
    'GobusterWrapper', 
    'NiktoWrapper',
    'URLFinderWrapper',
    'SQLMapWrapper',
    'WPScanWrapper',
    'HydraWrapper',
    'JohnWrapper',
    'AVAILABLE_TOOLS',
    'get_tool_wrapper',
    'list_available_tools',
    'create_tool_instance'
]