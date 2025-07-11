#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
工具状态检查模块

提供安全工具安装状态检查、健康检查逻辑和系统信息收集功能
用于确保系统环境的完整性和工具的可用性

主要功能:
- 安全工具安装状态检查
- 系统健康检查
- 系统信息收集
- 工具版本检测
- 依赖项验证
"""

import os
import sys
import platform
import subprocess
import shutil
import datetime
import psutil
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path

from command_executor import execute_command, execute_safe_command
from config import logger, CACHE_DIR, REPORTS_DIR


@dataclass
class ToolInfo:
    """工具信息数据类"""
    name: str
    command: str
    version_flag: str = "--version"
    help_flag: str = "--help"
    required: bool = True
    description: str = ""
    package_name: Optional[str] = None
    install_command: Optional[str] = None


class ToolChecker:
    """工具状态检查器"""
    
    # 定义需要检查的安全工具
    SECURITY_TOOLS = {
        "nmap": ToolInfo(
            name="Nmap",
            command="nmap",
            version_flag="--version",
            description="网络发现和安全审计工具",
            package_name="nmap",
            install_command="apt-get install nmap"
        ),
        "gobuster": ToolInfo(
            name="Gobuster",
            command="gobuster",
            version_flag="version",
            description="目录/文件暴力破解工具",
            package_name="gobuster",
            install_command="apt-get install gobuster"
        ),
        "dirb": ToolInfo(
            name="Dirb",
            command="dirb",
            help_flag="",
            description="Web内容扫描器",
            package_name="dirb",
            install_command="apt-get install dirb"
        ),
        "nikto": ToolInfo(
            name="Nikto",
            command="nikto",
            version_flag="-Version",
            description="Web服务器扫描器",
            package_name="nikto",
            install_command="apt-get install nikto"
        ),
        "sqlmap": ToolInfo(
            name="SQLMap",
            command="sqlmap",
            version_flag="--version",
            description="SQL注入检测工具",
            package_name="sqlmap",
            install_command="apt-get install sqlmap"
        ),
        "hydra": ToolInfo(
            name="Hydra",
            command="hydra",
            version_flag="-V",
            description="网络登录破解工具",
            package_name="hydra",
            install_command="apt-get install hydra"
        ),
        "john": ToolInfo(
            name="John the Ripper",
            command="john",
            help_flag="--help",
            description="密码破解工具",
            package_name="john",
            install_command="apt-get install john"
        ),
        "wpscan": ToolInfo(
            name="WPScan",
            command="wpscan",
            version_flag="--version",
            description="WordPress安全扫描器",
            package_name="wpscan",
            install_command="gem install wpscan"
        ),
        "urlfinder": ToolInfo(
            name="URLFinder",
            command="URLFinder",
            help_flag="-h",
            description="URL发现工具",
            required=False
        )
    }
    
    # Python依赖包检查
    PYTHON_DEPENDENCIES = {
        "flask": "Web框架",
        "requests": "HTTP库",
        "openpyxl": "Excel文件处理",
        "psutil": "系统信息获取",
        "packaging": "版本管理"
    }
    
    @classmethod
    def check_tool_installation(cls, tool_name: str) -> Dict[str, Any]:
        """
        检查单个工具的安装状态
        
        Args:
            tool_name: 工具名称
            
        Returns:
            Dict: 包含工具状态信息的字典
        """
        if tool_name not in cls.SECURITY_TOOLS:
            return {
                "name": tool_name,
                "installed": False,
                "error": "未知工具"
            }
        
        tool_info = cls.SECURITY_TOOLS[tool_name]
        result = {
            "name": tool_info.name,
            "command": tool_info.command,
            "description": tool_info.description,
            "required": tool_info.required,
            "installed": False,
            "version": None,
            "path": None,
            "error": None
        }
        
        try:
            # 检查工具是否在PATH中
            tool_path = shutil.which(tool_info.command)
            if tool_path:
                result["path"] = tool_path
                result["installed"] = True
                
                # 尝试获取版本信息
                version_info = cls._get_tool_version(tool_info)
                if version_info:
                    result["version"] = version_info
                    
            else:
                result["error"] = "工具未找到或未安装"
                
        except Exception as e:
            result["error"] = f"检查工具时出错: {str(e)}"
            logger.warning(f"检查工具 {tool_name} 时出错: {str(e)}")
        
        return result
    
    @classmethod
    def _get_tool_version(cls, tool_info: ToolInfo) -> Optional[str]:
        """
        获取工具版本信息
        
        Args:
            tool_info: 工具信息对象
            
        Returns:
            Optional[str]: 版本信息字符串
        """
        try:
            # 尝试使用版本标志
            if tool_info.version_flag:
                if tool_info.name == "Gobuster":
                    # Gobuster的版本命令特殊处理
                    result = execute_safe_command(f"{tool_info.command} {tool_info.version_flag}")
                else:
                    result = execute_safe_command(f"{tool_info.command} {tool_info.version_flag}")
                
                if result.get("success"):
                    output = result.get("stdout", "") or result.get("stderr", "")
                    if output:
                        # 提取版本号
                        lines = output.strip().split('\n')
                        return lines[0] if lines else "版本信息获取成功"
            
            # 如果版本标志失败，尝试帮助标志
            if tool_info.help_flag:
                result = execute_safe_command(f"{tool_info.command} {tool_info.help_flag}")
                if result.get("success") or result.get("stderr"):
                    return "工具可用"
            
            return None
            
        except Exception as e:
            logger.debug(f"获取 {tool_info.name} 版本信息失败: {str(e)}")
            return None
    
    @classmethod
    def check_all_tools(cls) -> Dict[str, Any]:
        """
        检查所有安全工具的安装状态
        
        Returns:
            Dict: 包含所有工具状态的字典
        """
        logger.info("开始检查所有安全工具的安装状态")
        
        tools_status = {}
        required_tools_count = 0
        installed_required_tools = 0
        
        for tool_name in cls.SECURITY_TOOLS:
            tool_status = cls.check_tool_installation(tool_name)
            tools_status[tool_name] = tool_status
            
            if tool_status["required"]:
                required_tools_count += 1
                if tool_status["installed"]:
                    installed_required_tools += 1
        
        # 计算统计信息
        total_tools = len(cls.SECURITY_TOOLS)
        installed_tools = sum(1 for status in tools_status.values() if status["installed"])
        
        summary = {
            "total_tools": total_tools,
            "installed_tools": installed_tools,
            "required_tools": required_tools_count,
            "installed_required_tools": installed_required_tools,
            "installation_rate": round((installed_tools / total_tools) * 100, 2),
            "required_tools_rate": round((installed_required_tools / required_tools_count) * 100, 2) if required_tools_count > 0 else 100,
            "all_required_installed": installed_required_tools == required_tools_count
        }
        
        logger.info(f"工具检查完成: {installed_tools}/{total_tools} 已安装, 必需工具: {installed_required_tools}/{required_tools_count}")
        
        return {
            "summary": summary,
            "tools": tools_status,
            "timestamp": datetime.datetime.now().isoformat()
        }
    
    @classmethod
    def check_python_dependencies(cls) -> Dict[str, Any]:
        """
        检查Python依赖包状态
        
        Returns:
            Dict: Python依赖包状态信息
        """
        dependencies_status = {}
        installed_count = 0
        
        for package, description in cls.PYTHON_DEPENDENCIES.items():
            try:
                __import__(package)
                dependencies_status[package] = {
                    "installed": True,
                    "description": description,
                    "error": None
                }
                installed_count += 1
            except ImportError as e:
                dependencies_status[package] = {
                    "installed": False,
                    "description": description,
                    "error": str(e)
                }
        
        total_deps = len(cls.PYTHON_DEPENDENCIES)
        
        return {
            "summary": {
                "total_dependencies": total_deps,
                "installed_dependencies": installed_count,
                "installation_rate": round((installed_count / total_deps) * 100, 2),
                "all_installed": installed_count == total_deps
            },
            "dependencies": dependencies_status
        }
    
    @classmethod
    def get_system_info(cls) -> Dict[str, Any]:
        """
        获取系统信息
        
        Returns:
            Dict: 系统信息字典
        """
        try:
            # 基本系统信息
            system_info = {
                "platform": {
                    "system": platform.system(),
                    "release": platform.release(),
                    "version": platform.version(),
                    "machine": platform.machine(),
                    "processor": platform.processor(),
                    "architecture": platform.architecture(),
                    "platform": platform.platform(),
                    "node": platform.node()
                },
                "python": {
                    "version": sys.version,
                    "version_info": {
                        "major": sys.version_info.major,
                        "minor": sys.version_info.minor,
                        "micro": sys.version_info.micro,
                        "releaselevel": sys.version_info.releaselevel,
                        "serial": sys.version_info.serial
                    },
                    "implementation": platform.python_implementation(),
                    "compiler": platform.python_compiler(),
                    "executable": sys.executable,
                    "path": sys.path[:3]  # 只显示前3个路径
                }
            }
            
            # 尝试获取硬件信息（需要psutil）
            try:
                system_info["hardware"] = {
                    "cpu_count": psutil.cpu_count(),
                    "cpu_count_logical": psutil.cpu_count(logical=True),
                    "cpu_percent": psutil.cpu_percent(interval=1),
                    "memory": {
                        "total_gb": round(psutil.virtual_memory().total / 1024 / 1024 / 1024, 2),
                        "available_gb": round(psutil.virtual_memory().available / 1024 / 1024 / 1024, 2),
                        "used_gb": round(psutil.virtual_memory().used / 1024 / 1024 / 1024, 2),
                        "percent": psutil.virtual_memory().percent
                    },
                    "disk": {
                        "total_gb": round(psutil.disk_usage('/').total / 1024 / 1024 / 1024, 2) if platform.system() != 'Windows' else round(psutil.disk_usage('C:').total / 1024 / 1024 / 1024, 2),
                        "used_gb": round(psutil.disk_usage('/').used / 1024 / 1024 / 1024, 2) if platform.system() != 'Windows' else round(psutil.disk_usage('C:').used / 1024 / 1024 / 1024, 2),
                        "free_gb": round(psutil.disk_usage('/').free / 1024 / 1024 / 1024, 2) if platform.system() != 'Windows' else round(psutil.disk_usage('C:').free / 1024 / 1024 / 1024, 2),
                        "percent": psutil.disk_usage('/').percent if platform.system() != 'Windows' else psutil.disk_usage('C:').percent
                    }
                }
            except Exception as e:
                system_info["hardware"] = {"error": f"无法获取硬件信息: {str(e)}"}
            
            # 环境信息
            system_info["environment"] = {
                "user": os.getenv('USER') or os.getenv('USERNAME', 'unknown'),
                "home": os.path.expanduser('~'),
                "cwd": os.getcwd(),
                "path_separator": os.pathsep,
                "line_separator": os.linesep
            }
            
            return system_info
            
        except Exception as e:
            logger.error(f"获取系统信息失败: {str(e)}")
            return {"error": f"获取系统信息失败: {str(e)}"}
    
    @classmethod
    def check_directories(cls) -> Dict[str, Any]:
        """
        检查重要目录的状态
        
        Returns:
            Dict: 目录状态信息
        """
        directories = {
            "cache_dir": CACHE_DIR,
            "reports_dir": REPORTS_DIR,
            "current_dir": os.getcwd(),
            "temp_dir": "/tmp" if platform.system() != 'Windows' else os.getenv('TEMP', 'C:\\temp')
        }
        
        directory_status = {}
        
        for dir_name, dir_path in directories.items():
            try:
                status = {
                    "path": dir_path,
                    "exists": os.path.exists(dir_path),
                    "readable": False,
                    "writable": False,
                    "size_mb": 0,
                    "file_count": 0
                }
                
                if status["exists"]:
                    status["readable"] = os.access(dir_path, os.R_OK)
                    status["writable"] = os.access(dir_path, os.W_OK)
                    
                    # 计算目录大小和文件数量
                    try:
                        total_size = 0
                        file_count = 0
                        for dirpath, dirnames, filenames in os.walk(dir_path):
                            file_count += len(filenames)
                            for filename in filenames:
                                filepath = os.path.join(dirpath, filename)
                                try:
                                    total_size += os.path.getsize(filepath)
                                except (OSError, IOError):
                                    pass
                        
                        status["size_mb"] = round(total_size / 1024 / 1024, 2)
                        status["file_count"] = file_count
                    except Exception:
                        pass
                
                directory_status[dir_name] = status
                
            except Exception as e:
                directory_status[dir_name] = {
                    "path": dir_path,
                    "error": str(e)
                }
        
        return directory_status
    
    @classmethod
    def perform_health_check(cls) -> Dict[str, Any]:
        """
        执行完整的健康检查
        
        Returns:
            Dict: 完整的健康检查结果
        """
        logger.info("开始执行系统健康检查")
        
        health_check_result = {
            "timestamp": datetime.datetime.now().isoformat(),
            "overall_status": "unknown",
            "checks": {}
        }
        
        try:
            # 1. 工具安装检查
            tools_check = cls.check_all_tools()
            health_check_result["checks"]["tools"] = tools_check
            
            # 2. Python依赖检查
            deps_check = cls.check_python_dependencies()
            health_check_result["checks"]["dependencies"] = deps_check
            
            # 3. 系统信息收集
            system_info = cls.get_system_info()
            health_check_result["checks"]["system"] = system_info
            
            # 4. 目录状态检查
            dirs_check = cls.check_directories()
            health_check_result["checks"]["directories"] = dirs_check
            
            # 5. 计算总体健康状态
            issues = []
            warnings = []
            
            # 检查必需工具
            if not tools_check["summary"]["all_required_installed"]:
                issues.append(f"缺少必需的安全工具: {tools_check['summary']['required_tools_rate']:.1f}% 已安装")
            
            # 检查Python依赖
            if not deps_check["summary"]["all_installed"]:
                warnings.append(f"部分Python依赖未安装: {deps_check['summary']['installation_rate']:.1f}% 已安装")
            
            # 检查目录状态
            for dir_name, dir_info in dirs_check.items():
                if "error" in dir_info:
                    warnings.append(f"目录 {dir_name} 检查失败: {dir_info['error']}")
                elif not dir_info.get("exists"):
                    warnings.append(f"目录 {dir_name} 不存在")
                elif not dir_info.get("writable"):
                    warnings.append(f"目录 {dir_name} 不可写")
            
            # 确定总体状态
            if issues:
                health_check_result["overall_status"] = "critical"
                health_check_result["issues"] = issues
            elif warnings:
                health_check_result["overall_status"] = "warning"
                health_check_result["warnings"] = warnings
            else:
                health_check_result["overall_status"] = "healthy"
            
            # 添加摘要信息
            health_check_result["summary"] = {
                "tools_installed": f"{tools_check['summary']['installed_tools']}/{tools_check['summary']['total_tools']}",
                "required_tools_installed": f"{tools_check['summary']['installed_required_tools']}/{tools_check['summary']['required_tools']}",
                "dependencies_installed": f"{deps_check['summary']['installed_dependencies']}/{deps_check['summary']['total_dependencies']}",
                "system_platform": system_info.get("platform", {}).get("system", "unknown"),
                "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
                "issues_count": len(issues),
                "warnings_count": len(warnings)
            }
            
            logger.info(f"健康检查完成: 状态={health_check_result['overall_status']}, 问题={len(issues)}, 警告={len(warnings)}")
            
        except Exception as e:
            logger.error(f"健康检查过程中出错: {str(e)}")
            health_check_result["overall_status"] = "error"
            health_check_result["error"] = str(e)
        
        return health_check_result


# 便捷函数
def check_tool(tool_name: str) -> Dict[str, Any]:
    """检查单个工具状态"""
    return ToolChecker.check_tool_installation(tool_name)


def check_all_tools() -> Dict[str, Any]:
    """检查所有工具状态"""
    return ToolChecker.check_all_tools()


def get_system_info() -> Dict[str, Any]:
    """获取系统信息"""
    return ToolChecker.get_system_info()


def health_check() -> Dict[str, Any]:
    """执行健康检查"""
    return ToolChecker.perform_health_check()


if __name__ == "__main__":
    print("=== 工具状态检查模块测试 ===")
    
    # 测试单个工具检查
    print("\n1. 检查Nmap工具:")
    nmap_status = check_tool("nmap")
    print(f"   状态: {'已安装' if nmap_status['installed'] else '未安装'}")
    if nmap_status.get("version"):
        print(f"   版本: {nmap_status['version']}")
    
    # 测试所有工具检查
    print("\n2. 检查所有工具:")
    all_tools = check_all_tools()
    summary = all_tools["summary"]
    print(f"   总工具数: {summary['total_tools']}")
    print(f"   已安装: {summary['installed_tools']}")
    print(f"   必需工具: {summary['installed_required_tools']}/{summary['required_tools']}")
    print(f"   安装率: {summary['installation_rate']:.1f}%")
    
    # 测试系统信息
    print("\n3. 系统信息:")
    sys_info = get_system_info()
    platform_info = sys_info.get("platform", {})
    print(f"   系统: {platform_info.get('system', 'unknown')}")
    print(f"   版本: {platform_info.get('release', 'unknown')}")
    print(f"   架构: {platform_info.get('machine', 'unknown')}")
    
    # 测试健康检查
    print("\n4. 健康检查:")
    health = health_check()
    print(f"   总体状态: {health['overall_status']}")
    if "issues" in health:
        print(f"   问题数: {len(health['issues'])}")
    if "warnings" in health:
        print(f"   警告数: {len(health['warnings'])}")
    
    print("\n=== 工具状态检查模块测试完成 ===")