#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
版本管理模块

集中管理应用程序的版本信息、更新历史和构建信息
提供统一的版本查询接口和版本比较功能

主要功能:
- 版本信息管理
- 版本历史记录
- 构建信息追踪
- 版本比较和验证
- 更新日志管理
"""

import sys
import platform
import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from packaging import version


@dataclass
class VersionInfo:
    """版本信息数据类"""
    major: int
    minor: int
    patch: int
    pre_release: Optional[str] = None
    build_metadata: Optional[str] = None
    
    def __str__(self) -> str:
        """返回版本字符串"""
        version_str = f"{self.major}.{self.minor}.{self.patch}"
        if self.pre_release:
            version_str += f"-{self.pre_release}"
        if self.build_metadata:
            version_str += f"+{self.build_metadata}"
        return version_str
    
    def to_tuple(self) -> tuple:
        """返回版本元组，用于比较"""
        return (self.major, self.minor, self.patch)


class VersionManager:
    """版本管理器"""
    
    # 当前版本信息
    CURRENT_VERSION = VersionInfo(1, 2, 0)
    
    # 应用程序元信息
    APP_INFO = {
        "name": "Kali Security Tools Platform",
        "description": "Kali Linux安全工具集成平台",
        "author": "Kali Security Tools Team",
        "license": "MIT",
        "homepage": "https://github.com/kali-tools/security-platform",
        "build_date": "2024-01-15",
        "python_requires": ">=3.8"
    }
    
    # 版本历史记录
    VERSION_HISTORY = {
        "1.2.0": {
            "date": "2024-01-15",
            "type": "minor",
            "changes": [
                "增强异常处理和日志记录",
                "集中化配置管理",
                "改进内存管理和缓存机制",
                "添加系统监控和统计功能",
                "完善中文注释和文档",
                "优化超时处理逻辑",
                "添加版本管理功能",
                "实现模块化API路由架构",
                "创建安全工具包装器模块"
            ],
            "breaking_changes": [],
            "security_fixes": [
                "增强输入验证",
                "添加危险命令检查",
                "改进API安全性"
            ],
            "deprecations": [],
            "performance_improvements": [
                "优化内存使用",
                "改进扫描结果存储效率",
                "减少不必要的日志输出"
            ]
        },
        "1.1.0": {
            "date": "2024-01-10",
            "type": "minor",
            "changes": [
                "添加URLFinder集成",
                "Excel报告生成功能",
                "CVE查询功能",
                "改进错误处理"
            ],
            "breaking_changes": [],
            "security_fixes": [
                "修复命令注入漏洞"
            ],
            "deprecations": [],
            "performance_improvements": [
                "优化扫描速度"
            ]
        },
        "1.0.0": {
            "date": "2024-01-01",
            "type": "major",
            "changes": [
                "初始版本发布",
                "基本的Nmap、Gobuster、Nikto集成",
                "RESTful API接口",
                "MCP客户端支持",
                "基础扫描结果管理"
            ],
            "breaking_changes": [],
            "security_fixes": [],
            "deprecations": [],
            "performance_improvements": []
        }
    }
    
    @classmethod
    def get_version(cls) -> str:
        """获取当前版本字符串"""
        return str(cls.CURRENT_VERSION)
    
    @classmethod
    def get_version_info(cls) -> Dict[str, Any]:
        """获取详细的版本信息"""
        current_version_str = cls.get_version()
        current_history = cls.VERSION_HISTORY.get(current_version_str, {})
        
        return {
            "version": current_version_str,
            "version_info": {
                "major": cls.CURRENT_VERSION.major,
                "minor": cls.CURRENT_VERSION.minor,
                "patch": cls.CURRENT_VERSION.patch,
                "pre_release": cls.CURRENT_VERSION.pre_release,
                "build_metadata": cls.CURRENT_VERSION.build_metadata
            },
            "app_info": cls.APP_INFO.copy(),
            "build_info": {
                "python_version": sys.version,
                "python_implementation": platform.python_implementation(),
                "platform": platform.platform(),
                "architecture": platform.architecture()[0],
                "machine": platform.machine(),
                "processor": platform.processor(),
                "build_date": cls.APP_INFO["build_date"]
            },
            "current_changes": current_history.get("changes", []),
            "security_fixes": current_history.get("security_fixes", []),
            "breaking_changes": current_history.get("breaking_changes", []),
            "performance_improvements": current_history.get("performance_improvements", [])
        }
    
    @classmethod
    def get_version_history(cls, limit: Optional[int] = None) -> Dict[str, Any]:
        """获取版本历史记录"""
        history = cls.VERSION_HISTORY.copy()
        
        if limit:
            # 按版本号排序，取最新的几个版本
            sorted_versions = sorted(history.keys(), key=lambda v: version.parse(v), reverse=True)
            limited_versions = sorted_versions[:limit]
            history = {v: history[v] for v in limited_versions}
        
        return {
            "total_versions": len(cls.VERSION_HISTORY),
            "returned_versions": len(history),
            "history": history
        }
    
    @classmethod
    def compare_versions(cls, version1: str, version2: str) -> Dict[str, Any]:
        """比较两个版本"""
        try:
            v1 = version.parse(version1)
            v2 = version.parse(version2)
            
            return {
                "version1": version1,
                "version2": version2,
                "comparison": {
                    "equal": v1 == v2,
                    "version1_newer": v1 > v2,
                    "version2_newer": v1 < v2,
                    "compatible": v1.major == v2.major  # 主版本号相同认为兼容
                },
                "difference": {
                    "major": abs(v1.major - v2.major),
                    "minor": abs(v1.minor - v2.minor),
                    "micro": abs(v1.micro - v2.micro)
                }
            }
        except Exception as e:
            return {
                "error": f"版本比较失败: {str(e)}",
                "version1": version1,
                "version2": version2
            }
    
    @classmethod
    def is_compatible_version(cls, required_version: str) -> bool:
        """检查当前版本是否与要求的版本兼容"""
        try:
            current = version.parse(cls.get_version())
            required = version.parse(required_version)
            
            # 主版本号相同且当前版本不低于要求版本
            return current.major == required.major and current >= required
        except Exception:
            return False
    
    @classmethod
    def get_changelog(cls, from_version: Optional[str] = None, to_version: Optional[str] = None) -> Dict[str, Any]:
        """获取版本变更日志"""
        if to_version is None:
            to_version = cls.get_version()
        
        try:
            # 获取版本范围内的所有变更
            all_versions = sorted(cls.VERSION_HISTORY.keys(), key=lambda v: version.parse(v))
            
            if from_version:
                start_idx = all_versions.index(from_version) + 1
            else:
                start_idx = 0
            
            end_idx = all_versions.index(to_version) + 1
            
            changelog_versions = all_versions[start_idx:end_idx]
            
            changelog = {}
            for ver in changelog_versions:
                changelog[ver] = cls.VERSION_HISTORY[ver]
            
            return {
                "from_version": from_version,
                "to_version": to_version,
                "versions_included": len(changelog_versions),
                "changelog": changelog
            }
        except Exception as e:
            return {
                "error": f"获取变更日志失败: {str(e)}",
                "from_version": from_version,
                "to_version": to_version
            }
    
    @classmethod
    def get_system_info(cls) -> Dict[str, Any]:
        """获取系统信息"""
        return {
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "architecture": platform.architecture(),
                "platform": platform.platform()
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
                "executable": sys.executable
            },
            "application": cls.get_version_info()
        }


# 便捷函数
def get_version() -> str:
    """获取当前版本字符串"""
    return VersionManager.get_version()


def get_version_info() -> Dict[str, Any]:
    """获取详细版本信息"""
    return VersionManager.get_version_info()


def get_version_history(limit: Optional[int] = None) -> Dict[str, Any]:
    """获取版本历史"""
    return VersionManager.get_version_history(limit)


def compare_versions(version1: str, version2: str) -> Dict[str, Any]:
    """比较版本"""
    return VersionManager.compare_versions(version1, version2)


def is_compatible_version(required_version: str) -> bool:
    """检查版本兼容性"""
    return VersionManager.is_compatible_version(required_version)


def get_changelog(from_version: Optional[str] = None, to_version: Optional[str] = None) -> Dict[str, Any]:
    """获取变更日志"""
    return VersionManager.get_changelog(from_version, to_version)


def get_system_info() -> Dict[str, Any]:
    """获取系统信息"""
    return VersionManager.get_system_info()


# 导出的版本常量
__version__ = VersionManager.get_version()
__author__ = VersionManager.APP_INFO["author"]
__description__ = VersionManager.APP_INFO["description"]
__build_date__ = VersionManager.APP_INFO["build_date"]
__python_requires__ = VersionManager.APP_INFO["python_requires"]


if __name__ == "__main__":
    print("=== 版本管理模块测试 ===")
    
    # 测试版本信息
    print(f"\n1. 当前版本: {get_version()}")
    
    # 测试详细版本信息
    print("\n2. 详细版本信息:")
    info = get_version_info()
    print(f"   应用名称: {info['app_info']['name']}")
    print(f"   版本: {info['version']}")
    print(f"   构建日期: {info['build_info']['build_date']}")
    print(f"   Python版本: {info['build_info']['python_version'].split()[0]}")
    print(f"   平台: {info['build_info']['platform']}")
    
    # 测试版本历史
    print("\n3. 版本历史 (最近3个版本):")
    history = get_version_history(3)
    for ver, details in history['history'].items():
        print(f"   v{ver} ({details['date']}) - {details['type']} release")
        print(f"     主要变更: {len(details['changes'])} 项")
        if details['security_fixes']:
            print(f"     安全修复: {len(details['security_fixes'])} 项")
    
    # 测试版本比较
    print("\n4. 版本比较测试:")
    comparison = compare_versions("1.2.0", "1.1.0")
    print(f"   1.2.0 vs 1.1.0: 1.2.0更新 = {comparison['comparison']['version1_newer']}")
    
    # 测试兼容性检查
    print("\n5. 兼容性检查:")
    print(f"   与1.2.0兼容: {is_compatible_version('1.2.0')}")
    print(f"   与1.1.0兼容: {is_compatible_version('1.1.0')}")
    print(f"   与2.0.0兼容: {is_compatible_version('2.0.0')}")
    
    # 测试变更日志
    print("\n6. 变更日志 (从1.0.0到当前版本):")
    changelog = get_changelog("1.0.0")
    print(f"   包含版本数: {changelog['versions_included']}")
    
    print("\n=== 版本管理模块测试完成 ===")