#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
基础工具包装器

为所有安全工具提供统一的基础接口和通用功能
包含参数验证、命令构建、结果解析等通用逻辑
"""

import re
import socket
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

from config import logger
from command_executor import execute_command


class BaseToolWrapper(ABC):
    """
    安全工具包装器基类
    
    提供所有安全工具的通用接口和功能
    子类需要实现具体的工具逻辑
    """
    
    def __init__(self, tool_name: str):
        """
        初始化工具包装器
        
        Args:
            tool_name: 工具名称
        """
        self.tool_name = tool_name
        self.logger = logger
    
    @abstractmethod
    def build_command(self, **kwargs) -> str:
        """
        构建工具命令
        
        Args:
            **kwargs: 工具参数
            
        Returns:
            构建好的命令字符串
        """
        pass
    
    @abstractmethod
    def validate_params(self, **kwargs) -> Dict[str, Any]:
        """
        验证工具参数
        
        Args:
            **kwargs: 工具参数
            
        Returns:
            验证结果字典，包含success和error字段
        """
        pass
    
    def parse_output(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """
        解析工具输出
        
        Args:
            stdout: 标准输出
            stderr: 错误输出
            
        Returns:
            解析后的结果字典
        """
        # 默认实现，子类可以重写
        return {
            'raw_output': stdout,
            'error_output': stderr,
            'parsed_data': self._extract_basic_info(stdout)
        }
    
    def execute(self, **kwargs) -> Dict[str, Any]:
        """
        执行工具
        
        Args:
            **kwargs: 工具参数
            
        Returns:
            执行结果字典
        """
        try:
            # 参数验证
            validation_result = self.validate_params(**kwargs)
            if not validation_result.get('success', False):
                return {
                    'success': False,
                    'error': validation_result.get('error', '参数验证失败'),
                    'tool': self.tool_name
                }
            
            # 构建命令
            command = self.build_command(**kwargs)
            self.logger.info(f"执行{self.tool_name}命令: {command[:100]}...")
            
            # 执行命令
            result = execute_command(command)
            
            if result.get('success', False):
                # 解析输出
                parsed_result = self.parse_output(
                    result.get('stdout', ''),
                    result.get('stderr', '')
                )
                
                # 合并结果
                final_result = {
                    'success': True,
                    'tool': self.tool_name,
                    'command': command,
                    'return_code': result.get('return_code', 0),
                    'stdout': result.get('stdout', ''),
                    'stderr': result.get('stderr', ''),
                    **parsed_result
                }
                
                self.logger.info(f"{self.tool_name}执行成功")
                return final_result
            else:
                self.logger.warning(f"{self.tool_name}执行失败: {result.get('stderr', '')}")
                return {
                    'success': False,
                    'tool': self.tool_name,
                    'command': command,
                    'error': result.get('stderr', '执行失败'),
                    'return_code': result.get('return_code', -1),
                    'stdout': result.get('stdout', ''),
                    'stderr': result.get('stderr', '')
                }
                
        except Exception as e:
            self.logger.error(f"{self.tool_name}执行异常: {str(e)}", exc_info=True)
            return {
                'success': False,
                'tool': self.tool_name,
                'error': f"执行异常: {str(e)}"
            }
    
    def _extract_basic_info(self, output: str) -> Dict[str, Any]:
        """
        提取基础信息
        
        Args:
            output: 工具输出
            
        Returns:
            提取的基础信息
        """
        info = {
            'line_count': len(output.split('\n')) if output else 0,
            'char_count': len(output) if output else 0,
            'has_errors': 'error' in output.lower() or 'failed' in output.lower() if output else False
        }
        return info
    
    @staticmethod
    def validate_ip_address(ip: str) -> bool:
        """
        验证IP地址格式
        
        Args:
            ip: IP地址字符串
            
        Returns:
            是否为有效IP地址
        """
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
    
    @staticmethod
    def validate_domain(domain: str) -> bool:
        """
        验证域名格式
        
        Args:
            domain: 域名字符串
            
        Returns:
            是否为有效域名
        """
        try:
            socket.gethostbyname(domain)
            return True
        except socket.gaierror:
            return False
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """
        验证URL格式
        
        Args:
            url: URL字符串
            
        Returns:
            是否为有效URL
        """
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    @staticmethod
    def validate_port_range(ports: str) -> bool:
        """
        验证端口范围格式
        
        Args:
            ports: 端口范围字符串
            
        Returns:
            是否为有效端口范围
        """
        if not ports:
            return True
        
        # 支持格式: 80, 80-443, 80,443,8080, 1-65535
        port_pattern = r'^\d+(-\d+)?(,\d+(-\d+)?)*$'
        if not re.match(port_pattern, ports):
            return False
        
        # 检查端口范围是否在有效范围内
        for port_part in ports.split(','):
            if '-' in port_part:
                start, end = map(int, port_part.split('-'))
                if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
                    return False
            else:
                port = int(port_part)
                if not (1 <= port <= 65535):
                    return False
        
        return True
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """
        清理文件名，移除不安全字符
        
        Args:
            filename: 原始文件名
            
        Returns:
            清理后的安全文件名
        """
        # 移除或替换不安全字符
        unsafe_chars = r'[<>:"/\\|?*]'
        safe_filename = re.sub(unsafe_chars, '_', filename)
        
        # 限制长度
        if len(safe_filename) > 200:
            safe_filename = safe_filename[:200]
        
        return safe_filename
    
    def get_tool_info(self) -> Dict[str, Any]:
        """
        获取工具信息
        
        Returns:
            工具信息字典
        """
        return {
            'name': self.tool_name,
            'wrapper_class': self.__class__.__name__,
            'description': self.__doc__ or f'{self.tool_name} 安全工具包装器'
        }