#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Gobuster工具包装器

提供Gobuster目录和文件扫描工具的专门封装
支持多种扫描模式、字典文件、扩展名等
包含结果解析和发现项统计功能
"""

import re
import os
from typing import Dict, Any, List

from .base_wrapper import BaseToolWrapper
from config import config


class GobusterWrapper(BaseToolWrapper):
    """
    Gobuster目录和文件扫描工具包装器
    
    支持目录扫描、DNS子域名扫描、虚拟主机扫描等模式
    自动解析扫描结果并统计发现项
    """
    
    def __init__(self):
        super().__init__('gobuster')
        self.default_wordlist = config.GOBUSTER_DEFAULT_WORDLIST
    
    def validate_params(self, **kwargs) -> Dict[str, Any]:
        """
        验证Gobuster参数
        
        Args:
            url: 目标URL（dir模式必需）
            domain: 目标域名（dns模式必需）
            mode: 扫描模式（dir/dns/vhost）
            wordlist: 字典文件路径
            extensions: 文件扩展名
            threads: 线程数
            
        Returns:
            验证结果
        """
        mode = kwargs.get('mode', 'dir')
        url = kwargs.get('url', '')
        domain = kwargs.get('domain', '')
        wordlist = kwargs.get('wordlist', self.default_wordlist)
        threads = kwargs.get('threads', 10)
        
        # 验证模式
        valid_modes = ['dir', 'dns', 'vhost']
        if mode not in valid_modes:
            return {'success': False, 'error': f'无效的扫描模式，支持: {", ".join(valid_modes)}'}
        
        # 根据模式验证必需参数
        if mode in ['dir', 'vhost']:
            if not url:
                return {'success': False, 'error': f'{mode}模式需要url参数'}
            if not self.validate_url(url):
                return {'success': False, 'error': '无效的URL格式'}
        
        if mode == 'dns':
            if not domain:
                return {'success': False, 'error': 'dns模式需要domain参数'}
            if not self.validate_domain(domain):
                return {'success': False, 'error': '无效的域名格式'}
        
        # 验证字典文件
        if wordlist and not os.path.isfile(wordlist):
            self.logger.warning(f"字典文件不存在: {wordlist}")
        
        # 验证线程数
        try:
            threads = int(threads)
            if not (1 <= threads <= 100):
                return {'success': False, 'error': '线程数必须在1-100之间'}
        except ValueError:
            return {'success': False, 'error': '线程数必须是数字'}
        
        return {'success': True}
    
    def build_command(self, **kwargs) -> str:
        """
        构建Gobuster命令
        
        Args:
            **kwargs: Gobuster参数
            
        Returns:
            完整的Gobuster命令
        """
        mode = kwargs.get('mode', 'dir')
        url = kwargs.get('url', '')
        domain = kwargs.get('domain', '')
        wordlist = kwargs.get('wordlist', self.default_wordlist)
        extensions = kwargs.get('extensions', '')
        threads = kwargs.get('threads', 10)
        additional_args = kwargs.get('additional_args', '')
        
        # 构建基础命令
        command_parts = ['gobuster', mode]
        
        # 添加目标
        if mode in ['dir', 'vhost']:
            command_parts.extend(['-u', url])
        elif mode == 'dns':
            command_parts.extend(['-d', domain])
        
        # 添加字典文件
        if wordlist:
            command_parts.extend(['-w', wordlist])
        
        # 添加扩展名
        if extensions and mode == 'dir':
            command_parts.extend(['-x', extensions])
        
        # 添加线程数
        command_parts.extend(['-t', str(threads)])
        
        # 添加状态码排除（排除301重定向）
        if mode == 'dir':
            command_parts.extend(['-b', '301,302'])
        
        # 添加附加参数
        if additional_args:
            command_parts.append(additional_args)
        
        return ' '.join(command_parts)
    
    def parse_output(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """
        解析Gobuster输出
        
        Args:
            stdout: Gobuster标准输出
            stderr: Gobuster错误输出
            
        Returns:
            解析后的结果
        """
        result = super().parse_output(stdout, stderr)
        
        # 解析发现项
        discoveries = self._parse_discoveries(stdout)
        
        # 按状态码分类
        status_summary = self._categorize_by_status(discoveries)
        
        # 解析扫描统计
        stats = self._parse_scan_stats(stdout, stderr)
        
        result.update({
            'discoveries': discoveries,
            'status_summary': status_summary,
            'scan_stats': stats,
            'summary': self._generate_summary(discoveries, stats)
        })
        
        return result
    
    def _parse_discoveries(self, output: str) -> List[Dict[str, Any]]:
        """
        解析发现项
        
        Args:
            output: Gobuster输出
            
        Returns:
            发现项列表
        """
        discoveries = []
        
        # 匹配目录/文件发现项
        # 格式: /admin (Status: 200) [Size: 1234]
        dir_pattern = r'(/[^\s]*?)\s+\(Status:\s+(\d+)\)(?:\s+\[Size:\s+(\d+)\])?'
        
        for match in re.finditer(dir_pattern, output):
            path = match.group(1)
            status_code = int(match.group(2))
            size = int(match.group(3)) if match.group(3) else None
            
            discoveries.append({
                'path': path,
                'status_code': status_code,
                'size': size,
                'type': 'directory' if path.endswith('/') else 'file'
            })
        
        # 匹配DNS子域名发现项
        # 格式: Found: admin.example.com
        dns_pattern = r'Found:\s+([^\s]+)'
        
        for match in re.finditer(dns_pattern, output):
            subdomain = match.group(1)
            
            discoveries.append({
                'subdomain': subdomain,
                'type': 'subdomain'
            })
        
        # 匹配虚拟主机发现项
        # 格式: Found: admin.example.com (Status: 200) [Size: 1234]
        vhost_pattern = r'Found:\s+([^\s]+)\s+\(Status:\s+(\d+)\)(?:\s+\[Size:\s+(\d+)\])?'
        
        for match in re.finditer(vhost_pattern, output):
            vhost = match.group(1)
            status_code = int(match.group(2))
            size = int(match.group(3)) if match.group(3) else None
            
            discoveries.append({
                'vhost': vhost,
                'status_code': status_code,
                'size': size,
                'type': 'vhost'
            })
        
        return discoveries
    
    def _categorize_by_status(self, discoveries: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        按状态码分类发现项
        
        Args:
            discoveries: 发现项列表
            
        Returns:
            状态码统计
        """
        status_summary = {}
        
        for discovery in discoveries:
            status_code = discovery.get('status_code')
            if status_code:
                status_summary[str(status_code)] = status_summary.get(str(status_code), 0) + 1
        
        return status_summary
    
    def _parse_scan_stats(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """
        解析扫描统计信息
        
        Args:
            stdout: 标准输出
            stderr: 错误输出
            
        Returns:
            统计信息
        """
        stats = {}
        
        # 从输出中提取统计信息
        output = stdout + stderr
        
        # 匹配进度信息
        progress_pattern = r'Progress:\s+(\d+)\s+/\s+(\d+)'
        progress_match = re.search(progress_pattern, output)
        if progress_match:
            stats['requests_made'] = int(progress_match.group(1))
            stats['total_requests'] = int(progress_match.group(2))
            stats['progress_percent'] = round((stats['requests_made'] / stats['total_requests']) * 100, 2)
        
        # 匹配错误信息
        error_count = len(re.findall(r'error|failed|timeout', output, re.IGNORECASE))
        stats['errors'] = error_count
        
        return stats
    
    def _generate_summary(self, discoveries: List[Dict], stats: Dict) -> str:
        """
        生成扫描摘要
        
        Args:
            discoveries: 发现项列表
            stats: 统计信息
            
        Returns:
            扫描摘要字符串
        """
        summary_parts = []
        
        # 发现项摘要
        total_discoveries = len(discoveries)
        summary_parts.append(f"发现 {total_discoveries} 个项目")
        
        # 按类型统计
        type_counts = {}
        for discovery in discoveries:
            item_type = discovery.get('type', 'unknown')
            type_counts[item_type] = type_counts.get(item_type, 0) + 1
        
        for item_type, count in type_counts.items():
            type_name = {
                'directory': '目录',
                'file': '文件',
                'subdomain': '子域名',
                'vhost': '虚拟主机'
            }.get(item_type, item_type)
            summary_parts.append(f"{count} 个{type_name}")
        
        # 状态码摘要
        status_200_count = sum(1 for d in discoveries if d.get('status_code') == 200)
        if status_200_count > 0:
            summary_parts.append(f"{status_200_count} 个可访问资源")
        
        return '，'.join(summary_parts)
    
    def scan_directory(self, url: str, wordlist: str = '', 
                      extensions: str = '', **kwargs) -> Dict[str, Any]:
        """
        目录扫描的便捷方法
        
        Args:
            url: 目标URL
            wordlist: 字典文件
            extensions: 文件扩展名
            **kwargs: 其他参数
            
        Returns:
            扫描结果
        """
        return self.execute(
            mode='dir',
            url=url,
            wordlist=wordlist or self.default_wordlist,
            extensions=extensions,
            **kwargs
        )
    
    def scan_dns(self, domain: str, wordlist: str = '', **kwargs) -> Dict[str, Any]:
        """
        DNS子域名扫描的便捷方法
        
        Args:
            domain: 目标域名
            wordlist: 字典文件
            **kwargs: 其他参数
            
        Returns:
            扫描结果
        """
        return self.execute(
            mode='dns',
            domain=domain,
            wordlist=wordlist or self.default_wordlist,
            **kwargs
        )
    
    def scan_vhost(self, url: str, wordlist: str = '', **kwargs) -> Dict[str, Any]:
        """
        虚拟主机扫描的便捷方法
        
        Args:
            url: 目标URL
            wordlist: 字典文件
            **kwargs: 其他参数
            
        Returns:
            扫描结果
        """
        return self.execute(
            mode='vhost',
            url=url,
            wordlist=wordlist or self.default_wordlist,
            **kwargs
        )
    
    def quick_dir_scan(self, url: str) -> Dict[str, Any]:
        """
        快速目录扫描
        
        Args:
            url: 目标URL
            
        Returns:
            扫描结果
        """
        return self.execute(
            mode='dir',
            url=url,
            wordlist=self.default_wordlist,
            extensions='php,html,txt,js',
            threads=20
        )