#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nikto Web漏洞扫描工具包装器

提供Nikto Web应用安全扫描工具的专门封装
支持多种扫描选项、插件配置、输出格式等
包含漏洞解析和风险评估功能
"""

import re
import json
from typing import Dict, Any, List

from .base_wrapper import BaseToolWrapper
from config import config


class NiktoWrapper(BaseToolWrapper):
    """
    Nikto Web漏洞扫描工具包装器
    
    支持Web应用漏洞扫描、SSL检查、插件扫描等
    自动解析扫描结果并进行风险评估
    """
    
    def __init__(self):
        super().__init__('nikto')
        self.default_plugins = config.NIKTO_DEFAULT_PLUGINS
    
    def validate_params(self, **kwargs) -> Dict[str, Any]:
        """
        验证Nikto参数
        
        Args:
            host: 目标主机或URL
            port: 端口号
            ssl: 是否使用SSL
            plugins: 插件列表
            timeout: 超时时间
            user_agent: 用户代理
            
        Returns:
            验证结果
        """
        host = kwargs.get('host', '')
        port = kwargs.get('port', 80)
        timeout = kwargs.get('timeout', 10)
        
        # 验证主机
        if not host:
            return {'success': False, 'error': '需要指定目标主机或URL'}
        
        # 如果是URL，验证格式
        if host.startswith(('http://', 'https://')):
            if not self.validate_url(host):
                return {'success': False, 'error': '无效的URL格式'}
        else:
            # 如果是主机名或IP，验证格式
            if not (self.validate_ip_address(host) or self.validate_domain(host)):
                return {'success': False, 'error': '无效的主机格式'}
        
        # 验证端口
        try:
            port = int(port)
            if not (1 <= port <= 65535):
                return {'success': False, 'error': '端口号必须在1-65535之间'}
        except ValueError:
            return {'success': False, 'error': '端口号必须是数字'}
        
        # 验证超时时间
        try:
            timeout = int(timeout)
            if not (1 <= timeout <= 300):
                return {'success': False, 'error': '超时时间必须在1-300秒之间'}
        except ValueError:
            return {'success': False, 'error': '超时时间必须是数字'}
        
        return {'success': True}
    
    def build_command(self, **kwargs) -> str:
        """
        构建Nikto命令
        
        Args:
            **kwargs: Nikto参数
            
        Returns:
            完整的Nikto命令
        """
        host = kwargs.get('host', '')
        port = kwargs.get('port', 80)
        ssl = kwargs.get('ssl', False)
        plugins = kwargs.get('plugins', self.default_plugins)
        timeout = kwargs.get('timeout', 10)
        user_agent = kwargs.get('user_agent', '')
        additional_args = kwargs.get('additional_args', '')
        
        # 构建基础命令
        command_parts = ['nikto']
        
        # 添加主机
        if host.startswith(('http://', 'https://')):
            command_parts.extend(['-h', host])
        else:
            # 构建主机:端口格式
            if ssl:
                target = f"https://{host}:{port}"
            else:
                target = f"http://{host}:{port}"
            command_parts.extend(['-h', target])
        
        # 添加端口（如果不是标准端口）
        if not host.startswith(('http://', 'https://')):
            if (ssl and port != 443) or (not ssl and port != 80):
                command_parts.extend(['-p', str(port)])
        
        # 添加SSL选项
        if ssl and not host.startswith('https://'):
            command_parts.append('-ssl')
        
        # 添加插件
        if plugins:
            command_parts.extend(['-Plugins', plugins])
        
        # 添加超时时间
        command_parts.extend(['-timeout', str(timeout)])
        
        # 添加用户代理
        if user_agent:
            command_parts.extend(['-useragent', f'"{user_agent}"'])
        
        # 移除输出格式参数，使用默认输出到stdout
        # command_parts.extend(['-Format', 'txt'])  # 这会导致"Output file format specified without a name"错误
        
        # 添加附加参数
        if additional_args:
            command_parts.append(additional_args)
        
        return ' '.join(command_parts)
    
    def parse_output(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """
        解析Nikto输出
        
        Args:
            stdout: Nikto标准输出
            stderr: Nikto错误输出
            
        Returns:
            解析后的结果
        """
        result = super().parse_output(stdout, stderr)
        
        # 解析扫描信息
        scan_info = self._parse_scan_info(stdout)
        
        # 解析漏洞发现
        vulnerabilities = self._parse_vulnerabilities(stdout)
        
        # 风险评估
        risk_assessment = self._assess_risks(vulnerabilities)
        
        # 解析服务器信息
        server_info = self._parse_server_info(stdout)
        
        # 解析扫描统计
        stats = self._parse_scan_stats(stdout, stderr)
        
        result.update({
            'scan_info': scan_info,
            'server_info': server_info,
            'vulnerabilities': vulnerabilities,
            'risk_assessment': risk_assessment,
            'scan_stats': stats,
            'summary': self._generate_summary(vulnerabilities, risk_assessment)
        })
        
        return result
    
    def _parse_scan_info(self, output: str) -> Dict[str, Any]:
        """
        解析扫描基本信息
        
        Args:
            output: Nikto输出
            
        Returns:
            扫描信息
        """
        scan_info = {}
        
        # 匹配目标信息
        target_pattern = r'-\s+Target\s+IP:\s+([^\n]+)'
        target_match = re.search(target_pattern, output)
        if target_match:
            scan_info['target_ip'] = target_match.group(1).strip()
        
        # 匹配目标主机名
        hostname_pattern = r'-\s+Target\s+Hostname:\s+([^\n]+)'
        hostname_match = re.search(hostname_pattern, output)
        if hostname_match:
            scan_info['target_hostname'] = hostname_match.group(1).strip()
        
        # 匹配目标端口
        port_pattern = r'-\s+Target\s+Port:\s+(\d+)'
        port_match = re.search(port_pattern, output)
        if port_match:
            scan_info['target_port'] = int(port_match.group(1))
        
        # 匹配开始时间
        start_pattern = r'-\s+Start\s+Time:\s+([^\n]+)'
        start_match = re.search(start_pattern, output)
        if start_match:
            scan_info['start_time'] = start_match.group(1).strip()
        
        return scan_info
    
    def _parse_server_info(self, output: str) -> Dict[str, Any]:
        """
        解析服务器信息
        
        Args:
            output: Nikto输出
            
        Returns:
            服务器信息
        """
        server_info = {}
        
        # 匹配服务器软件
        server_pattern = r'\+\s+Server:\s+([^\n]+)'
        server_match = re.search(server_pattern, output)
        if server_match:
            server_info['server_software'] = server_match.group(1).strip()
        
        # 匹配X-Powered-By
        powered_pattern = r'\+\s+X-Powered-By:\s+([^\n]+)'
        powered_match = re.search(powered_pattern, output)
        if powered_match:
            server_info['powered_by'] = powered_match.group(1).strip()
        
        # 匹配Cookie信息
        cookie_pattern = r'\+\s+Cookie\s+([^:]+):\s+([^\n]+)'
        cookie_matches = re.findall(cookie_pattern, output)
        if cookie_matches:
            server_info['cookies'] = {name.strip(): value.strip() for name, value in cookie_matches}
        
        return server_info
    
    def _parse_vulnerabilities(self, output: str) -> List[Dict[str, Any]]:
        """
        解析漏洞发现
        
        Args:
            output: Nikto输出
            
        Returns:
            漏洞列表
        """
        vulnerabilities = []
        
        # 匹配漏洞项
        # 格式: + /admin/: Admin login page/section found.
        vuln_pattern = r'\+\s+([^:]+):\s+([^\n]+)'
        
        for match in re.finditer(vuln_pattern, output):
            path = match.group(1).strip()
            description = match.group(2).strip()
            
            # 跳过服务器信息行
            if any(keyword in description.lower() for keyword in ['server:', 'x-powered-by:', 'cookie']):
                continue
            
            # 评估风险级别
            risk_level = self._assess_vulnerability_risk(path, description)
            
            # 分类漏洞类型
            vuln_type = self._categorize_vulnerability(path, description)
            
            vulnerabilities.append({
                'path': path,
                'description': description,
                'risk_level': risk_level,
                'type': vuln_type
            })
        
        return vulnerabilities
    
    def _assess_vulnerability_risk(self, path: str, description: str) -> str:
        """
        评估漏洞风险级别
        
        Args:
            path: 路径
            description: 描述
            
        Returns:
            风险级别
        """
        description_lower = description.lower()
        path_lower = path.lower()
        
        # 高风险关键词
        high_risk_keywords = [
            'sql injection', 'xss', 'csrf', 'directory traversal',
            'file inclusion', 'command injection', 'authentication bypass',
            'privilege escalation', 'remote code execution'
        ]
        
        # 中风险关键词
        medium_risk_keywords = [
            'admin', 'login', 'password', 'config', 'backup',
            'debug', 'test', 'phpinfo', 'server-status'
        ]
        
        # 低风险关键词
        low_risk_keywords = [
            'information disclosure', 'banner', 'version',
            'robots.txt', 'sitemap'
        ]
        
        # 检查高风险
        if any(keyword in description_lower for keyword in high_risk_keywords):
            return 'High'
        
        # 检查中风险
        if any(keyword in description_lower or keyword in path_lower for keyword in medium_risk_keywords):
            return 'Medium'
        
        # 检查低风险
        if any(keyword in description_lower for keyword in low_risk_keywords):
            return 'Low'
        
        # 默认为信息级别
        return 'Info'
    
    def _categorize_vulnerability(self, path: str, description: str) -> str:
        """
        分类漏洞类型
        
        Args:
            path: 路径
            description: 描述
            
        Returns:
            漏洞类型
        """
        description_lower = description.lower()
        
        if 'admin' in description_lower or 'login' in description_lower:
            return 'Authentication'
        elif 'config' in description_lower or 'backup' in description_lower:
            return 'Information Disclosure'
        elif 'directory' in description_lower or 'file' in description_lower:
            return 'Directory Traversal'
        elif 'script' in description_lower or 'php' in description_lower:
            return 'Script Vulnerability'
        elif 'server' in description_lower or 'version' in description_lower:
            return 'Server Information'
        else:
            return 'Other'
    
    def _assess_risks(self, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """
        评估整体风险
        
        Args:
            vulnerabilities: 漏洞列表
            
        Returns:
            风险评估结果
        """
        risk_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        type_counts = {}
        
        for vuln in vulnerabilities:
            risk_level = vuln.get('risk_level', 'Info')
            vuln_type = vuln.get('type', 'Other')
            
            risk_counts[risk_level] += 1
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
        
        # 计算总体风险评分
        risk_score = (risk_counts['High'] * 10 + 
                     risk_counts['Medium'] * 5 + 
                     risk_counts['Low'] * 2 + 
                     risk_counts['Info'] * 1)
        
        # 确定总体风险级别
        if risk_score >= 50:
            overall_risk = 'Critical'
        elif risk_score >= 20:
            overall_risk = 'High'
        elif risk_score >= 10:
            overall_risk = 'Medium'
        elif risk_score > 0:
            overall_risk = 'Low'
        else:
            overall_risk = 'None'
        
        return {
            'overall_risk': overall_risk,
            'risk_score': risk_score,
            'risk_counts': risk_counts,
            'type_counts': type_counts
        }
    
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
        
        output = stdout + stderr
        
        # 匹配扫描时间
        time_pattern = r'(\d+)\s+host\(s\)\s+tested\s+in\s+([\d.]+)\s+seconds'
        time_match = re.search(time_pattern, output)
        if time_match:
            stats['hosts_tested'] = int(time_match.group(1))
            stats['scan_duration'] = float(time_match.group(2))
        
        # 匹配请求数
        requests_pattern = r'(\d+)\s+requests\s+made'
        requests_match = re.search(requests_pattern, output)
        if requests_match:
            stats['requests_made'] = int(requests_match.group(1))
        
        # 匹配错误数
        error_count = len(re.findall(r'error|failed|timeout', output, re.IGNORECASE))
        stats['errors'] = error_count
        
        return stats
    
    def _generate_summary(self, vulnerabilities: List[Dict], risk_assessment: Dict) -> str:
        """
        生成扫描摘要
        
        Args:
            vulnerabilities: 漏洞列表
            risk_assessment: 风险评估
            
        Returns:
            扫描摘要字符串
        """
        summary_parts = []
        
        total_vulns = len(vulnerabilities)
        overall_risk = risk_assessment.get('overall_risk', 'None')
        risk_counts = risk_assessment.get('risk_counts', {})
        
        summary_parts.append(f"发现 {total_vulns} 个安全问题")
        summary_parts.append(f"总体风险级别: {overall_risk}")
        
        # 风险分布
        if risk_counts.get('High', 0) > 0:
            summary_parts.append(f"{risk_counts['High']} 个高风险")
        if risk_counts.get('Medium', 0) > 0:
            summary_parts.append(f"{risk_counts['Medium']} 个中风险")
        if risk_counts.get('Low', 0) > 0:
            summary_parts.append(f"{risk_counts['Low']} 个低风险")
        
        return '，'.join(summary_parts)
    
    def scan_web_app(self, host: str, port: int = 80, ssl: bool = False, **kwargs) -> Dict[str, Any]:
        """
        Web应用扫描的便捷方法
        
        Args:
            host: 目标主机
            port: 端口号
            ssl: 是否使用SSL
            **kwargs: 其他参数
            
        Returns:
            扫描结果
        """
        return self.execute(
            host=host,
            port=port,
            ssl=ssl,
            plugins=self.default_plugins,
            **kwargs
        )
    
    def quick_scan(self, url: str) -> Dict[str, Any]:
        """
        快速扫描
        
        Args:
            url: 目标URL
            
        Returns:
            扫描结果
        """
        return self.execute(
            host=url,
            plugins='@@ALL',
            timeout=5
        )
    
    def comprehensive_scan(self, host: str, port: int = 80, ssl: bool = False) -> Dict[str, Any]:
        """
        全面扫描
        
        Args:
            host: 目标主机
            port: 端口号
            ssl: 是否使用SSL
            
        Returns:
            扫描结果
        """
        return self.execute(
            host=host,
            port=port,
            ssl=ssl,
            plugins='@@ALL',
            timeout=30
        )