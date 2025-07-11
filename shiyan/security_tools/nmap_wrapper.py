#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nmap工具包装器

提供Nmap网络扫描工具的专门封装
支持多种扫描类型、端口范围、目标格式等
包含结果解析和CVE信息提取功能
"""

import re
import socket
from typing import Dict, Any, List

from .base_wrapper import BaseToolWrapper
from config import config
from cve_lookup import get_cve_details


class NmapWrapper(BaseToolWrapper):
    """
    Nmap网络扫描工具包装器
    
    支持多种扫描类型和参数配置
    自动解析扫描结果并提取服务信息
    """
    
    def __init__(self):
        super().__init__('nmap')
        self.default_args = config.NMAP_DEFAULT_ARGS
    
    def validate_params(self, **kwargs) -> Dict[str, Any]:
        """
        验证Nmap参数
        
        Args:
            target: 扫描目标（必需）
            scan_type: 扫描类型（可选，默认-sV）
            ports: 端口范围（可选）
            additional_args: 附加参数（可选）
            
        Returns:
            验证结果
        """
        target = kwargs.get('target', '')
        scan_type = kwargs.get('scan_type', '-sV')
        ports = kwargs.get('ports', '')
        
        # 验证目标
        if not target:
            return {'success': False, 'error': 'target参数是必需的'}
        
        # 验证目标格式（IP、域名或CIDR）
        target_clean = target.split('/')[0]  # 处理CIDR格式
        if not (self.validate_ip_address(target_clean) or self.validate_domain(target_clean)):
            return {'success': False, 'error': '无效的目标地址格式'}
        
        # 验证端口范围
        if ports and not self.validate_port_range(ports):
            return {'success': False, 'error': '无效的端口范围格式'}
        
        # 验证扫描类型
        valid_scan_types = ['-sS', '-sT', '-sU', '-sV', '-sC', '-sA', '-sF', '-sN', '-sX']
        if scan_type and not any(st in scan_type for st in valid_scan_types):
            self.logger.warning(f"未知的扫描类型: {scan_type}")
        
        return {'success': True}
    
    def build_command(self, **kwargs) -> str:
        """
        构建Nmap命令
        
        Args:
            **kwargs: Nmap参数
            
        Returns:
            完整的Nmap命令
        """
        target = kwargs.get('target', '')
        scan_type = kwargs.get('scan_type', '-sV')
        ports = kwargs.get('ports', '')
        additional_args = kwargs.get('additional_args', self.default_args)
        
        # 构建基础命令
        command_parts = ['nmap']
        
        # 添加扫描类型
        if scan_type:
            command_parts.append(scan_type)
        
        # 添加端口范围
        if ports:
            command_parts.extend(['-p', ports])
        
        # 添加附加参数
        if additional_args:
            command_parts.append(additional_args)
        
        # 添加目标
        command_parts.append(target)
        
        return ' '.join(command_parts)
    
    def parse_output(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """
        解析Nmap输出
        
        Args:
            stdout: Nmap标准输出
            stderr: Nmap错误输出
            
        Returns:
            解析后的结果
        """
        result = super().parse_output(stdout, stderr)
        
        # 解析主机信息
        hosts = self._parse_hosts(stdout)
        
        # 解析端口信息
        ports = self._parse_ports(stdout)
        
        # 解析服务信息
        services = self._parse_services(stdout)
        
        # 提取CVE信息
        cves = self._extract_cves(stdout)
        
        # 统计信息
        stats = self._parse_scan_stats(stdout)
        
        result.update({
            'hosts': hosts,
            'ports': ports,
            'services': services,
            'cves': cves,
            'scan_stats': stats,
            'summary': self._generate_summary(hosts, ports, services, cves)
        })
        
        return result
    
    def _parse_hosts(self, output: str) -> List[Dict[str, Any]]:
        """
        解析主机信息
        
        Args:
            output: Nmap输出
            
        Returns:
            主机信息列表
        """
        hosts = []
        
        # 匹配主机状态行
        host_pattern = r'Nmap scan report for ([^\n]+)'
        status_pattern = r'Host is (up|down)'
        
        host_matches = re.finditer(host_pattern, output)
        
        for match in host_matches:
            host_info = match.group(1).strip()
            
            # 提取IP和主机名
            if '(' in host_info and ')' in host_info:
                hostname = host_info.split('(')[0].strip()
                ip = host_info.split('(')[1].split(')')[0].strip()
            else:
                hostname = ''
                ip = host_info
            
            # 查找状态信息
            status_match = re.search(status_pattern, output[match.end():])
            status = status_match.group(1) if status_match else 'unknown'
            
            hosts.append({
                'ip': ip,
                'hostname': hostname,
                'status': status
            })
        
        return hosts
    
    def _parse_ports(self, output: str) -> List[Dict[str, Any]]:
        """
        解析端口信息
        
        Args:
            output: Nmap输出
            
        Returns:
            端口信息列表
        """
        ports = []
        
        # 匹配端口行
        port_pattern = r'(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+([^\n]*?)(?:\s+(.*))?$'
        
        for match in re.finditer(port_pattern, output, re.MULTILINE):
            port_num = int(match.group(1))
            protocol = match.group(2)
            state = match.group(3)
            service = match.group(4).strip() if match.group(4) else ''
            version = match.group(5).strip() if match.group(5) else ''
            
            ports.append({
                'port': port_num,
                'protocol': protocol,
                'state': state,
                'service': service,
                'version': version
            })
        
        return ports
    
    def _parse_services(self, output: str) -> List[Dict[str, Any]]:
        """
        解析服务信息
        
        Args:
            output: Nmap输出
            
        Returns:
            服务信息列表
        """
        services = []
        
        # 匹配服务版本信息
        service_pattern = r'(\d+)/(tcp|udp)\s+open\s+([^\s]+)\s+(.+)'
        
        for match in re.finditer(service_pattern, output):
            port = int(match.group(1))
            protocol = match.group(2)
            service_name = match.group(3)
            version_info = match.group(4).strip()
            
            services.append({
                'port': port,
                'protocol': protocol,
                'service': service_name,
                'version': version_info,
                'banner': version_info
            })
        
        return services
    
    def _extract_cves(self, output: str) -> List[Dict[str, Any]]:
        """
        提取CVE信息
        
        Args:
            output: Nmap输出
            
        Returns:
            CVE信息列表
        """
        cves = []
        
        # 匹配CVE编号
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        cve_matches = re.findall(cve_pattern, output)
        
        for cve_id in set(cve_matches):  # 去重
            try:
                cve_details = get_cve_details(cve_id)
                if cve_details:
                    cves.append({
                        'cve_id': cve_id,
                        'details': cve_details
                    })
            except Exception as e:
                self.logger.warning(f"获取CVE详情失败 {cve_id}: {str(e)}")
                cves.append({
                    'cve_id': cve_id,
                    'details': None,
                    'error': str(e)
                })
        
        return cves
    
    def _parse_scan_stats(self, output: str) -> Dict[str, Any]:
        """
        解析扫描统计信息
        
        Args:
            output: Nmap输出
            
        Returns:
            统计信息
        """
        stats = {}
        
        # 匹配扫描时间
        time_pattern = r'Nmap done: .* in ([\d.]+) seconds'
        time_match = re.search(time_pattern, output)
        if time_match:
            stats['scan_time'] = float(time_match.group(1))
        
        # 匹配主机数量
        hosts_pattern = r'(\d+) hosts? up'
        hosts_match = re.search(hosts_pattern, output)
        if hosts_match:
            stats['hosts_up'] = int(hosts_match.group(1))
        
        # 匹配端口数量
        ports_scanned = len(re.findall(r'\d+/(tcp|udp)', output))
        stats['ports_scanned'] = ports_scanned
        
        return stats
    
    def _generate_summary(self, hosts: List[Dict], ports: List[Dict], 
                         services: List[Dict], cves: List[Dict]) -> str:
        """
        生成扫描摘要
        
        Args:
            hosts: 主机列表
            ports: 端口列表
            services: 服务列表
            cves: CVE列表
            
        Returns:
            扫描摘要字符串
        """
        summary_parts = []
        
        # 主机摘要
        active_hosts = [h for h in hosts if h.get('status') == 'up']
        summary_parts.append(f"发现 {len(active_hosts)} 个活跃主机")
        
        # 端口摘要
        open_ports = [p for p in ports if p.get('state') == 'open']
        summary_parts.append(f"发现 {len(open_ports)} 个开放端口")
        
        # 服务摘要
        if services:
            summary_parts.append(f"识别 {len(services)} 个服务")
        
        # CVE摘要
        if cves:
            summary_parts.append(f"发现 {len(cves)} 个潜在漏洞")
        
        return '，'.join(summary_parts)
    
    def scan_host(self, target: str, scan_type: str = '-sV', 
                  ports: str = '', **kwargs) -> Dict[str, Any]:
        """
        扫描单个主机的便捷方法
        
        Args:
            target: 目标主机
            scan_type: 扫描类型
            ports: 端口范围
            **kwargs: 其他参数
            
        Returns:
            扫描结果
        """
        return self.execute(
            target=target,
            scan_type=scan_type,
            ports=ports,
            **kwargs
        )
    
    def quick_scan(self, target: str) -> Dict[str, Any]:
        """
        快速扫描
        
        Args:
            target: 目标主机
            
        Returns:
            扫描结果
        """
        return self.execute(
            target=target,
            scan_type='-sS',
            additional_args='-T4 -F'
        )
    
    def service_scan(self, target: str, ports: str = '') -> Dict[str, Any]:
        """
        服务版本扫描
        
        Args:
            target: 目标主机
            ports: 端口范围
            
        Returns:
            扫描结果
        """
        return self.execute(
            target=target,
            scan_type='-sV',
            ports=ports,
            additional_args='-T4'
        )
    
    def vulnerability_scan(self, target: str, ports: str = '') -> Dict[str, Any]:
        """
        漏洞扫描
        
        Args:
            target: 目标主机
            ports: 端口范围
            
        Returns:
            扫描结果
        """
        return self.execute(
            target=target,
            scan_type='-sV -sC',
            ports=ports,
            additional_args='--script vuln'
        )