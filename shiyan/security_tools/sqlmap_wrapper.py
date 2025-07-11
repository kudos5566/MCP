#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SQLMap SQL注入检测工具包装器

提供SQLMap SQL注入检测工具的专门封装
支持多种注入技术、数据库类型、输出格式等
包含漏洞分析和风险评估功能
"""

import re
import json
from typing import Dict, Any, List

from .base_wrapper import BaseToolWrapper
from config import config


class SQLMapWrapper(BaseToolWrapper):
    """
    SQLMap SQL注入检测工具包装器
    
    支持URL、POST数据、Cookie等多种注入点检测
    自动识别数据库类型并执行相应的注入测试
    """
    
    def __init__(self):
        super().__init__('sqlmap')
        self.default_level = config.SQLMAP_DEFAULT_LEVEL
        self.default_risk = config.SQLMAP_DEFAULT_RISK
    
    def validate_params(self, **kwargs) -> Dict[str, Any]:
        """
        验证SQLMap参数
        
        Args:
            url: 目标URL
            data: POST数据
            cookie: Cookie数据
            level: 测试级别(1-5)
            risk: 风险级别(1-3)
            technique: 注入技术
            dbms: 数据库类型
            
        Returns:
            验证结果
        """
        url = kwargs.get('url', '')
        data = kwargs.get('data', '')
        cookie = kwargs.get('cookie', '')
        level = kwargs.get('level', self.default_level)
        risk = kwargs.get('risk', self.default_risk)
        
        # 验证目标（URL、POST数据或Cookie至少需要一个）
        if not any([url, data, cookie]):
            return {'success': False, 'error': '需要指定目标URL、POST数据或Cookie'}
        
        # 验证URL格式
        if url and not self.validate_url(url):
            return {'success': False, 'error': '无效的URL格式'}
        
        # 验证测试级别
        try:
            level = int(level)
            if not (1 <= level <= 5):
                return {'success': False, 'error': '测试级别必须在1-5之间'}
        except ValueError:
            return {'success': False, 'error': '测试级别必须是数字'}
        
        # 验证风险级别
        try:
            risk = int(risk)
            if not (1 <= risk <= 3):
                return {'success': False, 'error': '风险级别必须在1-3之间'}
        except ValueError:
            return {'success': False, 'error': '风险级别必须是数字'}
        
        return {'success': True}
    
    def build_command(self, **kwargs) -> str:
        """
        构建SQLMap命令
        
        Args:
            **kwargs: SQLMap参数
            
        Returns:
            完整的SQLMap命令
        """
        url = kwargs.get('url', '')
        data = kwargs.get('data', '')
        cookie = kwargs.get('cookie', '')
        headers = kwargs.get('headers', '')
        level = kwargs.get('level', self.default_level)
        risk = kwargs.get('risk', self.default_risk)
        technique = kwargs.get('technique', 'BEUSTQ')
        dbms = kwargs.get('dbms', '')
        threads = kwargs.get('threads', 1)
        timeout = kwargs.get('timeout', 30)
        batch = kwargs.get('batch', True)
        additional_args = kwargs.get('additional_args', '')
        
        # 构建基础命令
        command_parts = ['sqlmap']
        
        # 添加目标URL
        if url:
            command_parts.extend(['-u', f'"{url}"'])
        
        # 添加POST数据
        if data:
            command_parts.extend(['--data', f'"{data}"'])
        
        # 添加Cookie
        if cookie:
            command_parts.extend(['--cookie', f'"{cookie}"'])
        
        # 添加HTTP头
        if headers:
            command_parts.extend(['--headers', f'"{headers}"'])
        
        # 添加测试级别和风险级别
        command_parts.extend(['--level', str(level)])
        command_parts.extend(['--risk', str(risk)])
        
        # 添加注入技术
        if technique:
            command_parts.extend(['--technique', technique])
        
        # 添加数据库类型
        if dbms:
            command_parts.extend(['--dbms', dbms])
        
        # 添加线程数
        command_parts.extend(['--threads', str(threads)])
        
        # 添加超时时间
        command_parts.extend(['--timeout', str(timeout)])
        
        # 添加批处理模式
        if batch:
            command_parts.append('--batch')
        
        # 添加输出选项
        command_parts.extend(['--output-dir', '/tmp/sqlmap_output'])
        command_parts.append('--flush-session')
        
        # 添加附加参数
        if additional_args:
            command_parts.append(additional_args)
        
        return ' '.join(command_parts)
    
    def parse_output(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """
        解析SQLMap输出
        
        Args:
            stdout: SQLMap标准输出
            stderr: SQLMap错误输出
            
        Returns:
            解析后的结果
        """
        result = super().parse_output(stdout, stderr)
        
        # 解析注入点
        injection_points = self._parse_injection_points(stdout)
        
        # 解析数据库信息
        database_info = self._parse_database_info(stdout)
        
        # 解析漏洞详情
        vulnerabilities = self._parse_vulnerabilities(stdout)
        
        # 风险评估
        risk_assessment = self._assess_risks(injection_points, vulnerabilities)
        
        # 解析扫描统计
        stats = self._parse_scan_stats(stdout, stderr)
        
        result.update({
            'injection_points': injection_points,
            'database_info': database_info,
            'vulnerabilities': vulnerabilities,
            'risk_assessment': risk_assessment,
            'scan_stats': stats,
            'summary': self._generate_summary(injection_points, database_info, risk_assessment)
        })
        
        return result
    
    def _parse_injection_points(self, output: str) -> List[Dict[str, Any]]:
        """
        解析注入点
        
        Args:
            output: SQLMap输出
            
        Returns:
            注入点列表
        """
        injection_points = []
        
        # 匹配注入点信息
        # 格式: Parameter: id (GET)
        param_pattern = r'Parameter:\s+([^\s]+)\s+\(([^)]+)\)'
        
        # 匹配注入类型
        # 格式: Type: boolean-based blind
        type_pattern = r'Type:\s+([^\n]+)'
        
        # 匹配Payload
        payload_pattern = r'Payload:\s+([^\n]+)'
        
        # 查找所有注入点
        param_matches = list(re.finditer(param_pattern, output))
        
        for i, param_match in enumerate(param_matches):
            parameter = param_match.group(1)
            method = param_match.group(2)
            
            # 查找该注入点后的类型和Payload信息
            start_pos = param_match.end()
            next_param_pos = param_matches[i + 1].start() if i + 1 < len(param_matches) else len(output)
            section = output[start_pos:next_param_pos]
            
            # 提取注入类型
            injection_types = []
            for type_match in re.finditer(type_pattern, section):
                injection_types.append(type_match.group(1).strip())
            
            # 提取Payload
            payloads = []
            for payload_match in re.finditer(payload_pattern, section):
                payloads.append(payload_match.group(1).strip())
            
            injection_points.append({
                'parameter': parameter,
                'method': method,
                'injection_types': injection_types,
                'payloads': payloads,
                'vulnerable': len(injection_types) > 0
            })
        
        return injection_points
    
    def _parse_database_info(self, output: str) -> Dict[str, Any]:
        """
        解析数据库信息
        
        Args:
            output: SQLMap输出
            
        Returns:
            数据库信息
        """
        database_info = {}
        
        # 匹配数据库类型
        dbms_pattern = r'back-end\s+DBMS:\s+([^\n]+)'
        dbms_match = re.search(dbms_pattern, output)
        if dbms_match:
            database_info['dbms'] = dbms_match.group(1).strip()
        
        # 匹配数据库版本
        version_pattern = r'back-end\s+DBMS\s+version:\s+([^\n]+)'
        version_match = re.search(version_pattern, output)
        if version_match:
            database_info['version'] = version_match.group(1).strip()
        
        # 匹配操作系统
        os_pattern = r'web\s+server\s+operating\s+system:\s+([^\n]+)'
        os_match = re.search(os_pattern, output)
        if os_match:
            database_info['operating_system'] = os_match.group(1).strip()
        
        # 匹配Web服务器
        web_server_pattern = r'web\s+application\s+technology:\s+([^\n]+)'
        web_server_match = re.search(web_server_pattern, output)
        if web_server_match:
            database_info['web_technology'] = web_server_match.group(1).strip()
        
        # 匹配当前用户
        user_pattern = r'current\s+user:\s+\'([^\']*)\''
        user_match = re.search(user_pattern, output)
        if user_match:
            database_info['current_user'] = user_match.group(1)
        
        # 匹配当前数据库
        db_pattern = r'current\s+database:\s+\'([^\']*)\''
        db_match = re.search(db_pattern, output)
        if db_match:
            database_info['current_database'] = db_match.group(1)
        
        return database_info
    
    def _parse_vulnerabilities(self, output: str) -> List[Dict[str, Any]]:
        """
        解析漏洞详情
        
        Args:
            output: SQLMap输出
            
        Returns:
            漏洞列表
        """
        vulnerabilities = []
        
        # 检查是否存在SQL注入
        if 'is vulnerable' in output.lower():
            # 提取漏洞类型
            vuln_types = []
            
            # 常见的SQL注入类型
            injection_types = {
                'boolean-based blind': 'Boolean盲注',
                'time-based blind': '时间盲注',
                'error-based': '报错注入',
                'union query': 'Union注入',
                'stacked queries': '堆叠注入'
            }
            
            for eng_type, chn_type in injection_types.items():
                if eng_type in output.lower():
                    vuln_types.append(chn_type)
            
            if vuln_types:
                vulnerabilities.append({
                    'type': 'SQL注入',
                    'subtypes': vuln_types,
                    'severity': 'High',
                    'description': f"发现SQL注入漏洞，支持的注入类型: {', '.join(vuln_types)}"
                })
        
        # 检查权限提升可能性
        if any(keyword in output.lower() for keyword in ['dba privileges', 'file privileges']):
            vulnerabilities.append({
                'type': '权限提升',
                'severity': 'Critical',
                'description': '数据库用户具有DBA权限或文件操作权限，可能导致权限提升'
            })
        
        # 检查文件读写能力
        if 'file system access' in output.lower():
            vulnerabilities.append({
                'type': '文件系统访问',
                'severity': 'High',
                'description': '可通过SQL注入访问文件系统'
            })
        
        return vulnerabilities
    
    def _assess_risks(self, injection_points: List[Dict], vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """
        评估风险
        
        Args:
            injection_points: 注入点列表
            vulnerabilities: 漏洞列表
            
        Returns:
            风险评估结果
        """
        risk_score = 0
        risk_factors = []
        
        # 基于注入点数量评分
        vulnerable_points = sum(1 for point in injection_points if point.get('vulnerable', False))
        risk_score += vulnerable_points * 20
        
        if vulnerable_points > 0:
            risk_factors.append(f"{vulnerable_points}个SQL注入点")
        
        # 基于漏洞严重性评分
        severity_scores = {'Critical': 50, 'High': 30, 'Medium': 15, 'Low': 5}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low')
            risk_score += severity_scores.get(severity, 5)
            risk_factors.append(f"{vuln.get('type', '未知漏洞')}({severity})")
        
        # 确定总体风险级别
        if risk_score >= 100:
            overall_risk = 'Critical'
        elif risk_score >= 60:
            overall_risk = 'High'
        elif risk_score >= 30:
            overall_risk = 'Medium'
        elif risk_score > 0:
            overall_risk = 'Low'
        else:
            overall_risk = 'None'
        
        return {
            'overall_risk': overall_risk,
            'risk_score': risk_score,
            'risk_factors': risk_factors,
            'vulnerable_parameters': vulnerable_points,
            'total_vulnerabilities': len(vulnerabilities)
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
        
        # 匹配测试的参数数量
        param_pattern = r'testing\s+(\d+)\s+parameter'
        param_match = re.search(param_pattern, output)
        if param_match:
            stats['tested_parameters'] = int(param_match.group(1))
        
        # 匹配执行的测试数量
        test_pattern = r'performed\s+(\d+)\s+queries'
        test_match = re.search(test_pattern, output)
        if test_match:
            stats['total_queries'] = int(test_match.group(1))
        
        # 匹配扫描时间
        time_pattern = r'sqlmap\s+finished\s+at\s+[^\n]*\s+\(total\s+time:\s+([^)]+)\)'
        time_match = re.search(time_pattern, output)
        if time_match:
            stats['scan_duration'] = time_match.group(1).strip()
        
        # 匹配错误数
        error_count = len(re.findall(r'error|failed|timeout', output, re.IGNORECASE))
        stats['errors'] = error_count
        
        return stats
    
    def _generate_summary(self, injection_points: List[Dict], database_info: Dict, risk_assessment: Dict) -> str:
        """
        生成扫描摘要
        
        Args:
            injection_points: 注入点列表
            database_info: 数据库信息
            risk_assessment: 风险评估
            
        Returns:
            扫描摘要字符串
        """
        summary_parts = []
        
        vulnerable_points = risk_assessment.get('vulnerable_parameters', 0)
        overall_risk = risk_assessment.get('overall_risk', 'None')
        dbms = database_info.get('dbms', '未知')
        
        if vulnerable_points > 0:
            summary_parts.append(f"发现 {vulnerable_points} 个SQL注入漏洞")
            summary_parts.append(f"风险级别: {overall_risk}")
            
            if dbms != '未知':
                summary_parts.append(f"数据库类型: {dbms}")
            
            # 注入类型统计
            all_types = set()
            for point in injection_points:
                if point.get('vulnerable', False):
                    all_types.update(point.get('injection_types', []))
            
            if all_types:
                summary_parts.append(f"支持注入类型: {len(all_types)}种")
        else:
            summary_parts.append("未发现SQL注入漏洞")
        
        return '，'.join(summary_parts)
    
    def test_url(self, url: str, **kwargs) -> Dict[str, Any]:
        """
        测试URL的便捷方法
        
        Args:
            url: 目标URL
            **kwargs: 其他参数
            
        Returns:
            测试结果
        """
        return self.execute(
            url=url,
            level=self.default_level,
            risk=self.default_risk,
            **kwargs
        )
    
    def test_post_data(self, url: str, data: str, **kwargs) -> Dict[str, Any]:
        """
        测试POST数据的便捷方法
        
        Args:
            url: 目标URL
            data: POST数据
            **kwargs: 其他参数
            
        Returns:
            测试结果
        """
        return self.execute(
            url=url,
            data=data,
            level=self.default_level,
            risk=self.default_risk,
            **kwargs
        )
    
    def quick_test(self, url: str) -> Dict[str, Any]:
        """
        快速测试
        
        Args:
            url: 目标URL
            
        Returns:
            测试结果
        """
        return self.execute(
            url=url,
            level=1,
            risk=1,
            technique='B',
            batch=True
        )
    
    def comprehensive_test(self, url: str, **kwargs) -> Dict[str, Any]:
        """
        全面测试
        
        Args:
            url: 目标URL
            **kwargs: 其他参数
            
        Returns:
            测试结果
        """
        return self.execute(
            url=url,
            level=5,
            risk=3,
            technique='BEUSTQ',
            batch=True,
            **kwargs
        )