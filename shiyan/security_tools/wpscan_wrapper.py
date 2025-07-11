#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WPScan WordPress安全扫描工具包装器

提供WPScan WordPress安全扫描工具的专门封装
支持插件、主题、用户枚举、漏洞检测等
包含WordPress特定的安全分析功能
"""

import re
import json
from typing import Dict, Any, List

from .base_wrapper import BaseToolWrapper
from config import config


class WPScanWrapper(BaseToolWrapper):
    """
    WPScan WordPress安全扫描工具包装器
    
    支持WordPress核心、插件、主题漏洞检测
    用户枚举、密码爆破、配置检查等功能
    """
    
    def __init__(self):
        super().__init__('wpscan')
        self.api_token = config.WPSCAN_API_TOKEN
    
    def validate_params(self, **kwargs) -> Dict[str, Any]:
        """
        验证WPScan参数
        
        Args:
            url: 目标WordPress站点URL
            enumerate: 枚举选项
            plugins_detection: 插件检测模式
            themes_detection: 主题检测模式
            users: 用户枚举
            passwords: 密码字典
            
        Returns:
            验证结果
        """
        url = kwargs.get('url', '')
        
        # 验证URL
        if not url:
            return {'success': False, 'error': '需要指定目标WordPress站点URL'}
        
        if not self.validate_url(url):
            return {'success': False, 'error': '无效的URL格式'}
        
        # 验证枚举选项
        enumerate = kwargs.get('enumerate', '')
        if enumerate:
            valid_enum_options = ['p', 't', 'tt', 'u', 'vp', 'ap', 'at', 'cb', 'dbe']
            enum_parts = enumerate.split(',')
            for part in enum_parts:
                if part.strip() not in valid_enum_options:
                    return {'success': False, 'error': f'无效的枚举选项: {part}'}
        
        # 验证检测模式
        detection_modes = ['passive', 'aggressive', 'mixed']
        plugins_detection = kwargs.get('plugins_detection', 'passive')
        themes_detection = kwargs.get('themes_detection', 'passive')
        
        if plugins_detection not in detection_modes:
            return {'success': False, 'error': f'无效的插件检测模式: {plugins_detection}'}
        
        if themes_detection not in detection_modes:
            return {'success': False, 'error': f'无效的主题检测模式: {themes_detection}'}
        
        return {'success': True}
    
    def build_command(self, **kwargs) -> str:
        """
        构建WPScan命令
        
        Args:
            **kwargs: WPScan参数
            
        Returns:
            完整的WPScan命令
        """
        url = kwargs.get('url', '')
        enumerate = kwargs.get('enumerate', 'vp,vt,u')
        plugins_detection = kwargs.get('plugins_detection', 'passive')
        themes_detection = kwargs.get('themes_detection', 'passive')
        users = kwargs.get('users', '')
        passwords = kwargs.get('passwords', '')
        threads = kwargs.get('threads', 5)
        timeout = kwargs.get('timeout', 60)
        user_agent = kwargs.get('user_agent', '')
        additional_args = kwargs.get('additional_args', '')
        
        # 构建基础命令
        command_parts = ['wpscan']
        
        # 添加目标URL
        command_parts.extend(['--url', url])
        
        # 添加枚举选项
        if enumerate:
            command_parts.extend(['--enumerate', enumerate])
        
        # 添加插件检测模式
        command_parts.extend(['--plugins-detection', plugins_detection])
        
        # 添加主题检测模式
        command_parts.extend(['--themes-detection', themes_detection])
        
        # 添加API Token（如果可用）
        if self.api_token:
            command_parts.extend(['--api-token', self.api_token])
        
        # 添加用户枚举
        if users:
            command_parts.extend(['--usernames', users])
        
        # 添加密码字典
        if passwords:
            command_parts.extend(['--passwords', passwords])
        
        # 添加线程数
        command_parts.extend(['--max-threads', str(threads)])
        
        # 添加超时时间
        command_parts.extend(['--request-timeout', str(timeout)])
        
        # 添加用户代理
        if user_agent:
            command_parts.extend(['--user-agent', f'"{user_agent}"'])
        
        # 添加输出格式
        command_parts.extend(['--format', 'json'])
        
        # 禁用横幅
        command_parts.append('--no-banner')
        
        # 添加附加参数
        if additional_args:
            command_parts.append(additional_args)
        
        return ' '.join(command_parts)
    
    def parse_output(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """
        解析WPScan输出
        
        Args:
            stdout: WPScan标准输出
            stderr: WPScan错误输出
            
        Returns:
            解析后的结果
        """
        result = super().parse_output(stdout, stderr)
        
        # 尝试解析JSON输出
        scan_data = self._parse_json_output(stdout)
        
        if scan_data:
            # 解析WordPress信息
            wp_info = self._extract_wordpress_info(scan_data)
            
            # 解析漏洞信息
            vulnerabilities = self._extract_vulnerabilities(scan_data)
            
            # 解析插件信息
            plugins = self._extract_plugins(scan_data)
            
            # 解析主题信息
            themes = self._extract_themes(scan_data)
            
            # 解析用户信息
            users = self._extract_users(scan_data)
            
            # 风险评估
            risk_assessment = self._assess_risks(vulnerabilities, plugins, themes)
            
            result.update({
                'wordpress_info': wp_info,
                'vulnerabilities': vulnerabilities,
                'plugins': plugins,
                'themes': themes,
                'users': users,
                'risk_assessment': risk_assessment,
                'summary': self._generate_summary(wp_info, vulnerabilities, plugins, themes, users)
            })
        else:
            # 如果JSON解析失败，使用文本解析
            result.update(self._parse_text_output(stdout))
        
        return result
    
    def _parse_json_output(self, output: str) -> Dict[str, Any]:
        """
        解析JSON格式输出
        
        Args:
            output: WPScan输出
            
        Returns:
            解析后的JSON数据
        """
        try:
            # 查找JSON数据的开始位置
            json_start = output.find('{')
            if json_start != -1:
                json_data = output[json_start:]
                return json.loads(json_data)
        except json.JSONDecodeError as e:
            self.logger.warning(f"JSON解析失败: {e}")
        
        return None
    
    def _extract_wordpress_info(self, data: Dict) -> Dict[str, Any]:
        """
        提取WordPress基本信息
        
        Args:
            data: 扫描数据
            
        Returns:
            WordPress信息
        """
        wp_info = {}
        
        # 提取版本信息
        version_info = data.get('version', {})
        if version_info:
            wp_info['version'] = version_info.get('number', '未知')
            wp_info['version_status'] = version_info.get('status', '未知')
            wp_info['version_found_by'] = version_info.get('found_by', [])
        
        # 提取主要URL
        wp_info['target_url'] = data.get('target_url', '')
        wp_info['effective_url'] = data.get('effective_url', '')
        
        # 提取服务器信息
        wp_info['interesting_findings'] = data.get('interesting_findings', [])
        
        return wp_info
    
    def _extract_vulnerabilities(self, data: Dict) -> List[Dict[str, Any]]:
        """
        提取漏洞信息
        
        Args:
            data: 扫描数据
            
        Returns:
            漏洞列表
        """
        vulnerabilities = []
        
        # WordPress核心漏洞
        version_info = data.get('version', {})
        if 'vulnerabilities' in version_info:
            for vuln in version_info['vulnerabilities']:
                vulnerabilities.append({
                    'component': 'WordPress Core',
                    'component_version': version_info.get('number', '未知'),
                    'title': vuln.get('title', ''),
                    'fixed_in': vuln.get('fixed_in', ''),
                    'references': vuln.get('references', {}),
                    'severity': self._determine_severity(vuln)
                })
        
        # 插件漏洞
        plugins = data.get('plugins', {})
        for plugin_name, plugin_info in plugins.items():
            if 'vulnerabilities' in plugin_info:
                for vuln in plugin_info['vulnerabilities']:
                    vulnerabilities.append({
                        'component': f'Plugin: {plugin_name}',
                        'component_version': plugin_info.get('version', {}).get('number', '未知'),
                        'title': vuln.get('title', ''),
                        'fixed_in': vuln.get('fixed_in', ''),
                        'references': vuln.get('references', {}),
                        'severity': self._determine_severity(vuln)
                    })
        
        # 主题漏洞
        themes = data.get('themes', {})
        for theme_name, theme_info in themes.items():
            if 'vulnerabilities' in theme_info:
                for vuln in theme_info['vulnerabilities']:
                    vulnerabilities.append({
                        'component': f'Theme: {theme_name}',
                        'component_version': theme_info.get('version', {}).get('number', '未知'),
                        'title': vuln.get('title', ''),
                        'fixed_in': vuln.get('fixed_in', ''),
                        'references': vuln.get('references', {}),
                        'severity': self._determine_severity(vuln)
                    })
        
        return vulnerabilities
    
    def _extract_plugins(self, data: Dict) -> List[Dict[str, Any]]:
        """
        提取插件信息
        
        Args:
            data: 扫描数据
            
        Returns:
            插件列表
        """
        plugins = []
        
        plugins_data = data.get('plugins', {})
        for plugin_name, plugin_info in plugins_data.items():
            plugin_entry = {
                'name': plugin_name,
                'version': plugin_info.get('version', {}).get('number', '未知'),
                'latest_version': plugin_info.get('latest_version', '未知'),
                'outdated': plugin_info.get('outdated', False),
                'vulnerabilities_count': len(plugin_info.get('vulnerabilities', [])),
                'found_by': plugin_info.get('found_by', []),
                'location': plugin_info.get('location', '')
            }
            plugins.append(plugin_entry)
        
        return plugins
    
    def _extract_themes(self, data: Dict) -> List[Dict[str, Any]]:
        """
        提取主题信息
        
        Args:
            data: 扫描数据
            
        Returns:
            主题列表
        """
        themes = []
        
        themes_data = data.get('themes', {})
        for theme_name, theme_info in themes_data.items():
            theme_entry = {
                'name': theme_name,
                'version': theme_info.get('version', {}).get('number', '未知'),
                'latest_version': theme_info.get('latest_version', '未知'),
                'outdated': theme_info.get('outdated', False),
                'vulnerabilities_count': len(theme_info.get('vulnerabilities', [])),
                'found_by': theme_info.get('found_by', []),
                'location': theme_info.get('location', ''),
                'style': theme_info.get('style', '')
            }
            themes.append(theme_entry)
        
        return themes
    
    def _extract_users(self, data: Dict) -> List[Dict[str, Any]]:
        """
        提取用户信息
        
        Args:
            data: 扫描数据
            
        Returns:
            用户列表
        """
        users = []
        
        users_data = data.get('users', {})
        for user_id, user_info in users_data.items():
            user_entry = {
                'id': user_id,
                'username': user_info.get('username', ''),
                'found_by': user_info.get('found_by', []),
                'password_attack': user_info.get('password_attack', {})
            }
            users.append(user_entry)
        
        return users
    
    def _determine_severity(self, vulnerability: Dict) -> str:
        """
        确定漏洞严重性
        
        Args:
            vulnerability: 漏洞信息
            
        Returns:
            严重性级别
        """
        title = vulnerability.get('title', '').lower()
        
        # 高危关键词
        high_risk_keywords = [
            'remote code execution', 'rce', 'sql injection', 'authentication bypass',
            'privilege escalation', 'arbitrary file upload', 'directory traversal'
        ]
        
        # 中危关键词
        medium_risk_keywords = [
            'cross-site scripting', 'xss', 'csrf', 'information disclosure',
            'open redirect', 'file inclusion'
        ]
        
        # 低危关键词
        low_risk_keywords = [
            'denial of service', 'dos', 'information exposure'
        ]
        
        if any(keyword in title for keyword in high_risk_keywords):
            return 'High'
        elif any(keyword in title for keyword in medium_risk_keywords):
            return 'Medium'
        elif any(keyword in title for keyword in low_risk_keywords):
            return 'Low'
        else:
            return 'Info'
    
    def _assess_risks(self, vulnerabilities: List[Dict], plugins: List[Dict], themes: List[Dict]) -> Dict[str, Any]:
        """
        评估风险
        
        Args:
            vulnerabilities: 漏洞列表
            plugins: 插件列表
            themes: 主题列表
            
        Returns:
            风险评估结果
        """
        risk_score = 0
        risk_factors = []
        
        # 漏洞风险评分
        severity_scores = {'High': 30, 'Medium': 15, 'Low': 5, 'Info': 1}
        vuln_counts = {'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Info')
            vuln_counts[severity] += 1
            risk_score += severity_scores.get(severity, 1)
        
        # 过期组件风险
        outdated_plugins = sum(1 for plugin in plugins if plugin.get('outdated', False))
        outdated_themes = sum(1 for theme in themes if theme.get('outdated', False))
        
        risk_score += outdated_plugins * 5
        risk_score += outdated_themes * 5
        
        if outdated_plugins > 0:
            risk_factors.append(f"{outdated_plugins}个过期插件")
        if outdated_themes > 0:
            risk_factors.append(f"{outdated_themes}个过期主题")
        
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
            'vulnerability_counts': vuln_counts,
            'outdated_components': outdated_plugins + outdated_themes
        }
    
    def _parse_text_output(self, output: str) -> Dict[str, Any]:
        """
        解析文本格式输出（备用方法）
        
        Args:
            output: WPScan输出
            
        Returns:
            解析结果
        """
        result = {
            'wordpress_info': {},
            'vulnerabilities': [],
            'plugins': [],
            'themes': [],
            'users': []
        }
        
        # 简单的文本解析逻辑
        lines = output.split('\n')
        for line in lines:
            if 'WordPress version' in line:
                version_match = re.search(r'WordPress version ([\d.]+)', line)
                if version_match:
                    result['wordpress_info']['version'] = version_match.group(1)
        
        return result
    
    def _generate_summary(self, wp_info: Dict, vulnerabilities: List, plugins: List, themes: List, users: List) -> str:
        """
        生成扫描摘要
        
        Args:
            wp_info: WordPress信息
            vulnerabilities: 漏洞列表
            plugins: 插件列表
            themes: 主题列表
            users: 用户列表
            
        Returns:
            扫描摘要字符串
        """
        summary_parts = []
        
        # WordPress版本
        wp_version = wp_info.get('version', '未知')
        summary_parts.append(f"WordPress版本: {wp_version}")
        
        # 漏洞统计
        vuln_count = len(vulnerabilities)
        if vuln_count > 0:
            summary_parts.append(f"发现 {vuln_count} 个漏洞")
        
        # 组件统计
        plugin_count = len(plugins)
        theme_count = len(themes)
        if plugin_count > 0:
            summary_parts.append(f"{plugin_count} 个插件")
        if theme_count > 0:
            summary_parts.append(f"{theme_count} 个主题")
        
        # 用户统计
        user_count = len(users)
        if user_count > 0:
            summary_parts.append(f"发现 {user_count} 个用户")
        
        return '，'.join(summary_parts)
    
    def scan_wordpress(self, url: str, **kwargs) -> Dict[str, Any]:
        """
        WordPress扫描的便捷方法
        
        Args:
            url: 目标WordPress站点URL
            **kwargs: 其他参数
            
        Returns:
            扫描结果
        """
        return self.execute(
            url=url,
            enumerate='vp,vt,u',
            plugins_detection='passive',
            themes_detection='passive',
            **kwargs
        )
    
    def quick_scan(self, url: str) -> Dict[str, Any]:
        """
        快速扫描
        
        Args:
            url: 目标WordPress站点URL
            
        Returns:
            扫描结果
        """
        return self.execute(
            url=url,
            enumerate='vp',
            plugins_detection='passive',
            threads=3
        )
    
    def comprehensive_scan(self, url: str) -> Dict[str, Any]:
        """
        全面扫描
        
        Args:
            url: 目标WordPress站点URL
            
        Returns:
            扫描结果
        """
        return self.execute(
            url=url,
            enumerate='vp,vt,tt,cb,dbe,u,m',
            plugins_detection='aggressive',
            themes_detection='aggressive',
            threads=10
        )
    
    def enumerate_users(self, url: str, **kwargs) -> Dict[str, Any]:
        """
        用户枚举
        
        Args:
            url: 目标WordPress站点URL
            **kwargs: 其他参数
            
        Returns:
            扫描结果
        """
        return self.execute(
            url=url,
            enumerate='u',
            **kwargs
        )