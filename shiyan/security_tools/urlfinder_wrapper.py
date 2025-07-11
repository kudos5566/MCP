#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
URLFinder URL发现工具包装器

提供URL发现和收集工具的专门封装
支持多种URL发现方式、过滤选项、输出格式等
包含URL分析和分类功能
"""

import re
import urllib.parse
from typing import Dict, Any, List, Set

from .base_wrapper import BaseToolWrapper
from config import config


class URLFinderWrapper(BaseToolWrapper):
    """
    URLFinder URL发现工具包装器
    
    支持从多种来源发现URL：网页爬取、搜索引擎、归档网站等
    自动分析和分类发现的URL
    """
    
    def __init__(self):
        super().__init__('urlfinder')
        self.default_depth = config.URLFINDER_DEFAULT_DEPTH
    
    def validate_params(self, **kwargs) -> Dict[str, Any]:
        """
        验证URLFinder参数
        
        Args:
            domain: 目标域名
            url: 目标URL
            depth: 爬取深度
            threads: 线程数
            timeout: 超时时间
            include_subdomains: 是否包含子域名
            
        Returns:
            验证结果
        """
        domain = kwargs.get('domain', '')
        url = kwargs.get('url', '')
        depth = kwargs.get('depth', self.default_depth)
        threads = kwargs.get('threads', 10)
        timeout = kwargs.get('timeout', 10)
        
        # 验证目标（域名或URL至少需要一个）
        if not domain and not url:
            return {'success': False, 'error': '需要指定目标域名或URL'}
        
        # 验证域名格式
        if domain and not self.validate_domain(domain):
            return {'success': False, 'error': '无效的域名格式'}
        
        # 验证URL格式
        if url and not self.validate_url(url):
            return {'success': False, 'error': '无效的URL格式'}
        
        # 验证爬取深度
        try:
            depth = int(depth)
            if not (1 <= depth <= 10):
                return {'success': False, 'error': '爬取深度必须在1-10之间'}
        except ValueError:
            return {'success': False, 'error': '爬取深度必须是数字'}
        
        # 验证线程数
        try:
            threads = int(threads)
            if not (1 <= threads <= 50):
                return {'success': False, 'error': '线程数必须在1-50之间'}
        except ValueError:
            return {'success': False, 'error': '线程数必须是数字'}
        
        # 验证超时时间
        try:
            timeout = int(timeout)
            if not (1 <= timeout <= 60):
                return {'success': False, 'error': '超时时间必须在1-60秒之间'}
        except ValueError:
            return {'success': False, 'error': '超时时间必须是数字'}
        
        return {'success': True}
    
    def build_command(self, **kwargs) -> str:
        """
        构建URLFinder命令
        
        Args:
            **kwargs: URLFinder参数
            
        Returns:
            完整的URLFinder命令
        """
        domain = kwargs.get('domain', '')
        url = kwargs.get('url', '')
        depth = kwargs.get('depth', self.default_depth)
        threads = kwargs.get('threads', 10)
        timeout = kwargs.get('timeout', 10)
        include_subdomains = kwargs.get('include_subdomains', False)
        sources = kwargs.get('sources', 'wayback,commoncrawl,urlscan')
        additional_args = kwargs.get('additional_args', '')
        
        # 构建基础命令
        command_parts = ['urlfinder']
        
        # 添加目标
        if domain:
            command_parts.extend(['-d', domain])
        elif url:
            command_parts.extend(['-u', url])
        
        # 添加爬取深度
        command_parts.extend(['--depth', str(depth)])
        
        # 添加线程数
        command_parts.extend(['-t', str(threads)])
        
        # 添加超时时间
        command_parts.extend(['--timeout', str(timeout)])
        
        # 添加子域名选项
        if include_subdomains:
            command_parts.append('--include-subdomains')
        
        # 添加数据源
        if sources:
            command_parts.extend(['--sources', sources])
        
        # 添加输出格式
        command_parts.extend(['--output', 'json'])
        
        # 添加附加参数
        if additional_args:
            command_parts.append(additional_args)
        
        return ' '.join(command_parts)
    
    def parse_output(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """
        解析URLFinder输出
        
        Args:
            stdout: URLFinder标准输出
            stderr: URLFinder错误输出
            
        Returns:
            解析后的结果
        """
        result = super().parse_output(stdout, stderr)
        
        # 解析发现的URL
        urls = self._parse_urls(stdout)
        
        # 分析URL
        url_analysis = self._analyze_urls(urls)
        
        # 分类URL
        url_categories = self._categorize_urls(urls)
        
        # 提取参数
        parameters = self._extract_parameters(urls)
        
        # 解析统计信息
        stats = self._parse_scan_stats(stdout, stderr)
        
        result.update({
            'urls': urls,
            'url_analysis': url_analysis,
            'url_categories': url_categories,
            'parameters': parameters,
            'scan_stats': stats,
            'summary': self._generate_summary(urls, url_analysis)
        })
        
        return result
    
    def _parse_urls(self, output: str) -> List[str]:
        """
        解析发现的URL
        
        Args:
            output: URLFinder输出
            
        Returns:
            URL列表
        """
        urls = set()
        
        # 尝试解析JSON格式输出
        try:
            import json
            json_data = json.loads(output)
            if isinstance(json_data, list):
                urls.update(json_data)
            elif isinstance(json_data, dict) and 'urls' in json_data:
                urls.update(json_data['urls'])
        except (json.JSONDecodeError, ImportError):
            # 如果不是JSON格式，使用正则表达式提取URL
            url_pattern = r'https?://[^\s<>"\'{},|\\^`\[\]]+'
            found_urls = re.findall(url_pattern, output)
            urls.update(found_urls)
        
        # 去重并排序
        return sorted(list(urls))
    
    def _analyze_urls(self, urls: List[str]) -> Dict[str, Any]:
        """
        分析URL
        
        Args:
            urls: URL列表
            
        Returns:
            URL分析结果
        """
        analysis = {
            'total_urls': len(urls),
            'unique_domains': set(),
            'unique_paths': set(),
            'file_extensions': {},
            'url_lengths': [],
            'protocols': {'http': 0, 'https': 0},
            'has_parameters': 0,
            'suspicious_urls': []
        }
        
        for url in urls:
            try:
                parsed = urllib.parse.urlparse(url)
                
                # 域名统计
                analysis['unique_domains'].add(parsed.netloc)
                
                # 路径统计
                analysis['unique_paths'].add(parsed.path)
                
                # 协议统计
                if parsed.scheme in analysis['protocols']:
                    analysis['protocols'][parsed.scheme] += 1
                
                # URL长度统计
                analysis['url_lengths'].append(len(url))
                
                # 参数统计
                if parsed.query:
                    analysis['has_parameters'] += 1
                
                # 文件扩展名统计
                path = parsed.path
                if '.' in path:
                    ext = path.split('.')[-1].lower()
                    if ext and len(ext) <= 5:  # 合理的扩展名长度
                        analysis['file_extensions'][ext] = analysis['file_extensions'].get(ext, 0) + 1
                
                # 检测可疑URL
                if self._is_suspicious_url(url):
                    analysis['suspicious_urls'].append(url)
                    
            except Exception as e:
                self.logger.warning(f"解析URL失败: {url}, 错误: {e}")
        
        # 转换集合为列表以便JSON序列化
        analysis['unique_domains'] = list(analysis['unique_domains'])
        analysis['unique_paths'] = list(analysis['unique_paths'])
        
        # 计算统计值
        if analysis['url_lengths']:
            analysis['avg_url_length'] = sum(analysis['url_lengths']) / len(analysis['url_lengths'])
            analysis['max_url_length'] = max(analysis['url_lengths'])
            analysis['min_url_length'] = min(analysis['url_lengths'])
        
        return analysis
    
    def _categorize_urls(self, urls: List[str]) -> Dict[str, List[str]]:
        """
        分类URL
        
        Args:
            urls: URL列表
            
        Returns:
            分类后的URL
        """
        categories = {
            'api_endpoints': [],
            'admin_panels': [],
            'login_pages': [],
            'config_files': [],
            'backup_files': [],
            'development_files': [],
            'static_resources': [],
            'dynamic_pages': [],
            'other': []
        }
        
        for url in urls:
            url_lower = url.lower()
            path = urllib.parse.urlparse(url).path.lower()
            
            # API端点
            if any(keyword in url_lower for keyword in ['/api/', '/rest/', '/graphql', '/v1/', '/v2/']):
                categories['api_endpoints'].append(url)
            # 管理面板
            elif any(keyword in url_lower for keyword in ['/admin', '/administrator', '/manage', '/control']):
                categories['admin_panels'].append(url)
            # 登录页面
            elif any(keyword in url_lower for keyword in ['/login', '/signin', '/auth', '/logon']):
                categories['login_pages'].append(url)
            # 配置文件
            elif any(ext in path for ext in ['.config', '.ini', '.conf', '.xml', '.json', '.yaml', '.yml']):
                categories['config_files'].append(url)
            # 备份文件
            elif any(ext in path for ext in ['.bak', '.backup', '.old', '.tmp', '.swp']):
                categories['backup_files'].append(url)
            # 开发文件
            elif any(keyword in path for keyword in ['/test', '/debug', '/dev', '.git', '.svn']):
                categories['development_files'].append(url)
            # 静态资源
            elif any(ext in path for ext in ['.css', '.js', '.img', '.png', '.jpg', '.gif', '.pdf']):
                categories['static_resources'].append(url)
            # 动态页面
            elif any(ext in path for ext in ['.php', '.asp', '.jsp', '.py', '.rb']):
                categories['dynamic_pages'].append(url)
            else:
                categories['other'].append(url)
        
        return categories
    
    def _extract_parameters(self, urls: List[str]) -> Dict[str, Any]:
        """
        提取URL参数
        
        Args:
            urls: URL列表
            
        Returns:
            参数分析结果
        """
        all_params = set()
        param_values = {}
        suspicious_params = []
        
        for url in urls:
            try:
                parsed = urllib.parse.urlparse(url)
                if parsed.query:
                    params = urllib.parse.parse_qs(parsed.query)
                    for param, values in params.items():
                        all_params.add(param)
                        
                        # 收集参数值样本
                        if param not in param_values:
                            param_values[param] = set()
                        param_values[param].update(values[:5])  # 最多保存5个样本值
                        
                        # 检测可疑参数
                        if self._is_suspicious_parameter(param, values):
                            suspicious_params.append({
                                'url': url,
                                'parameter': param,
                                'values': values
                            })
            except Exception as e:
                self.logger.warning(f"解析URL参数失败: {url}, 错误: {e}")
        
        # 转换为可序列化格式
        param_values_serializable = {}
        for param, values in param_values.items():
            param_values_serializable[param] = list(values)
        
        return {
            'unique_parameters': list(all_params),
            'parameter_count': len(all_params),
            'parameter_values': param_values_serializable,
            'suspicious_parameters': suspicious_params
        }
    
    def _is_suspicious_url(self, url: str) -> bool:
        """
        检测可疑URL
        
        Args:
            url: URL
            
        Returns:
            是否可疑
        """
        suspicious_patterns = [
            r'\.\./',  # 目录遍历
            r'<script',  # XSS
            r'javascript:',  # JavaScript协议
            r'data:',  # Data协议
            r'file://',  # 文件协议
            r'\bselect\b.*\bfrom\b',  # SQL注入
            r'\bunion\b.*\bselect\b',  # SQL注入
            r'\bexec\b|\beval\b',  # 代码执行
        ]
        
        url_lower = url.lower()
        return any(re.search(pattern, url_lower, re.IGNORECASE) for pattern in suspicious_patterns)
    
    def _is_suspicious_parameter(self, param: str, values: List[str]) -> bool:
        """
        检测可疑参数
        
        Args:
            param: 参数名
            values: 参数值列表
            
        Returns:
            是否可疑
        """
        # 可疑参数名
        suspicious_param_names = [
            'cmd', 'exec', 'system', 'eval', 'file', 'path',
            'url', 'redirect', 'include', 'require', 'load'
        ]
        
        if param.lower() in suspicious_param_names:
            return True
        
        # 检查参数值
        for value in values:
            if self._is_suspicious_url(value):
                return True
        
        return False
    
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
        
        # 匹配处理的URL数量
        processed_pattern = r'Processed\s+(\d+)\s+URLs'
        processed_match = re.search(processed_pattern, output)
        if processed_match:
            stats['processed_urls'] = int(processed_match.group(1))
        
        # 匹配发现的URL数量
        found_pattern = r'Found\s+(\d+)\s+unique\s+URLs'
        found_match = re.search(found_pattern, output)
        if found_match:
            stats['found_urls'] = int(found_match.group(1))
        
        # 匹配扫描时间
        time_pattern = r'Scan\s+completed\s+in\s+([\d.]+)\s+seconds'
        time_match = re.search(time_pattern, output)
        if time_match:
            stats['scan_duration'] = float(time_match.group(1))
        
        # 匹配错误数
        error_count = len(re.findall(r'error|failed|timeout', output, re.IGNORECASE))
        stats['errors'] = error_count
        
        return stats
    
    def _generate_summary(self, urls: List[str], analysis: Dict) -> str:
        """
        生成扫描摘要
        
        Args:
            urls: URL列表
            analysis: URL分析结果
            
        Returns:
            扫描摘要字符串
        """
        summary_parts = []
        
        total_urls = len(urls)
        unique_domains = len(analysis.get('unique_domains', []))
        has_parameters = analysis.get('has_parameters', 0)
        suspicious_count = len(analysis.get('suspicious_urls', []))
        
        summary_parts.append(f"发现 {total_urls} 个URL")
        summary_parts.append(f"涉及 {unique_domains} 个域名")
        
        if has_parameters > 0:
            summary_parts.append(f"{has_parameters} 个带参数URL")
        
        if suspicious_count > 0:
            summary_parts.append(f"{suspicious_count} 个可疑URL")
        
        # 文件类型统计
        file_extensions = analysis.get('file_extensions', {})
        if file_extensions:
            top_ext = max(file_extensions.items(), key=lambda x: x[1])
            summary_parts.append(f"主要文件类型: {top_ext[0]} ({top_ext[1]}个)")
        
        return '，'.join(summary_parts)
    
    def find_urls_by_domain(self, domain: str, **kwargs) -> Dict[str, Any]:
        """
        按域名查找URL的便捷方法
        
        Args:
            domain: 目标域名
            **kwargs: 其他参数
            
        Returns:
            扫描结果
        """
        return self.execute(
            domain=domain,
            depth=self.default_depth,
            include_subdomains=True,
            **kwargs
        )
    
    def find_urls_by_url(self, url: str, **kwargs) -> Dict[str, Any]:
        """
        按URL查找相关URL的便捷方法
        
        Args:
            url: 目标URL
            **kwargs: 其他参数
            
        Returns:
            扫描结果
        """
        return self.execute(
            url=url,
            depth=self.default_depth,
            **kwargs
        )
    
    def quick_url_discovery(self, target: str) -> Dict[str, Any]:
        """
        快速URL发现
        
        Args:
            target: 目标（域名或URL）
            
        Returns:
            扫描结果
        """
        if target.startswith(('http://', 'https://')):
            return self.execute(url=target, depth=2, threads=20)
        else:
            return self.execute(domain=target, depth=2, threads=20)
    
    def comprehensive_url_discovery(self, domain: str) -> Dict[str, Any]:
        """
        全面URL发现
        
        Args:
            domain: 目标域名
            
        Returns:
            扫描结果
        """
        return self.execute(
            domain=domain,
            depth=5,
            threads=30,
            include_subdomains=True,
            sources='wayback,commoncrawl,urlscan,alienvault'
        )