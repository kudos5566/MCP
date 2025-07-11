#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hydra密码爆破工具包装器

提供Hydra密码暴力破解工具的专门封装
支持多种协议、用户名和密码字典、并发控制等
包含爆破结果分析和成功率统计功能
"""

import re
import os
from typing import Dict, Any, List

from .base_wrapper import BaseToolWrapper
from config import config


class HydraWrapper(BaseToolWrapper):
    """
    Hydra密码爆破工具包装器
    
    支持SSH、FTP、HTTP、RDP等多种协议的密码爆破
    自动分析爆破结果并统计成功率
    """
    
    def __init__(self):
        super().__init__('hydra')
        self.default_userlist = config.HYDRA_DEFAULT_USERLIST
        self.default_passlist = config.HYDRA_DEFAULT_PASSLIST
    
    def validate_params(self, **kwargs) -> Dict[str, Any]:
        """
        验证Hydra参数
        
        Args:
            target: 目标主机或IP
            service: 服务类型
            port: 端口号
            username: 单个用户名
            userlist: 用户名字典文件
            password: 单个密码
            passlist: 密码字典文件
            threads: 线程数
            
        Returns:
            验证结果
        """
        target = kwargs.get('target', '')
        service = kwargs.get('service', '')
        port = kwargs.get('port', '')
        username = kwargs.get('username', '')
        userlist = kwargs.get('userlist', '')
        password = kwargs.get('password', '')
        passlist = kwargs.get('passlist', '')
        threads = kwargs.get('threads', 16)
        
        # 验证目标
        if not target:
            return {'success': False, 'error': '需要指定目标主机或IP'}
        
        if not (self.validate_ip(target) or self.validate_domain(target)):
            return {'success': False, 'error': '无效的目标格式'}
        
        # 验证服务类型
        if not service:
            return {'success': False, 'error': '需要指定服务类型'}
        
        supported_services = [
            'ssh', 'ftp', 'telnet', 'http-get', 'http-post-form', 'https-get',
            'https-post-form', 'smb', 'pop3', 'imap', 'smtp', 'mysql', 'mssql',
            'postgres', 'rdp', 'vnc', 'snmp', 'ldap'
        ]
        
        if service not in supported_services:
            return {'success': False, 'error': f'不支持的服务类型，支持: {", ".join(supported_services)}'}
        
        # 验证端口
        if port:
            try:
                port = int(port)
                if not (1 <= port <= 65535):
                    return {'success': False, 'error': '端口号必须在1-65535之间'}
            except ValueError:
                return {'success': False, 'error': '端口号必须是数字'}
        
        # 验证用户名/密码配置
        if not username and not userlist:
            return {'success': False, 'error': '需要指定用户名或用户名字典文件'}
        
        if not password and not passlist:
            return {'success': False, 'error': '需要指定密码或密码字典文件'}
        
        # 验证字典文件
        if userlist and not os.path.isfile(userlist):
            self.logger.warning(f"用户名字典文件不存在: {userlist}")
        
        if passlist and not os.path.isfile(passlist):
            self.logger.warning(f"密码字典文件不存在: {passlist}")
        
        # 验证线程数
        try:
            threads = int(threads)
            if not (1 <= threads <= 64):
                return {'success': False, 'error': '线程数必须在1-64之间'}
        except ValueError:
            return {'success': False, 'error': '线程数必须是数字'}
        
        return {'success': True}
    
    def build_command(self, **kwargs) -> str:
        """
        构建Hydra命令
        
        Args:
            **kwargs: Hydra参数
            
        Returns:
            完整的Hydra命令
        """
        target = kwargs.get('target', '')
        service = kwargs.get('service', '')
        port = kwargs.get('port', '')
        username = kwargs.get('username', '')
        userlist = kwargs.get('userlist', self.default_userlist)
        password = kwargs.get('password', '')
        passlist = kwargs.get('passlist', self.default_passlist)
        threads = kwargs.get('threads', 16)
        timeout = kwargs.get('timeout', 30)
        exit_on_first = kwargs.get('exit_on_first', True)
        verbose = kwargs.get('verbose', True)
        additional_args = kwargs.get('additional_args', '')
        
        # 构建基础命令
        command_parts = ['hydra']
        
        # 添加用户名选项
        if username:
            command_parts.extend(['-l', username])
        elif userlist:
            command_parts.extend(['-L', userlist])
        
        # 添加密码选项
        if password:
            command_parts.extend(['-p', password])
        elif passlist:
            command_parts.extend(['-P', passlist])
        
        # 添加线程数
        command_parts.extend(['-t', str(threads)])
        
        # 添加超时时间
        command_parts.extend(['-w', str(timeout)])
        
        # 添加详细输出
        if verbose:
            command_parts.append('-v')
        
        # 添加找到第一个密码后退出
        if exit_on_first:
            command_parts.append('-f')
        
        # 添加目标和端口
        if port:
            command_parts.extend(['-s', str(port)])
        
        # 添加目标主机
        command_parts.append(target)
        
        # 添加服务类型
        command_parts.append(service)
        
        # 添加附加参数
        if additional_args:
            command_parts.append(additional_args)
        
        return ' '.join(command_parts)
    
    def parse_output(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """
        解析Hydra输出
        
        Args:
            stdout: Hydra标准输出
            stderr: Hydra错误输出
            
        Returns:
            解析后的结果
        """
        result = super().parse_output(stdout, stderr)
        
        # 解析成功的凭据
        credentials = self._parse_credentials(stdout)
        
        # 解析爆破统计
        stats = self._parse_attack_stats(stdout, stderr)
        
        # 解析错误信息
        errors = self._parse_errors(stderr)
        
        # 分析结果
        analysis = self._analyze_results(credentials, stats)
        
        result.update({
            'credentials': credentials,
            'attack_stats': stats,
            'errors': errors,
            'analysis': analysis,
            'summary': self._generate_summary(credentials, stats, analysis)
        })
        
        return result
    
    def _parse_credentials(self, output: str) -> List[Dict[str, Any]]:
        """
        解析成功的凭据
        
        Args:
            output: Hydra输出
            
        Returns:
            凭据列表
        """
        credentials = []
        
        # 匹配成功的登录
        # 格式: [22][ssh] host: 192.168.1.1   login: admin   password: 123456
        success_pattern = r'\[(\d+)\]\[([^\]]+)\]\s+host:\s+([^\s]+)\s+login:\s+([^\s]+)\s+password:\s+(.+)'
        
        for match in re.finditer(success_pattern, output):
            port = match.group(1)
            service = match.group(2)
            host = match.group(3)
            username = match.group(4)
            password = match.group(5)
            
            credentials.append({
                'host': host,
                'port': int(port),
                'service': service,
                'username': username,
                'password': password,
                'status': 'success'
            })
        
        # 匹配有效的凭据（另一种格式）
        # 格式: [DATA] found valid credentials: admin:password123
        valid_pattern = r'\[DATA\]\s+found\s+valid\s+credentials:\s+([^:]+):(.+)'
        
        for match in re.finditer(valid_pattern, output):
            username = match.group(1)
            password = match.group(2)
            
            # 如果不在已找到的凭据中，添加它
            if not any(cred['username'] == username and cred['password'] == password for cred in credentials):
                credentials.append({
                    'username': username,
                    'password': password,
                    'status': 'valid'
                })
        
        return credentials
    
    def _parse_attack_stats(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """
        解析爆破统计信息
        
        Args:
            stdout: 标准输出
            stderr: 错误输出
            
        Returns:
            统计信息
        """
        stats = {}
        
        output = stdout + stderr
        
        # 匹配尝试次数
        attempts_pattern = r'(\d+)\s+of\s+(\d+)\s+target'
        attempts_match = re.search(attempts_pattern, output)
        if attempts_match:
            stats['completed_attempts'] = int(attempts_match.group(1))
            stats['total_targets'] = int(attempts_match.group(2))
        
        # 匹配数据统计
        data_pattern = r'\[DATA\]\s+max\s+(\d+)\s+tasks\s+per\s+(\d+)\s+server'
        data_match = re.search(data_pattern, output)
        if data_match:
            stats['max_tasks'] = int(data_match.group(1))
            stats['servers'] = int(data_match.group(2))
        
        # 匹配攻击进度
        progress_pattern = r'\[STATUS\]\s+(\d+)\.\d+\s+tries/min,\s+(\d+)\s+tries\s+in\s+([\d:]+)'
        progress_match = re.search(progress_pattern, output)
        if progress_match:
            stats['tries_per_minute'] = float(progress_match.group(1))
            stats['total_tries'] = int(progress_match.group(2))
            stats['elapsed_time'] = progress_match.group(3)
        
        # 匹配完成状态
        if '[DATA] attack finished' in output:
            stats['status'] = 'completed'
        elif '[ERROR]' in output:
            stats['status'] = 'error'
        else:
            stats['status'] = 'running'
        
        return stats
    
    def _parse_errors(self, stderr: str) -> List[str]:
        """
        解析错误信息
        
        Args:
            stderr: 错误输出
            
        Returns:
            错误列表
        """
        errors = []
        
        # 匹配错误信息
        error_patterns = [
            r'\[ERROR\]\s+(.+)',
            r'\[WARNING\]\s+(.+)',
            r'Error:\s+(.+)'
        ]
        
        for pattern in error_patterns:
            for match in re.finditer(pattern, stderr):
                error_msg = match.group(1).strip()
                if error_msg not in errors:
                    errors.append(error_msg)
        
        return errors
    
    def _analyze_results(self, credentials: List[Dict], stats: Dict) -> Dict[str, Any]:
        """
        分析爆破结果
        
        Args:
            credentials: 凭据列表
            stats: 统计信息
            
        Returns:
            分析结果
        """
        analysis = {
            'success_count': len(credentials),
            'success_rate': 0.0,
            'weak_passwords': [],
            'common_usernames': [],
            'password_patterns': {}
        }
        
        # 计算成功率
        total_tries = stats.get('total_tries', 0)
        if total_tries > 0:
            analysis['success_rate'] = (len(credentials) / total_tries) * 100
        
        # 分析弱密码
        weak_password_list = [
            'password', '123456', 'admin', 'root', 'guest', 'user',
            'test', 'demo', 'default', '12345', 'qwerty', 'abc123'
        ]
        
        for cred in credentials:
            password = cred.get('password', '').lower()
            if password in weak_password_list:
                analysis['weak_passwords'].append(cred)
        
        # 分析常见用户名
        usernames = [cred.get('username', '') for cred in credentials]
        username_counts = {}
        for username in usernames:
            username_counts[username] = username_counts.get(username, 0) + 1
        
        analysis['common_usernames'] = sorted(username_counts.items(), key=lambda x: x[1], reverse=True)
        
        # 分析密码模式
        for cred in credentials:
            password = cred.get('password', '')
            
            # 检查密码长度
            length_category = f"{len(password)}字符"
            analysis['password_patterns'][length_category] = analysis['password_patterns'].get(length_category, 0) + 1
            
            # 检查密码类型
            if password.isdigit():
                analysis['password_patterns']['纯数字'] = analysis['password_patterns'].get('纯数字', 0) + 1
            elif password.isalpha():
                analysis['password_patterns']['纯字母'] = analysis['password_patterns'].get('纯字母', 0) + 1
            elif any(c.isdigit() for c in password) and any(c.isalpha() for c in password):
                analysis['password_patterns']['字母数字混合'] = analysis['password_patterns'].get('字母数字混合', 0) + 1
        
        return analysis
    
    def _generate_summary(self, credentials: List[Dict], stats: Dict, analysis: Dict) -> str:
        """
        生成爆破摘要
        
        Args:
            credentials: 凭据列表
            stats: 统计信息
            analysis: 分析结果
            
        Returns:
            爆破摘要字符串
        """
        summary_parts = []
        
        success_count = len(credentials)
        total_tries = stats.get('total_tries', 0)
        success_rate = analysis.get('success_rate', 0)
        
        if success_count > 0:
            summary_parts.append(f"成功破解 {success_count} 个凭据")
            
            if total_tries > 0:
                summary_parts.append(f"成功率: {success_rate:.2f}%")
            
            # 弱密码统计
            weak_count = len(analysis.get('weak_passwords', []))
            if weak_count > 0:
                summary_parts.append(f"{weak_count} 个弱密码")
            
            # 最常见的用户名
            common_usernames = analysis.get('common_usernames', [])
            if common_usernames:
                top_username = common_usernames[0][0]
                summary_parts.append(f"最常见用户名: {top_username}")
        else:
            summary_parts.append("未成功破解任何凭据")
            
            if total_tries > 0:
                summary_parts.append(f"尝试了 {total_tries} 次")
        
        return '，'.join(summary_parts)
    
    def attack_ssh(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        SSH爆破的便捷方法
        
        Args:
            target: 目标主机
            **kwargs: 其他参数
            
        Returns:
            爆破结果
        """
        return self.execute(
            target=target,
            service='ssh',
            port=kwargs.get('port', 22),
            **kwargs
        )
    
    def attack_ftp(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        FTP爆破的便捷方法
        
        Args:
            target: 目标主机
            **kwargs: 其他参数
            
        Returns:
            爆破结果
        """
        return self.execute(
            target=target,
            service='ftp',
            port=kwargs.get('port', 21),
            **kwargs
        )
    
    def attack_http_form(self, target: str, form_path: str, **kwargs) -> Dict[str, Any]:
        """
        HTTP表单爆破的便捷方法
        
        Args:
            target: 目标主机
            form_path: 表单路径
            **kwargs: 其他参数
            
        Returns:
            爆破结果
        """
        service = f"http-post-form:{form_path}"
        return self.execute(
            target=target,
            service=service,
            port=kwargs.get('port', 80),
            **kwargs
        )
    
    def attack_rdp(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        RDP爆破的便捷方法
        
        Args:
            target: 目标主机
            **kwargs: 其他参数
            
        Returns:
            爆破结果
        """
        return self.execute(
            target=target,
            service='rdp',
            port=kwargs.get('port', 3389),
            **kwargs
        )
    
    def quick_attack(self, target: str, service: str, username: str = 'admin') -> Dict[str, Any]:
        """
        快速爆破（使用常见密码）
        
        Args:
            target: 目标主机
            service: 服务类型
            username: 用户名
            
        Returns:
            爆破结果
        """
        common_passwords = ['password', '123456', 'admin', 'root', '12345', 'qwerty']
        
        return self.execute(
            target=target,
            service=service,
            username=username,
            password=','.join(common_passwords),
            threads=4,
            exit_on_first=True
        )