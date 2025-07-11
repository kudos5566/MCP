#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
John the Ripper密码破解工具包装器

提供John the Ripper密码哈希破解工具的专门封装
支持多种哈希类型、字典攻击、暴力破解等
包含破解结果分析和密码强度评估功能
"""

import re
import os
import tempfile
from typing import Dict, Any, List

from .base_wrapper import BaseToolWrapper
from config import config


class JohnWrapper(BaseToolWrapper):
    """
    John the Ripper密码破解工具包装器
    
    支持MD5、SHA1、SHA256、NTLM等多种哈希类型破解
    自动识别哈希类型并选择合适的破解策略
    """
    
    def __init__(self):
        super().__init__('john')
        self.default_wordlist = config.JOHN_DEFAULT_WORDLIST
        self.session_dir = tempfile.gettempdir()
    
    def validate_params(self, **kwargs) -> Dict[str, Any]:
        """
        验证John参数
        
        Args:
            hash_file: 哈希文件路径
            hash_string: 单个哈希字符串
            hash_type: 哈希类型
            wordlist: 字典文件路径
            mode: 破解模式
            rules: 规则文件
            
        Returns:
            验证结果
        """
        hash_file = kwargs.get('hash_file', '')
        hash_string = kwargs.get('hash_string', '')
        hash_type = kwargs.get('hash_type', '')
        wordlist = kwargs.get('wordlist', '')
        mode = kwargs.get('mode', 'wordlist')
        
        # 验证输入（哈希文件或哈希字符串至少需要一个）
        if not hash_file and not hash_string:
            return {'success': False, 'error': '需要指定哈希文件或哈希字符串'}
        
        # 验证哈希文件
        if hash_file and not os.path.isfile(hash_file):
            return {'success': False, 'error': f'哈希文件不存在: {hash_file}'}
        
        # 验证哈希类型
        if hash_type:
            supported_types = [
                'md5', 'sha1', 'sha256', 'sha512', 'ntlm', 'lm', 'des',
                'md5crypt', 'sha256crypt', 'sha512crypt', 'bcrypt', 'scrypt',
                'mysql', 'mysql-sha1', 'mssql', 'oracle', 'postgres'
            ]
            
            if hash_type.lower() not in supported_types:
                return {'success': False, 'error': f'不支持的哈希类型，支持: {", ".join(supported_types)}'}
        
        # 验证破解模式
        valid_modes = ['wordlist', 'incremental', 'single', 'external']
        if mode not in valid_modes:
            return {'success': False, 'error': f'无效的破解模式，支持: {", ".join(valid_modes)}'}
        
        # 验证字典文件
        if wordlist and not os.path.isfile(wordlist):
            self.logger.warning(f"字典文件不存在: {wordlist}")
        
        return {'success': True}
    
    def build_command(self, **kwargs) -> str:
        """
        构建John命令
        
        Args:
            **kwargs: John参数
            
        Returns:
            完整的John命令
        """
        hash_file = kwargs.get('hash_file', '')
        hash_string = kwargs.get('hash_string', '')
        hash_type = kwargs.get('hash_type', '')
        wordlist = kwargs.get('wordlist', self.default_wordlist)
        mode = kwargs.get('mode', 'wordlist')
        rules = kwargs.get('rules', '')
        session = kwargs.get('session', 'default')
        additional_args = kwargs.get('additional_args', '')
        
        # 如果提供了哈希字符串，创建临时文件
        if hash_string and not hash_file:
            hash_file = self._create_temp_hash_file(hash_string)
        
        # 构建基础命令
        command_parts = ['john']
        
        # 添加哈希类型
        if hash_type:
            command_parts.extend(['--format', hash_type])
        
        # 添加破解模式
        if mode == 'wordlist':
            if wordlist:
                command_parts.extend(['--wordlist', wordlist])
            else:
                command_parts.append('--wordlist')
        elif mode == 'incremental':
            command_parts.append('--incremental')
        elif mode == 'single':
            command_parts.append('--single')
        elif mode == 'external':
            command_parts.append('--external')
        
        # 添加规则
        if rules:
            command_parts.extend(['--rules', rules])
        
        # 添加会话名称
        command_parts.extend(['--session', session])
        
        # 添加哈希文件
        command_parts.append(hash_file)
        
        # 添加附加参数
        if additional_args:
            command_parts.append(additional_args)
        
        return ' '.join(command_parts)
    
    def parse_output(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """
        解析John输出
        
        Args:
            stdout: John标准输出
            stderr: John错误输出
            
        Returns:
            解析后的结果
        """
        result = super().parse_output(stdout, stderr)
        
        # 解析破解的密码
        cracked_passwords = self._parse_cracked_passwords(stdout)
        
        # 解析哈希信息
        hash_info = self._parse_hash_info(stdout)
        
        # 解析破解统计
        stats = self._parse_crack_stats(stdout, stderr)
        
        # 分析密码强度
        password_analysis = self._analyze_passwords(cracked_passwords)
        
        result.update({
            'cracked_passwords': cracked_passwords,
            'hash_info': hash_info,
            'crack_stats': stats,
            'password_analysis': password_analysis,
            'summary': self._generate_summary(cracked_passwords, hash_info, password_analysis)
        })
        
        return result
    
    def _create_temp_hash_file(self, hash_string: str) -> str:
        """
        创建临时哈希文件
        
        Args:
            hash_string: 哈希字符串
            
        Returns:
            临时文件路径
        """
        temp_file = os.path.join(self.session_dir, 'temp_hashes.txt')
        
        try:
            with open(temp_file, 'w') as f:
                f.write(hash_string + '\n')
            return temp_file
        except Exception as e:
            self.logger.error(f"创建临时哈希文件失败: {e}")
            return ''
    
    def _parse_cracked_passwords(self, output: str) -> List[Dict[str, Any]]:
        """
        解析破解的密码
        
        Args:
            output: John输出
            
        Returns:
            破解的密码列表
        """
        passwords = []
        
        # 匹配破解成功的密码
        # 格式: username:password (hash)
        crack_pattern = r'([^:]+):([^\s]+)\s+\(([^)]+)\)'
        
        for match in re.finditer(crack_pattern, output):
            username = match.group(1)
            password = match.group(2)
            hash_value = match.group(3)
            
            passwords.append({
                'username': username,
                'password': password,
                'hash': hash_value,
                'status': 'cracked'
            })
        
        # 匹配简单格式的密码
        # 格式: password
        simple_pattern = r'^([a-zA-Z0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>?]+)$'
        
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            if line and re.match(simple_pattern, line):
                # 检查是否已经在结果中
                if not any(p['password'] == line for p in passwords):
                    passwords.append({
                        'password': line,
                        'status': 'cracked'
                    })
        
        return passwords
    
    def _parse_hash_info(self, output: str) -> Dict[str, Any]:
        """
        解析哈希信息
        
        Args:
            output: John输出
            
        Returns:
            哈希信息
        """
        hash_info = {}
        
        # 匹配加载的哈希数量
        loaded_pattern = r'Loaded\s+(\d+)\s+password\s+hash'
        loaded_match = re.search(loaded_pattern, output)
        if loaded_match:
            hash_info['loaded_hashes'] = int(loaded_match.group(1))
        
        # 匹配哈希类型
        format_pattern = r'Using\s+default\s+input\s+encoding:\s+([^\n]+)'
        format_match = re.search(format_pattern, output)
        if format_match:
            hash_info['encoding'] = format_match.group(1).strip()
        
        # 匹配检测到的哈希格式
        detected_pattern = r'Detected\s+hash\s+type:\s+"([^"]+)"'
        detected_match = re.search(detected_pattern, output)
        if detected_match:
            hash_info['detected_format'] = detected_match.group(1)
        
        # 匹配会话信息
        session_pattern = r'Session\s+completed'
        if re.search(session_pattern, output):
            hash_info['session_status'] = 'completed'
        elif 'Interrupted' in output:
            hash_info['session_status'] = 'interrupted'
        else:
            hash_info['session_status'] = 'running'
        
        return hash_info
    
    def _parse_crack_stats(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """
        解析破解统计信息
        
        Args:
            stdout: 标准输出
            stderr: 错误输出
            
        Returns:
            统计信息
        """
        stats = {}
        
        output = stdout + stderr
        
        # 匹配尝试次数
        tries_pattern = r'(\d+)\s+password\s+hashes\s+cracked,\s+(\d+)\s+left'
        tries_match = re.search(tries_pattern, output)
        if tries_match:
            stats['cracked_count'] = int(tries_match.group(1))
            stats['remaining_count'] = int(tries_match.group(2))
        
        # 匹配速度信息
        speed_pattern = r'(\d+)\s+c/s\s+real,\s+(\d+)\s+c/s\s+virtual'
        speed_match = re.search(speed_pattern, output)
        if speed_match:
            stats['real_speed'] = int(speed_match.group(1))
            stats['virtual_speed'] = int(speed_match.group(2))
        
        # 匹配时间信息
        time_pattern = r'(\d+):(\d+):(\d+)\s+\((\d+)\)'
        time_match = re.search(time_pattern, output)
        if time_match:
            hours = int(time_match.group(1))
            minutes = int(time_match.group(2))
            seconds = int(time_match.group(3))
            stats['elapsed_time'] = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            stats['elapsed_seconds'] = hours * 3600 + minutes * 60 + seconds
        
        # 匹配进度信息
        progress_pattern = r'(\d+)%\s+\((\d+)/(\d+)\)'
        progress_match = re.search(progress_pattern, output)
        if progress_match:
            stats['progress_percent'] = int(progress_match.group(1))
            stats['current_position'] = int(progress_match.group(2))
            stats['total_positions'] = int(progress_match.group(3))
        
        return stats
    
    def _analyze_passwords(self, passwords: List[Dict]) -> Dict[str, Any]:
        """
        分析密码强度
        
        Args:
            passwords: 密码列表
            
        Returns:
            密码分析结果
        """
        analysis = {
            'total_cracked': len(passwords),
            'length_distribution': {},
            'character_types': {
                'lowercase': 0,
                'uppercase': 0,
                'digits': 0,
                'special': 0,
                'mixed': 0
            },
            'common_passwords': [],
            'weak_passwords': [],
            'strength_distribution': {
                'very_weak': 0,
                'weak': 0,
                'medium': 0,
                'strong': 0
            }
        }
        
        # 常见弱密码列表
        common_weak = [
            'password', '123456', '12345678', 'qwerty', 'abc123',
            'password123', 'admin', 'root', 'user', 'guest', 'test'
        ]
        
        for pwd_entry in passwords:
            password = pwd_entry.get('password', '')
            if not password:
                continue
            
            # 长度分布
            length = len(password)
            length_category = f"{length}字符"
            analysis['length_distribution'][length_category] = analysis['length_distribution'].get(length_category, 0) + 1
            
            # 字符类型分析
            has_lower = any(c.islower() for c in password)
            has_upper = any(c.isupper() for c in password)
            has_digit = any(c.isdigit() for c in password)
            has_special = any(not c.isalnum() for c in password)
            
            type_count = sum([has_lower, has_upper, has_digit, has_special])
            
            if type_count >= 3:
                analysis['character_types']['mixed'] += 1
            elif has_special:
                analysis['character_types']['special'] += 1
            elif has_digit:
                analysis['character_types']['digits'] += 1
            elif has_upper:
                analysis['character_types']['uppercase'] += 1
            else:
                analysis['character_types']['lowercase'] += 1
            
            # 检查常见密码
            if password.lower() in common_weak:
                analysis['common_passwords'].append(password)
            
            # 强度评估
            strength = self._assess_password_strength(password)
            analysis['strength_distribution'][strength] += 1
            
            if strength in ['very_weak', 'weak']:
                analysis['weak_passwords'].append({
                    'password': password,
                    'strength': strength,
                    'username': pwd_entry.get('username', '')
                })
        
        return analysis
    
    def _assess_password_strength(self, password: str) -> str:
        """
        评估密码强度
        
        Args:
            password: 密码
            
        Returns:
            强度级别
        """
        if len(password) < 6:
            return 'very_weak'
        
        score = 0
        
        # 长度评分
        if len(password) >= 8:
            score += 1
        if len(password) >= 12:
            score += 1
        
        # 字符类型评分
        if any(c.islower() for c in password):
            score += 1
        if any(c.isupper() for c in password):
            score += 1
        if any(c.isdigit() for c in password):
            score += 1
        if any(not c.isalnum() for c in password):
            score += 1
        
        # 复杂性评分
        if not password.isdigit() and not password.isalpha():
            score += 1
        
        if score <= 2:
            return 'very_weak'
        elif score <= 4:
            return 'weak'
        elif score <= 6:
            return 'medium'
        else:
            return 'strong'
    
    def _generate_summary(self, passwords: List[Dict], hash_info: Dict, analysis: Dict) -> str:
        """
        生成破解摘要
        
        Args:
            passwords: 密码列表
            hash_info: 哈希信息
            analysis: 密码分析
            
        Returns:
            破解摘要字符串
        """
        summary_parts = []
        
        cracked_count = len(passwords)
        loaded_hashes = hash_info.get('loaded_hashes', 0)
        weak_count = len(analysis.get('weak_passwords', []))
        
        if cracked_count > 0:
            summary_parts.append(f"成功破解 {cracked_count} 个密码")
            
            if loaded_hashes > 0:
                success_rate = (cracked_count / loaded_hashes) * 100
                summary_parts.append(f"成功率: {success_rate:.1f}%")
            
            if weak_count > 0:
                summary_parts.append(f"{weak_count} 个弱密码")
            
            # 最常见的密码长度
            length_dist = analysis.get('length_distribution', {})
            if length_dist:
                most_common_length = max(length_dist.items(), key=lambda x: x[1])[0]
                summary_parts.append(f"最常见长度: {most_common_length}")
        else:
            summary_parts.append("未成功破解任何密码")
            
            if loaded_hashes > 0:
                summary_parts.append(f"共 {loaded_hashes} 个哈希")
        
        return '，'.join(summary_parts)
    
    def crack_hash(self, hash_string: str, hash_type: str = '', **kwargs) -> Dict[str, Any]:
        """
        破解单个哈希的便捷方法
        
        Args:
            hash_string: 哈希字符串
            hash_type: 哈希类型
            **kwargs: 其他参数
            
        Returns:
            破解结果
        """
        return self.execute(
            hash_string=hash_string,
            hash_type=hash_type,
            mode='wordlist',
            wordlist=self.default_wordlist,
            **kwargs
        )
    
    def crack_file(self, hash_file: str, **kwargs) -> Dict[str, Any]:
        """
        破解哈希文件的便捷方法
        
        Args:
            hash_file: 哈希文件路径
            **kwargs: 其他参数
            
        Returns:
            破解结果
        """
        return self.execute(
            hash_file=hash_file,
            mode='wordlist',
            wordlist=self.default_wordlist,
            **kwargs
        )
    
    def quick_crack(self, hash_string: str, hash_type: str = '') -> Dict[str, Any]:
        """
        快速破解（使用常见密码）
        
        Args:
            hash_string: 哈希字符串
            hash_type: 哈希类型
            
        Returns:
            破解结果
        """
        return self.execute(
            hash_string=hash_string,
            hash_type=hash_type,
            mode='single',
            session='quick'
        )
    
    def incremental_crack(self, hash_string: str, hash_type: str = '') -> Dict[str, Any]:
        """
        增量破解（暴力破解）
        
        Args:
            hash_string: 哈希字符串
            hash_type: 哈希类型
            
        Returns:
            破解结果
        """
        return self.execute(
            hash_string=hash_string,
            hash_type=hash_type,
            mode='incremental',
            session='incremental'
        )