#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
命令执行模块

提供安全、可靠的系统命令执行功能，包括：
- 命令执行逻辑
- 超时处理
- 输出流管理
- 编码处理
- 异常处理
"""

import subprocess
import threading
import time
import traceback
from typing import Dict, Any

# 导入配置和日志
from config import COMMAND_TIMEOUT, logger


class CommandExecutor:
    """
    命令执行器类
    
    提供安全、可靠的系统命令执行功能，支持：
    - 智能超时管理
    - 实时输出流读取
    - 多编码格式支持
    - 优雅的进程终止
    - 部分结果保留
    """
    
    def __init__(self, command: str, timeout: int = COMMAND_TIMEOUT):
        """
        初始化命令执行器
        
        Args:
            command: 要执行的命令
            timeout: 超时时间（秒），默认使用配置值
        """
        self.command = command
        self.timeout = timeout
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.stdout_thread = None
        self.stderr_thread = None
        self.return_code = None
        self.timed_out = False
    
    def _read_stdout(self):
        """
        线程函数：持续读取标准输出
        
        支持多种编码格式，确保输出正确解码
        """
        try:
            for line in iter(self.process.stdout.readline, b''):
                decoded_line = self._decode_line(line)
                self.stdout_data += decoded_line
        except Exception as e:
            logger.error(f"读取标准输出时发生错误: {e}")
    
    def _read_stderr(self):
        """
        线程函数：持续读取标准错误输出
        
        支持多种编码格式，确保错误信息正确解码
        """
        try:
            for line in iter(self.process.stderr.readline, b''):
                decoded_line = self._decode_line(line)
                self.stderr_data += decoded_line
        except Exception as e:
            logger.error(f"读取标准错误输出时发生错误: {e}")
    
    def _decode_line(self, line: bytes) -> str:
        """
        智能解码字节数据为字符串
        
        Args:
            line: 字节数据
            
        Returns:
            str: 解码后的字符串
        """
        # 尝试多种编码格式，优先考虑系统默认编码
        encodings = ['utf-8', 'gbk', 'gb2312', 'cp936', 'latin-1']
        
        for encoding in encodings:
            try:
                return line.decode(encoding)
            except UnicodeDecodeError:
                continue
        
        # 如果所有编码都失败，使用错误处理模式
        return line.decode('utf-8', errors='replace')
    
    def _terminate_process(self):
        """
        优雅地终止进程
        
        首先尝试正常终止，如果失败则强制杀死进程
        """
        try:
            # 尝试优雅终止
            self.process.terminate()
            try:
                self.process.wait(timeout=5)  # 给进程5秒时间终止
                logger.info("进程已优雅终止")
            except subprocess.TimeoutExpired:
                # 如果进程不响应终止信号，强制杀死
                logger.warning("进程未响应终止信号，强制杀死进程")
                self.process.kill()
                self.process.wait()  # 等待进程完全结束
        except Exception as e:
            logger.error(f"终止进程时发生错误: {e}")
    
    def execute(self) -> Dict[str, Any]:
        """
        执行命令并处理超时
        
        Returns:
            Dict[str, Any]: 执行结果，包含以下字段：
                - stdout: 标准输出
                - stderr: 标准错误输出
                - return_code: 返回码
                - success: 是否成功
                - timed_out: 是否超时
                - partial_results: 是否有部分结果
        """
        logger.info(f"开始执行命令: {self.command}")
        
        try:
            # 启动进程
            self.process = subprocess.Popen(
                self.command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,  # 使用二进制模式，手动处理编码
                bufsize=0  # 无缓冲，避免二进制模式下的行缓冲警告
            )
            
            # 启动线程持续读取输出
            self.stdout_thread = threading.Thread(target=self._read_stdout)
            self.stderr_thread = threading.Thread(target=self._read_stderr)
            self.stdout_thread.daemon = True
            self.stderr_thread.daemon = True
            self.stdout_thread.start()
            self.stderr_thread.start()
            
            # 等待进程完成或超时
            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                # 进程正常完成，等待线程结束
                self.stdout_thread.join()
                self.stderr_thread.join()
                logger.info(f"命令执行完成，返回码: {self.return_code}")
            except subprocess.TimeoutExpired:
                # 进程超时，但可能有部分结果
                self.timed_out = True
                logger.warning(f"命令在 {self.timeout} 秒后超时，正在终止进程")
                
                # 终止进程
                self._terminate_process()
                self.return_code = -1
            
            # 如果有输出，即使超时也认为是成功的（部分成功）
            success = True if self.timed_out and (self.stdout_data or self.stderr_data) else (self.return_code == 0)
            
            result = {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "partial_results": self.timed_out and (self.stdout_data or self.stderr_data)
            }
            
            logger.debug(f"命令执行结果: 成功={success}, 超时={self.timed_out}, 输出长度={len(self.stdout_data)}")
            return result
        
        except Exception as e:
            logger.error(f"执行命令时发生错误: {str(e)}")
            logger.error(traceback.format_exc())
            return {
                "stdout": self.stdout_data,
                "stderr": f"执行命令时发生错误: {str(e)}" + "\n" + self.stderr_data,
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": bool(self.stdout_data or self.stderr_data)
            }


def execute_command(command: str, timeout: int = None) -> Dict[str, Any]:
    """
    便捷的命令执行函数
    
    Args:
        command: 要执行的命令
        timeout: 超时时间（秒），默认使用配置值
        
    Returns:
        Dict[str, Any]: 执行结果
    """
    if timeout is None:
        timeout = COMMAND_TIMEOUT
    
    executor = CommandExecutor(command, timeout)
    return executor.execute()


def is_dangerous_command(command: str) -> bool:
    """
    检查命令是否包含危险操作
    
    Args:
        command: 要检查的命令
        
    Returns:
        bool: 如果命令危险返回True
    """
    dangerous_patterns = [
        'rm -rf', 'format', 'del /f', 'shutdown', 'reboot', 'halt',
        'mkfs', 'fdisk', 'dd if=', 'wipefs', 'shred',
        '> /dev/', 'chmod 777', 'chown root'
    ]
    
    command_lower = command.lower()
    for pattern in dangerous_patterns:
        if pattern in command_lower:
            return True
    
    return False


def execute_safe_command(command: str, timeout: int = None, allow_dangerous: bool = False) -> Dict[str, Any]:
    """
    安全的命令执行函数
    
    Args:
        command: 要执行的命令
        timeout: 超时时间（秒）
        allow_dangerous: 是否允许危险命令
        
    Returns:
        Dict[str, Any]: 执行结果
    """
    # 安全检查
    if not allow_dangerous and is_dangerous_command(command):
        logger.error(f"检测到危险命令: {command}")
        return {
            "stdout": "",
            "stderr": "检测到潜在危险命令，执行被拒绝",
            "return_code": -1,
            "success": False,
            "timed_out": False,
            "partial_results": False
        }
    
    return execute_command(command, timeout)


# 测试代码
if __name__ == "__main__":
    print("命令执行模块测试")
    print("=" * 50)
    
    # 测试基本命令执行
    print("\n1. 测试基本命令执行:")
    result = execute_command("echo Hello World")
    print(f"输出: {result['stdout'].strip()}")
    print(f"成功: {result['success']}")
    
    # 测试危险命令检测
    print("\n2. 测试危险命令检测:")
    dangerous_result = execute_safe_command("rm -rf /")
    print(f"危险命令结果: {dangerous_result['stderr']}")
    
    # 测试超时处理
    print("\n3. 测试超时处理:")
    timeout_result = execute_command("ping -n 10 127.0.0.1", timeout=2)
    print(f"超时: {timeout_result['timed_out']}")
    print(f"部分结果: {timeout_result['partial_results']}")
    
    print("\n命令执行模块测试完成")