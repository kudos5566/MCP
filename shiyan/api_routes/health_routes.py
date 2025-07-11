"""健康检查路由模块

包含系统健康检查、工具状态检查和性能监控功能。
"""

import os
import time
import datetime
import traceback
from flask import Blueprint, jsonify
from command_executor import execute_command
from scan_manager import scan_manager
from config import logger
from config import CACHE_DIR, REPORTS_DIR

# 创建健康检查路由蓝图
health_bp = Blueprint('health', __name__)

# 使用配置中的日志记录器

# 全局变量用于跟踪服务器启动时间
start_time = time.time()

@health_bp.route('/health', methods=['GET'])
def health_check():
    """基本健康检查端点
    
    提供服务器基本状态和工具可用性检查
    
    Returns:
        包含健康状态信息的JSON响应
    """
    try:
        logger.debug('执行健康检查')
        
        # 检查必要工具是否安装
        essential_tools = ['nmap', 'gobuster', 'dirb', 'nikto', 'URLFinder']
        tools_status = {}
        
        for tool in essential_tools:
            try:
                # 对于URLFinder，尝试多种检查方式
                if tool == 'URLFinder':
                    # 首先尝试which命令
                    result = execute_command(f'which {tool}')
                    if not result['success']:
                        # 如果which失败，尝试直接运行工具查看帮助
                        result = execute_command(f'{tool} -h')
                        # URLFinder -h 通常会返回非0退出码但有输出，这表示工具存在
                        tools_status[tool] = bool(result.get('stdout') or result.get('stderr'))
                    else:
                        tools_status[tool] = True
                else:
                    result = execute_command(f'which {tool}')
                    tools_status[tool] = result['success']
            except Exception as e:
                logger.warning(f'检查工具 {tool} 时出错: {str(e)}')
                tools_status[tool] = False
        
        all_essential_tools_available = all(tools_status.values())
        
        # 检查缓存目录
        cache_accessible = os.path.exists(CACHE_DIR) and os.access(CACHE_DIR, os.W_OK)
        
        # 检查报告目录
        reports_accessible = os.path.exists(REPORTS_DIR) and os.access(REPORTS_DIR, os.W_OK)
        
        ai_status = 'removed'
        ai_provider = 'none'
        
        health_status = {
            'status': 'healthy' if all_essential_tools_available else 'degraded',
            'ai_status': ai_status,
            'ai_provider': ai_provider, 
            'message': 'Kali Linux Tools API Server is running',
            'tools_status': tools_status,
            'all_essential_tools_available': all_essential_tools_available,
            'cache_accessible': cache_accessible,
            'reports_accessible': reports_accessible,
            'scan_history_count': len(scan_manager.scan_history),
            'excel_reports_count': len(scan_manager.excel_reports),
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        # 如果有工具不可用，添加警告信息
        if not all_essential_tools_available:
            missing_tools = [tool for tool, available in tools_status.items() if not available]
            health_status['warnings'] = [f'以下工具不可用: {", ".join(missing_tools)}']
        
        return jsonify(health_status)
        
    except Exception as e:
        logger.error(f'健康检查失败: {str(e)}', exc_info=True)
        return jsonify({
            'status': 'unhealthy',
            'error': f'健康检查失败: {str(e)}',
            'timestamp': datetime.datetime.now().isoformat()
        }), 500

@health_bp.route('/health/detailed', methods=['GET'])
def detailed_health_check():
    """详细健康检查端点
    
    提供更详细的系统状态信息，包括系统资源使用情况
    
    Returns:
        包含详细健康状态信息的JSON响应
    """
    try:
        logger.debug('执行详细健康检查')
        
        # 获取基本健康状态
        basic_health = health_check().get_json()
        
        # 添加系统信息
        try:
            import psutil
            import platform
            
            system_info = {
                'platform': platform.system(),
                'platform_version': platform.version(),
                'python_version': platform.python_version(),
                'cpu_count': psutil.cpu_count(),
                'memory_total_gb': round(psutil.virtual_memory().total / 1024 / 1024 / 1024, 2),
                'memory_available_gb': round(psutil.virtual_memory().available / 1024 / 1024 / 1024, 2),
                'memory_usage_percent': psutil.virtual_memory().percent,
                'disk_usage_percent': psutil.disk_usage('/').percent if platform.system() != 'Windows' else psutil.disk_usage('C:').percent,
                'cpu_usage_percent': psutil.cpu_percent(interval=1)
            }
            
            basic_health['system_info'] = system_info
            
        except ImportError:
            logger.warning('psutil模块不可用，跳过系统信息收集')
            basic_health['system_info'] = {'error': 'psutil模块不可用'}
        
        # 添加服务器运行时间
        uptime_seconds = time.time() - start_time
        basic_health['server_uptime_seconds'] = uptime_seconds
        basic_health['server_uptime_formatted'] = str(datetime.timedelta(seconds=int(uptime_seconds)))
        
        # 检查扩展工具
        extended_tools = ['sqlmap', 'hydra', 'john', 'wpscan', 'enum4linux', 'metasploit']
        extended_tools_status = {}
        
        for tool in extended_tools:
            try:
                if tool == 'metasploit':
                    # 检查msfconsole
                    result = execute_command('which msfconsole')
                    extended_tools_status[tool] = result['success']
                else:
                    result = execute_command(f'which {tool}')
                    extended_tools_status[tool] = result['success']
            except Exception as e:
                logger.warning(f'检查扩展工具 {tool} 时出错: {str(e)}')
                extended_tools_status[tool] = False
        
        basic_health['extended_tools_status'] = extended_tools_status
        basic_health['all_extended_tools_available'] = all(extended_tools_status.values())
        
        return jsonify(basic_health)
        
    except Exception as e:
        logger.error(f'详细健康检查失败: {str(e)}', exc_info=True)
        return jsonify({
            'status': 'unhealthy',
            'error': f'详细健康检查失败: {str(e)}',
            'timestamp': datetime.datetime.now().isoformat()
        }), 500

@health_bp.route('/health/tools', methods=['GET'])
def tools_status():
    """工具状态检查端点
    
    专门检查所有安全工具的可用性状态
    
    Returns:
        包含工具状态信息的JSON响应
    """
    try:
        logger.debug('执行工具状态检查')
        
        # 所有支持的工具列表
        all_tools = {
            'essential': ['nmap', 'gobuster', 'dirb', 'nikto', 'URLFinder'],
            'extended': ['sqlmap', 'hydra', 'john', 'wpscan', 'enum4linux'],
            'framework': ['metasploit']
        }
        
        tools_status = {}
        
        for category, tools in all_tools.items():
            tools_status[category] = {}
            
            for tool in tools:
                try:
                    if tool == 'URLFinder':
                        # URLFinder特殊处理
                        result = execute_command(f'which {tool}')
                        if not result['success']:
                            result = execute_command(f'{tool} -h')
                            tools_status[category][tool] = {
                                'available': bool(result.get('stdout') or result.get('stderr')),
                                'version': 'unknown',
                                'path': 'unknown'
                            }
                        else:
                            tools_status[category][tool] = {
                                'available': True,
                                'version': 'unknown',
                                'path': result.get('stdout', '').strip()
                            }
                    elif tool == 'metasploit':
                        # Metasploit特殊处理
                        result = execute_command('which msfconsole')
                        if result['success']:
                            # 尝试获取版本信息
                            version_result = execute_command('msfconsole --version')
                            tools_status[category][tool] = {
                                'available': True,
                                'version': version_result.get('stdout', 'unknown').strip(),
                                'path': result.get('stdout', '').strip()
                            }
                        else:
                            tools_status[category][tool] = {
                                'available': False,
                                'version': 'N/A',
                                'path': 'N/A'
                            }
                    else:
                        # 标准工具处理
                        result = execute_command(f'which {tool}')
                        if result['success']:
                            # 尝试获取版本信息
                            version_result = execute_command(f'{tool} --version')
                            tools_status[category][tool] = {
                                'available': True,
                                'version': version_result.get('stdout', 'unknown').strip()[:100],  # 限制长度
                                'path': result.get('stdout', '').strip()
                            }
                        else:
                            tools_status[category][tool] = {
                                'available': False,
                                'version': 'N/A',
                                'path': 'N/A'
                            }
                            
                except Exception as e:
                    logger.warning(f'检查工具 {tool} 时出错: {str(e)}')
                    tools_status[category][tool] = {
                        'available': False,
                        'version': 'error',
                        'path': 'error',
                        'error': str(e)
                    }
        
        # 计算统计信息
        total_tools = sum(len(tools) for tools in all_tools.values())
        available_tools = sum(
            1 for category in tools_status.values() 
            for tool_info in category.values() 
            if tool_info['available']
        )
        
        response = {
            'tools_status': tools_status,
            'summary': {
                'total_tools': total_tools,
                'available_tools': available_tools,
                'availability_percentage': round((available_tools / total_tools) * 100, 2) if total_tools > 0 else 0
            },
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f'工具状态检查失败: {str(e)}', exc_info=True)
        return jsonify({
            'error': f'工具状态检查失败: {str(e)}',
            'timestamp': datetime.datetime.now().isoformat()
        }), 500

@health_bp.route('/health/quick', methods=['GET'])
def quick_health_check():
    """快速健康检查端点
    
    提供最基本的服务状态信息，响应速度最快
    
    Returns:
        包含基本状态信息的JSON响应
    """
    try:
        return jsonify({
            'status': 'healthy',
            'message': 'API Server is running',
            'timestamp': datetime.datetime.now().isoformat(),
            'uptime_seconds': time.time() - start_time
        })
        
    except Exception as e:
        logger.error(f'快速健康检查失败: {str(e)}', exc_info=True)
        return jsonify({
            'status': 'unhealthy',
            'error': f'快速健康检查失败: {str(e)}',
            'timestamp': datetime.datetime.now().isoformat()
        }), 500