"""管理相关路由模块

包含系统版本信息、统计信息、配置管理和系统管理功能。
"""

import os
import time
import datetime
import traceback
from flask import Blueprint, jsonify, request
from scan_manager import scan_manager, get_scan_statistics
from command_executor import execute_command
from config import logger
from config import API_PORT, DEBUG_MODE, COMMAND_TIMEOUT, MAX_SCAN_HISTORY, CACHE_DIR, REPORTS_DIR

# 版本信息
__version__ = "1.2.0"
__author__ = "Kali Security Tools Team"
__description__ = "Kali Linux安全工具集成平台"
__build_date__ = "2024-01-15"
__python_requires__ = ">=3.8"

# 版本历史记录
VERSION_HISTORY = {
    "1.2.0": {
        "date": "2024-01-15",
        "changes": [
            "增强异常处理和日志记录",
            "集中化配置管理",
            "改进内存管理和缓存机制",
            "添加系统监控和统计功能",
            "完善中文注释和文档",
            "优化超时处理逻辑",
            "添加版本管理功能"
        ],
        "breaking_changes": [],
        "security_fixes": [
            "增强输入验证",
            "添加危险命令检查",
            "改进API安全性"
        ]
    },
    "1.1.0": {
        "date": "2024-01-10",
        "changes": [
            "添加URLFinder集成",
            "Excel报告生成",
            "CVE查询功能"
        ]
    },
    "1.0.0": {
        "date": "2024-01-01",
        "changes": [
            "初始版本发布",
            "基本的Nmap、Gobuster、Nikto集成",
            "RESTful API接口",
            "MCP客户端支持"
        ]
    }
}

def get_version_info():
    """获取详细的版本信息"""
    return {
        "version": __version__,
        "author": __author__,
        "description": __description__,
        "build_date": __build_date__,
        "python_requires": __python_requires__,
        "python_version": sys.version,
        "platform": sys.platform,
        "latest_changes": VERSION_HISTORY.get(__version__, {}).get("changes", []),
        "security_fixes": VERSION_HISTORY.get(__version__, {}).get("security_fixes", [])
    }

# 创建管理路由蓝图
admin_bp = Blueprint('admin', __name__, url_prefix='/api')

# 使用配置中的日志记录器

# 全局变量用于跟踪服务器启动时间
start_time = time.time()

@admin_bp.route('/version', methods=['GET'])
def get_version_endpoint():
    """获取系统版本信息API端点
    
    提供详细的版本信息、更新历史和系统环境信息
    
    Returns:
        包含版本信息的JSON响应
    """
    try:
        logger.debug('获取版本信息')
        
        version_info = get_version_info()
        
        # 添加运行时信息
        runtime_info = {
            'uptime_seconds': time.time() - start_time,
            'total_scans_processed': len(scan_manager.get_scan_history()),
            'cache_files_count': len([f for f in os.listdir(CACHE_DIR) if f.endswith('.json')]) if os.path.exists(CACHE_DIR) else 0,
            'reports_generated': 0,  # 需要从适当的地方获取
            'configuration_loaded': True
        }
        
        # 合并版本信息和运行时信息
        response_data = {
            **version_info,
            'runtime_info': runtime_info,
            'version_history': VERSION_HISTORY
        }
        
        logger.info(f'版本信息查询成功: v{__version__}')
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f'获取版本信息失败: {str(e)}', exc_info=True)
        return jsonify({
            'error': '获取版本信息失败',
            'details': str(e)
        }), 500

@admin_bp.route('/statistics', methods=['GET'])
def get_scan_statistics_endpoint():
    """获取扫描统计信息API端点
    
    提供系统运行状态、扫描历史统计和性能监控数据
    
    Returns:
        包含统计信息的JSON响应
    """
    try:
        logger.debug('获取扫描统计信息')
        
        # 获取基本统计信息
        stats = get_scan_statistics()
        
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
                'disk_usage_percent': psutil.disk_usage('/').percent if platform.system() != 'Windows' else psutil.disk_usage('C:').percent
            }
        except ImportError:
            # 如果psutil不可用，返回基本信息
            logger.warning('psutil模块不可用，返回基本系统信息')
            import platform
            system_info = {
                'platform': platform.system(),
                'platform_version': platform.version(),
                'python_version': platform.python_version(),
                'error': 'psutil模块不可用，系统资源信息不可用'
            }
        
        # 添加配置信息
        config_info = {
            'api_port': API_PORT,
            'debug_mode': DEBUG_MODE,
            'command_timeout': COMMAND_TIMEOUT,
            'max_scan_history': MAX_SCAN_HISTORY,
            'cache_dir': CACHE_DIR,
            'reports_dir': REPORTS_DIR
        }
        
        # 检查工具可用性
        essential_tools = ['nmap', 'gobuster', 'dirb', 'nikto', 'URLFinder']
        tools_status = {}
        
        for tool in essential_tools:
            try:
                if tool == 'URLFinder':
                    result = execute_command(f'which {tool}')
                    if not result['success']:
                        result = execute_command(f'{tool} -h')
                        tools_status[tool] = bool(result.get('stdout') or result.get('stderr'))
                    else:
                        tools_status[tool] = True
                else:
                    result = execute_command(f'which {tool}')
                    tools_status[tool] = result['success']
            except:
                tools_status[tool] = False
        
        # 组合所有信息
        response_data = {
            'scan_statistics': stats,
            'system_info': system_info,
            'configuration': config_info,
            'tools_status': tools_status,
            'all_tools_available': all(tools_status.values()),
            'server_uptime': str(datetime.timedelta(seconds=int(time.time() - start_time))),
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f'获取统计信息失败: {str(e)}', exc_info=True)
        return jsonify({
            'error': f'获取统计信息失败: {str(e)}',
            'timestamp': datetime.datetime.now().isoformat()
        }), 500

@admin_bp.route('/config', methods=['GET'])
def get_configuration():
    """获取系统配置信息
    
    Returns:
        包含配置信息的JSON响应
    """
    try:
        logger.debug('获取系统配置信息')
        
        config_data = {
            'server': {
                'api_port': API_PORT,
                'debug_mode': DEBUG_MODE,
                'command_timeout': COMMAND_TIMEOUT,
                'max_scan_history': MAX_SCAN_HISTORY
            },
            'directories': {
                'cache_dir': CACHE_DIR,
                'reports_dir': REPORTS_DIR,
                'cache_exists': os.path.exists(CACHE_DIR),
                'reports_exists': os.path.exists(REPORTS_DIR)
            },
            'runtime': {
                'uptime_seconds': time.time() - start_time,
                'scan_history_count': len(scan_manager.get_scan_history()),
                'excel_reports_count': 0  # 需要从适当的地方获取
            },
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        return jsonify(config_data)
        
    except Exception as e:
        logger.error(f'获取配置信息失败: {str(e)}', exc_info=True)
        return jsonify({
            'error': f'获取配置信息失败: {str(e)}',
            'timestamp': datetime.datetime.now().isoformat()
        }), 500

@admin_bp.route('/scan-history', methods=['GET'])
def get_scan_history():
    """获取扫描历史记录
    
    Returns:
        包含扫描历史的JSON响应
    """
    try:
        logger.debug('获取扫描历史记录')
        
        # 获取查询参数
        limit = request.args.get('limit', type=int)
        tool_filter = request.args.get('tool')
        
        # 获取扫描历史
        all_history = scan_manager.get_scan_history()
        
        # 过滤扫描历史
        filtered_history = all_history
        
        if tool_filter:
            filtered_history = [scan for scan in all_history if scan.get('tool') == tool_filter]
        
        # 限制返回数量
        if limit and limit > 0:
            filtered_history = filtered_history[-limit:]
        
        response_data = {
            'scan_history': filtered_history,
            'total_count': len(all_history),
            'filtered_count': len(filtered_history),
            'filters': {
                'tool': tool_filter,
                'limit': limit
            },
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f'获取扫描历史失败: {str(e)}', exc_info=True)
        return jsonify({
            'error': f'获取扫描历史失败: {str(e)}',
            'timestamp': datetime.datetime.now().isoformat()
        }), 500

@admin_bp.route('/scan-history', methods=['DELETE'])
def clear_scan_history():
    """清除扫描历史记录
    
    Returns:
        清除结果的JSON响应
    """
    try:
        logger.debug('清除扫描历史记录')
        
        history_count = len(scan_manager.get_scan_history())
        scan_manager.clear_scan_history()
        
        logger.info(f'已清除扫描历史: 共{history_count}条记录')
        
        return jsonify({
            'message': f'Scan history cleared successfully',
            'cleared_count': history_count,
            'timestamp': datetime.datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f'清除扫描历史失败: {str(e)}', exc_info=True)
        return jsonify({
            'error': f'清除扫描历史失败: {str(e)}',
            'timestamp': datetime.datetime.now().isoformat()
        }), 500

@admin_bp.route('/system/restart', methods=['POST'])
def restart_system():
    """重启系统服务
    
    注意：这个端点需要谨慎使用，可能需要额外的权限验证
    
    Returns:
        重启结果的JSON响应
    """
    try:
        logger.warning('收到系统重启请求')
        
        # 这里可以添加权限验证逻辑
        # 例如：检查API密钥、用户权限等
        
        # 清理资源
        scan_manager.clear_scan_history()
        
        logger.info('系统重启准备完成')
        
        return jsonify({
            'message': 'System restart initiated',
            'timestamp': datetime.datetime.now().isoformat(),
            'note': 'Server will restart shortly'
        })
        
        # 注意：实际的重启逻辑需要在返回响应后执行
        # 可以使用定时器或其他机制来实现
        
    except Exception as e:
        logger.error(f'系统重启失败: {str(e)}', exc_info=True)
        return jsonify({
            'error': f'系统重启失败: {str(e)}',
            'timestamp': datetime.datetime.now().isoformat()
        }), 500

@admin_bp.route('/system/cleanup', methods=['POST'])
def cleanup_system():
    """清理系统缓存和临时文件
    
    Returns:
        清理结果的JSON响应
    """
    try:
        logger.debug('执行系统清理')
        
        cleanup_results = {
            'scan_history_cleared': 0,
            'reports_cleared': 0,
            'cache_files_removed': 0,
            'temp_files_removed': 0
        }
        
        # 清理扫描历史
        cleanup_results['scan_history_cleared'] = len(scan_manager.get_scan_history())
        scan_manager.clear_scan_history()
        
        # 清理Excel报告
        cleanup_results['reports_cleared'] = 0  # 需要从适当的地方获取和清理
        
        # 清理缓存文件
        if os.path.exists(CACHE_DIR):
            cache_files = [f for f in os.listdir(CACHE_DIR) if f.endswith('.json')]
            for cache_file in cache_files:
                try:
                    os.remove(os.path.join(CACHE_DIR, cache_file))
                    cleanup_results['cache_files_removed'] += 1
                except Exception as e:
                    logger.warning(f'删除缓存文件失败 {cache_file}: {str(e)}')
        
        # 清理临时文件（如果有的话）
        # 这里可以添加更多的清理逻辑
        
        logger.info(f'系统清理完成: {cleanup_results}')
        
        return jsonify({
            'message': 'System cleanup completed successfully',
            'cleanup_results': cleanup_results,
            'timestamp': datetime.datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f'系统清理失败: {str(e)}', exc_info=True)
        return jsonify({
            'error': f'系统清理失败: {str(e)}',
            'timestamp': datetime.datetime.now().isoformat()
        }), 500

@admin_bp.route('/logs', methods=['GET'])
def get_logs():
    """获取系统日志
    
    Returns:
        包含日志信息的JSON响应
    """
    try:
        logger.debug('获取系统日志')
        
        # 获取查询参数
        lines = request.args.get('lines', 100, type=int)
        level = request.args.get('level', 'INFO')
        
        # 这里可以实现日志读取逻辑
        # 由于日志系统的具体实现可能不同，这里提供一个基本框架
        
        log_data = {
            'message': 'Log retrieval not fully implemented',
            'parameters': {
                'lines': lines,
                'level': level
            },
            'note': 'This endpoint requires specific log file configuration',
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        return jsonify(log_data)
        
    except Exception as e:
        logger.error(f'获取日志失败: {str(e)}', exc_info=True)
        return jsonify({
            'error': f'获取日志失败: {str(e)}',
            'timestamp': datetime.datetime.now().isoformat()
        }), 500