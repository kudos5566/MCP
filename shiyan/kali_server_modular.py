#!/usr/bin/env python3
"""Kali Linux安全工具集成平台 - 模块化版本

使用模块化的API路由系统，将路由按功能分组到不同的模块中。
"""

import argparse
import time
import sys
from flask import Flask, jsonify, request
from config import logger
# 版本信息
__version__ = "1.2.0"

def get_version_info():
    """获取版本信息"""
    return {
        "version": __version__,
        "description": "Kali Linux安全工具集成平台",
        "build_date": "2024-01-15"
    }
from config import config
from api_routes import register_routes

# 使用配置中的日志记录器

# 记录启动时间
start_time = time.time()
logger.info(f"Kali安全工具平台 v{__version__} 启动中...")

# 创建Flask应用
app = Flask(__name__)

# 注册所有模块化路由
register_routes(app)

# 添加根路径路由
@app.route('/', methods=['GET'])
def root():
    """根路径，返回API信息"""
    version_info = get_version_info()
    return {
        'message': 'Kali Linux Tools API Server',
        'version': version_info['version'],
        'description': version_info['description'],
        'status': 'running',
        'endpoints': {
            'tools': '/api/tools/*',
            'reports': '/api/reports',
            'health': '/health',
            'admin': '/api/version, /api/statistics, /api/config'
        },
        'documentation': 'https://github.com/your-repo/kali-tools-api'
    }

# MCP兼容性路由（保留原有功能）
@app.route('/mcp/capabilities', methods=['GET'])
def get_capabilities():
    """返回MCP工具能力信息"""
    return {
        'tools': [
            {
                'name': 'nmap',
                'description': 'Network discovery and security auditing',
                'inputSchema': {
                    'type': 'object',
                    'properties': {
                        'target': {'type': 'string', 'description': 'Target IP or hostname'},
                        'scan_type': {'type': 'string', 'description': 'Scan type'},
                        'additional_args': {'type': 'string', 'description': 'Additional arguments'}
                    },
                    'required': ['target']
                }
            },
            {
                'name': 'gobuster',
                'description': 'Directory and file brute-forcing',
                'inputSchema': {
                    'type': 'object',
                    'properties': {
                        'url': {'type': 'string', 'description': 'Target URL'},
                        'wordlist': {'type': 'string', 'description': 'Wordlist path'},
                        'extensions': {'type': 'string', 'description': 'File extensions'}
                    },
                    'required': ['url']
                }
            },
            {
                'name': 'nikto',
                'description': 'Web server vulnerability scanner',
                'inputSchema': {
                    'type': 'object',
                    'properties': {
                        'host': {'type': 'string', 'description': 'Target host'},
                        'port': {'type': 'integer', 'description': 'Target port'},
                        'ssl': {'type': 'boolean', 'description': 'Use SSL'}
                    },
                    'required': ['host']
                }
            }
        ]
    }

@app.route('/mcp/tools/kali_tools/<tool_name>', methods=['POST'])
def execute_tool(tool_name):
    """MCP工具执行接口"""
    # 将MCP请求转发到相应的工具路由
    tool_routes = {
        'nmap': '/api/tools/nmap',
        'gobuster': '/api/tools/gobuster',
        'nikto': '/api/tools/nikto',
        'sqlmap': '/api/tools/sqlmap',
        'hydra': '/api/tools/hydra',
        'john': '/api/tools/john',
        'wpscan': '/api/tools/wpscan',
        'urlfinder': '/api/tools/urlfinder'
    }
    
    if tool_name not in tool_routes:
        return jsonify({'error': f'Tool {tool_name} not supported'}), 400
    
    # 这里可以添加MCP特定的处理逻辑
    # 目前直接返回工具路由信息
    return jsonify({
        'message': f'Use {tool_routes[tool_name]} endpoint for {tool_name}',
        'tool': tool_name,
        'endpoint': tool_routes[tool_name]
    })

# 错误处理
@app.errorhandler(404)
def not_found(error):
    """404错误处理"""
    return jsonify({
        'error': 'Endpoint not found',
        'message': 'The requested endpoint does not exist',
        'available_endpoints': {
            'tools': '/api/tools/*',
            'reports': '/api/reports',
            'health': '/health',
            'admin': '/api/version, /api/statistics'
        }
    }), 404

@app.errorhandler(500)
def internal_error(error):
    """500错误处理"""
    logger.error(f'Internal server error: {str(error)}')
    return jsonify({
        'error': 'Internal server error',
        'message': 'An unexpected error occurred on the server'
    }), 500

@app.errorhandler(400)
def bad_request(error):
    """400错误处理"""
    return jsonify({
        'error': 'Bad request',
        'message': 'The request was invalid or malformed'
    }), 400

# 请求日志中间件
@app.before_request
def log_request_info():
    """记录请求信息"""
    logger.debug(f'Request: {request.method} {request.url}')

@app.after_request
def log_response_info(response):
    """记录响应信息"""
    logger.debug(f'Response: {request.method} {request.url} - {response.status_code}')
    return response

def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description="Run the Kali Linux API Server (Modular Version)")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=config.API_PORT, help=f"Port for the API server (default: {config.API_PORT})")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host for the API server (default: 0.0.0.0)")
    return parser.parse_args()

def main():
    """主函数"""
    args = parse_args()
    
    # 使用config模块更新配置
    config.update_from_args(args)
    
    logger.info(f"Starting Kali Linux Tools API Server (Modular) on {args.host}:{config.API_PORT}")
    logger.info(f"Debug mode: {config.DEBUG_MODE}")
    logger.info(f"Available routes:")
    logger.info(f"  - Tools: /api/tools/*")
    logger.info(f"  - Reports: /api/reports")
    logger.info(f"  - Health: /health")
    logger.info(f"  - Admin: /api/version, /api/statistics")
    
    try:
        app.run(host=args.host, port=config.API_PORT, debug=config.DEBUG_MODE)
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()