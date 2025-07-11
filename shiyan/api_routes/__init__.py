"""API路由模块

将API路由按功能分组，提供模块化的路由管理。

模块结构:
- tool_routes.py: 工具相关路由
- report_routes.py: 报告相关路由  
- health_routes.py: 健康检查路由
- admin_routes.py: 管理相关路由
"""

from flask import Blueprint

# 导入各个路由模块
from .tool_routes import tool_bp
from .report_routes import report_bp
from .health_routes import health_bp
from .admin_routes import admin_bp

# 导出所有蓝图
__all__ = ['tool_bp', 'report_bp', 'health_bp', 'admin_bp']

def register_routes(app):
    """注册所有路由到Flask应用
    
    Args:
        app: Flask应用实例
    """
    app.register_blueprint(tool_bp)
    app.register_blueprint(report_bp)
    app.register_blueprint(health_bp)
    app.register_blueprint(admin_bp)