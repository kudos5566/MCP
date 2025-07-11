"""报告相关路由模块

包含报告下载、列表和管理功能。
"""

import traceback
from io import BytesIO
from flask import Blueprint, jsonify, send_file
from scan_manager import scan_manager
from config import logger

# 创建报告路由蓝图
report_bp = Blueprint('reports', __name__, url_prefix='/api')

# 使用配置中的日志记录器

@report_bp.route('/download-report/<report_id>', methods=['GET'])
def download_excel_report(report_id):
    """下载Excel扫描报告
    
    Args:
        report_id: 报告ID
        
    Returns:
        Excel文件或错误信息
    """
    try:
        import os
        from config import REPORTS_DIR
        
        # 首先尝试从内存中获取报告
        report_data = scan_manager.get_excel_report(report_id)
        
        if report_data is None:
            # 如果内存中没有，尝试从文件系统中读取
            filename = f'{report_id}.xlsx'
            file_path = os.path.join(REPORTS_DIR, filename)
            
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'rb') as f:
                        report_data = f.read()
                    logger.info(f'从文件系统读取报告: {file_path}')
                except Exception as file_error:
                    logger.error(f'读取报告文件失败: {file_path}, 错误: {str(file_error)}')
                    return jsonify({'error': 'Failed to read report file'}), 500
            else:
                logger.warning(f'报告未找到: {report_id} (内存和文件系统中都不存在)')
                return jsonify({'error': 'Report not found or expired'}), 404
        
        # 创建BytesIO对象
        output = BytesIO(report_data)
        output.seek(0)
        
        # 生成文件名
        filename = f'{report_id}.xlsx'
        
        logger.info(f'下载报告: {report_id}')
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        logger.error(f'下载报告失败: {report_id}, 错误: {str(e)}')
        logger.error(traceback.format_exc())
        return jsonify({
            'error': f'Server error: {str(e)}'
        }), 500

@report_bp.route('/reports', methods=['GET'])
def list_reports():
    """列出所有可用的Excel报告
    
    Returns:
        包含报告列表的JSON响应
    """
    try:
        import os
        from config import REPORTS_DIR
        
        reports = []
        
        # 列出内存中的报告
        for report_id in scan_manager.excel_reports.keys():
            reports.append({
                'report_id': report_id,
                'download_url': f'/api/download-report/{report_id}',
                'size_bytes': len(scan_manager.excel_reports[report_id]),
                'location': 'memory'
            })
        
        # 列出文件系统中的报告
        if os.path.exists(REPORTS_DIR):
            for filename in os.listdir(REPORTS_DIR):
                if filename.endswith('.xlsx'):
                    file_path = os.path.join(REPORTS_DIR, filename)
                    file_size = os.path.getsize(file_path)
                    file_mtime = os.path.getmtime(file_path)
                    
                    # 从文件名提取report_id（去掉.xlsx扩展名）
                    report_id = filename[:-5] if filename.endswith('.xlsx') else filename
                    
                    # 检查是否已经在内存列表中
                    memory_report_exists = any(r['report_id'] == report_id for r in reports)
                    
                    if not memory_report_exists:
                        reports.append({
                            'report_id': report_id,
                            'download_url': f'/api/download-report/{report_id}',
                            'size_bytes': file_size,
                            'location': 'file',
                            'file_path': file_path,
                            'modified_time': file_mtime
                        })
                    else:
                        # 更新已存在报告的信息
                        for report in reports:
                            if report['report_id'] == report_id:
                                report['location'] = 'both'
                                report['file_path'] = file_path
                                report['modified_time'] = file_mtime
                                break
        
        logger.info(f'列出报告: 共{len(reports)}个报告')
        return jsonify({
            'reports': reports,
            'total_count': len(reports),
            'reports_dir': REPORTS_DIR
        })
    except Exception as e:
        logger.error(f'列出报告失败: {str(e)}')
        logger.error(traceback.format_exc())
        return jsonify({
            'error': f'Server error: {str(e)}'
        }), 500

@report_bp.route('/reports/<report_id>', methods=['DELETE'])
def delete_report(report_id):
    """删除指定的报告
    
    Args:
        report_id: 报告ID
        
    Returns:
        删除结果的JSON响应
    """
    try:
        if report_id not in scan_manager.excel_reports:
            logger.warning(f'尝试删除不存在的报告: {report_id}')
            return jsonify({'error': 'Report not found'}), 404
        
        del scan_manager.excel_reports[report_id]
        logger.info(f'报告已删除: {report_id}')
        
        return jsonify({
            'message': f'Report {report_id} deleted successfully',
            'report_id': report_id
        })
        
    except Exception as e:
        logger.error(f'Error deleting report {report_id}: {str(e)}')
        logger.error(traceback.format_exc())
        return jsonify({'error': f'Failed to delete report: {str(e)}'}), 500

@report_bp.route('/reports/clear', methods=['DELETE'])
def clear_all_reports():
    """清除所有报告
    
    Returns:
        清除结果的JSON响应
    """
    try:
        report_count = len(scan_manager.excel_reports)
        scan_manager.excel_reports.clear()
        
        logger.info(f'已清除所有报告: 共{report_count}个报告')
        
        return jsonify({
            'message': f'All {report_count} reports cleared successfully',
            'cleared_count': report_count
        })
        
    except Exception as e:
        logger.error(f'Error clearing all reports: {str(e)}')
        logger.error(traceback.format_exc())
        return jsonify({'error': f'Failed to clear reports: {str(e)}'}), 500

@report_bp.route('/reports/<report_id>/info', methods=['GET'])
def get_report_info(report_id):
    """获取报告详细信息
    
    Args:
        report_id: 报告ID
        
    Returns:
        报告信息的JSON响应
    """
    try:
        if report_id not in scan_manager.excel_reports:
            logger.warning(f'尝试获取不存在的报告信息: {report_id}')
            return jsonify({'error': 'Report not found'}), 404
        
        report_data = scan_manager.excel_reports[report_id]
        
        report_info = {
            'report_id': report_id,
            'size_bytes': len(report_data),
            'download_url': f'/api/download-report/{report_id}',
            'created_at': 'N/A',  # 可以添加时间戳跟踪
            'format': 'xlsx',
            'type': 'security_scan_report'
        }
        
        logger.info(f'获取报告信息: {report_id}')
        
        return jsonify(report_info)
        
    except Exception as e:
        logger.error(f'Error getting report info {report_id}: {str(e)}')
        logger.error(traceback.format_exc())
        return jsonify({'error': f'Failed to get report info: {str(e)}'}), 500

@report_bp.route('/reports/<report_id>', methods=['GET'])
def get_report_by_id(report_id):
    """通过报告ID获取报告文件
    
    这个路由处理 /api/reports/<report_id> 格式的请求
    与 /api/download-report/<report_id> 功能相同，提供向后兼容性
    
    Args:
        report_id: 报告ID
        
    Returns:
        Excel文件或错误信息
    """
    # 直接调用现有的下载函数
    return download_excel_report(report_id)