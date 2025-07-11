#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
扫描管理模块

提供扫描结果存储、统计分析、内存管理和历史记录清理功能
独立的扫描数据管理，支持智能内存优化和统计分析

主要功能:
- 扫描结果存储和管理
- 扫描统计信息生成
- 智能内存管理
- 历史记录清理
- Excel报告管理
"""

import datetime
import sys
import time
from typing import Dict, Any, List

from config import config, logger
from excel_report_generator import ExcelReportGenerator


class ScanManager:
    """
    扫描管理器
    
    负责扫描结果的存储、管理和统计分析
    包含智能内存管理和历史记录清理功能
    """
    
    def __init__(self):
        """初始化扫描管理器"""
        self.scan_history: List[Dict[str, Any]] = []
        self.excel_reports: Dict[str, bytes] = {}
        self.max_scan_history = config.MAX_SCAN_HISTORY
        logger.debug(f"扫描管理器初始化完成，最大历史记录数: {self.max_scan_history}")
    
    def store_scan_result(self, tool: str, target: str, result: Dict[str, Any]):
        """
        存储扫描结果，包含智能内存管理
        
        自动清理过大的结果数据，避免内存泄漏
        限制历史记录数量，保持系统性能
        
        Args:
            tool: 扫描工具名称
            target: 扫描目标
            result: 扫描结果字典
        """
        try:
            # 清理结果中的大型数据，避免内存占用过多
            cleaned_result = result.copy()
            
            # 如果stdout过大，只保留前1000字符和后500字符
            if 'stdout' in cleaned_result and len(str(cleaned_result['stdout'])) > 2000:
                stdout = str(cleaned_result['stdout'])
                cleaned_result['stdout'] = stdout[:1000] + "\n... [输出过长，已截断] ...\n" + stdout[-500:]
                logger.debug(f"截断了过长的{tool}扫描输出")
            
            # 如果stderr过大，只保留前500字符
            if 'stderr' in cleaned_result and len(str(cleaned_result['stderr'])) > 1000:
                stderr = str(cleaned_result['stderr'])
                cleaned_result['stderr'] = stderr[:500] + "\n... [错误输出过长，已截断] ..."
            
            scan_entry = {
                "tool": tool,
                "target": target,
                "timestamp": datetime.datetime.now().isoformat(),
                "result": cleaned_result,
                "success": result.get('success', False),
                "return_code": result.get('return_code', -1)
            }
            
            self.scan_history.append(scan_entry)
            logger.debug(f"存储扫描结果: {tool} -> {target}")
            
            # 限制历史记录大小，使用配置的最大值
            if len(self.scan_history) > self.max_scan_history:
                removed_count = len(self.scan_history) - self.max_scan_history
                self.scan_history[:removed_count] = []  # 删除最旧的记录
                logger.info(f"清理了 {removed_count} 条旧的扫描记录")
                
        except Exception as e:
            logger.error(f"存储扫描结果失败: {tool} -> {target}, 错误: {str(e)}", exc_info=True)
    
    def get_scan_statistics(self) -> Dict[str, Any]:
        """
        获取扫描统计信息
        
        返回扫描历史的统计数据，用于监控和报告
        
        Returns:
            包含统计信息的字典
        """
        try:
            total_scans = len(self.scan_history)
            successful_scans = sum(1 for entry in self.scan_history if entry.get('success', False))
            failed_scans = total_scans - successful_scans
            
            # 按工具统计
            tool_stats = {}
            for entry in self.scan_history:
                tool = entry.get('tool', 'unknown')
                if tool not in tool_stats:
                    tool_stats[tool] = {'total': 0, 'success': 0, 'failed': 0}
                tool_stats[tool]['total'] += 1
                if entry.get('success', False):
                    tool_stats[tool]['success'] += 1
                else:
                    tool_stats[tool]['failed'] += 1
            
            # 最近扫描时间
            last_scan_time = self.scan_history[-1]['timestamp'] if self.scan_history else None
            
            return {
                'total_scans': total_scans,
                'successful_scans': successful_scans,
                'failed_scans': failed_scans,
                'success_rate': round(successful_scans / total_scans * 100, 2) if total_scans > 0 else 0,
                'tool_statistics': tool_stats,
                'last_scan_time': last_scan_time,
                'memory_usage_mb': round(sys.getsizeof(self.scan_history) / 1024 / 1024, 2)
            }
        except Exception as e:
            logger.error(f"获取扫描统计信息失败: {str(e)}")
            return {'error': '获取统计信息失败'}
    
    def generate_single_tool_excel_report(self, tool: str, target: str, result: Dict[str, Any]) -> str:
        """
        为单个工具的扫描结果生成Excel报告
        
        Args:
            tool: 扫描工具名称
            target: 扫描目标
            result: 扫描结果
            
        Returns:
            报告ID，用于下载报告
        """
        try:
            # 构造扫描结果数据结构
            scan_data = {
                'target': target,
                'scan_sequence': [{
                    'tool': tool,
                    'command': result.get('command', ''),
                    'result': result,
                    'summary': f"{tool}扫描完成",
                    'timestamp': datetime.datetime.now().isoformat()
                }],
                'secondary_scans': [],
                'errors': [] if result.get('success', False) else [result.get('stderr', '扫描失败')]
            }
            
            # 生成Excel报告
            generator = ExcelReportGenerator()
            report_data = generator.generate_report(scan_data)
            
            # 生成报告ID和文件名
            timestamp = int(time.time())
            safe_target = target.replace('/', '_').replace(':', '_').replace('?', '_').replace('&', '_')
            report_id = f"{tool}_{safe_target}_{timestamp}"
            filename = f"{report_id}.xlsx"
            
            # 存储报告到内存（用于下载）
            self.excel_reports[report_id] = report_data.getvalue()
            
            # 保存报告到文件系统
            try:
                import os
                from config import REPORTS_DIR
                
                # 确保reports目录存在
                os.makedirs(REPORTS_DIR, exist_ok=True)
                
                # 保存到文件
                file_path = os.path.join(REPORTS_DIR, filename)
                with open(file_path, 'wb') as f:
                    f.write(self.excel_reports[report_id])
                
                logger.info(f"Excel报告已保存到文件: {file_path}")
                
            except Exception as file_error:
                logger.warning(f"保存Excel报告到文件失败: {str(file_error)}")
            
            logger.info(f"已生成{tool}扫描Excel报告: {report_id}")
            return report_id
            
        except Exception as e:
            logger.error(f"生成{tool}扫描Excel报告失败: {str(e)}", exc_info=True)
            return None
    
    def get_excel_report(self, report_id: str) -> bytes:
        """
        获取Excel报告数据
        
        Args:
            report_id: 报告ID
            
        Returns:
            报告的二进制数据，如果不存在则返回None
        """
        return self.excel_reports.get(report_id)
    
    def cleanup_old_reports(self, max_reports: int = 50):
        """
        清理旧的Excel报告
        
        Args:
            max_reports: 保留的最大报告数量
        """
        if len(self.excel_reports) > max_reports:
            # 按报告ID排序（包含时间戳），删除最旧的报告
            sorted_reports = sorted(self.excel_reports.keys())
            reports_to_remove = sorted_reports[:-max_reports]
            
            for report_id in reports_to_remove:
                del self.excel_reports[report_id]
            
            logger.info(f"清理了 {len(reports_to_remove)} 个旧的Excel报告")
    
    def clear_scan_history(self):
        """
        清空扫描历史记录
        """
        cleared_count = len(self.scan_history)
        self.scan_history.clear()
        logger.info(f"已清空 {cleared_count} 条扫描历史记录")
    
    def get_scan_history(self, limit: int = None) -> List[Dict[str, Any]]:
        """
        获取扫描历史记录
        
        Args:
            limit: 返回记录的最大数量，None表示返回所有记录
            
        Returns:
            扫描历史记录列表
        """
        if limit is None:
            return self.scan_history.copy()
        else:
            return self.scan_history[-limit:] if limit > 0 else []
    
    def get_memory_usage(self) -> Dict[str, float]:
        """
        获取内存使用情况
        
        Returns:
            内存使用统计信息
        """
        return {
            'scan_history_mb': round(sys.getsizeof(self.scan_history) / 1024 / 1024, 2),
            'excel_reports_mb': round(sys.getsizeof(self.excel_reports) / 1024 / 1024, 2),
            'total_mb': round((sys.getsizeof(self.scan_history) + sys.getsizeof(self.excel_reports)) / 1024 / 1024, 2)
        }


# 全局扫描管理器实例
scan_manager = ScanManager()

# 兼容性函数，保持与原有代码的接口一致
def store_scan_result(tool: str, target: str, result: Dict[str, Any]):
    """
    存储扫描结果（兼容性函数）
    
    Args:
        tool: 扫描工具名称
        target: 扫描目标
        result: 扫描结果
    """
    scan_manager.store_scan_result(tool, target, result)


def get_scan_statistics() -> Dict[str, Any]:
    """
    获取扫描统计信息（兼容性函数）
    
    Returns:
        扫描统计信息字典
    """
    return scan_manager.get_scan_statistics()


def generate_single_tool_excel_report(tool: str, target: str, result: Dict[str, Any]) -> str:
    """
    生成单个工具的Excel报告（兼容性函数）
    
    Args:
        tool: 扫描工具名称
        target: 扫描目标
        result: 扫描结果
        
    Returns:
        报告ID
    """
    return scan_manager.generate_single_tool_excel_report(tool, target, result)


# 测试代码
if __name__ == "__main__":
    print("=== 扫描管理模块测试 ===")
    
    # 测试扫描结果存储
    test_result = {
        'success': True,
        'return_code': 0,
        'stdout': 'Test scan output',
        'stderr': '',
        'command': 'test command'
    }
    
    print("1. 测试扫描结果存储...")
    store_scan_result('nmap', '192.168.1.1', test_result)
    print("   ✓ 扫描结果存储成功")
    
    # 测试统计信息
    print("\n2. 测试统计信息获取...")
    stats = get_scan_statistics()
    print(f"   ✓ 总扫描数: {stats['total_scans']}")
    print(f"   ✓ 成功率: {stats['success_rate']}%")
    print(f"   ✓ 内存使用: {stats['memory_usage_mb']} MB")
    
    # 测试Excel报告生成
    print("\n3. 测试Excel报告生成...")
    report_id = generate_single_tool_excel_report('nmap', '192.168.1.1', test_result)
    if report_id:
        print(f"   ✓ Excel报告生成成功: {report_id}")
    else:
        print("   ✗ Excel报告生成失败")
    
    # 测试内存使用情况
    print("\n4. 测试内存使用情况...")
    memory_usage = scan_manager.get_memory_usage()
    print(f"   ✓ 扫描历史内存: {memory_usage['scan_history_mb']} MB")
    print(f"   ✓ Excel报告内存: {memory_usage['excel_reports_mb']} MB")
    print(f"   ✓ 总内存使用: {memory_usage['total_mb']} MB")
    
    print("\n=== 扫描管理模块测试完成 ===")