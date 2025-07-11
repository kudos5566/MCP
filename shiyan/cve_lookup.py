#!/usr/bin/env python3
"""
CVE查询模块

提供CVE漏洞信息查询功能，包括：
- NVD API交互
- 智能缓存管理
- CVE详情解析
- 缓存过期清理
"""

import os
import json
import time
import datetime
import requests
from typing import Dict, Any, List, Optional
from config import logger, CACHE_DIR, MAX_CVE_CACHE_DAYS, NVD_API_URL, NVD_REQUEST_TIMEOUT


class CVELookup:
    """
    CVE漏洞查询类
    
    提供完整的CVE查询功能，包括NVD API交互、缓存管理等
    """
    
    def __init__(self, cache_dir: Optional[str] = None, cache_days: Optional[int] = None):
        """
        初始化CVE查询器
        
        Args:
            cache_dir: 缓存目录，默认使用配置中的CACHE_DIR
            cache_days: 缓存天数，默认使用配置中的MAX_CVE_CACHE_DAYS
        """
        self.cache_dir = cache_dir or CACHE_DIR
        self.cache_days = cache_days or MAX_CVE_CACHE_DAYS
        self.api_url = NVD_API_URL
        self.request_timeout = NVD_REQUEST_TIMEOUT
        
        # 确保缓存目录存在
        os.makedirs(self.cache_dir, exist_ok=True)
    
    def get_cve_details(self, cve_id: str) -> Dict[str, Any]:
        """
        查询NVD获取CVE详细信息（含修复建议）
        
        包含智能缓存机制，避免重复请求
        支持缓存过期清理
        
        Args:
            cve_id: CVE编号，如 "CVE-2021-44228"
            
        Returns:
            Dict[str, Any]: CVE详细信息字典
        """
        if not cve_id or not isinstance(cve_id, str):
            return {"error": "无效的CVE ID"}
        
        # 标准化CVE ID格式
        cve_id = cve_id.upper().strip()
        if not cve_id.startswith('CVE-'):
            return {"error": "CVE ID格式错误，应以CVE-开头"}
        
        cache_file = os.path.join(self.cache_dir, f"{cve_id}.json")
        
        # 检查缓存
        cached_data = self._get_cached_data(cache_file, cve_id)
        if cached_data:
            return cached_data
        
        # 从NVD API获取数据
        return self._fetch_from_api(cve_id, cache_file)
    
    def _get_cached_data(self, cache_file: str, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        获取缓存的CVE数据
        
        Args:
            cache_file: 缓存文件路径
            cve_id: CVE编号
            
        Returns:
            Optional[Dict[str, Any]]: 缓存的数据，如果无效则返回None
        """
        if not os.path.exists(cache_file):
            return None
        
        try:
            # 检查文件修改时间
            file_age = time.time() - os.path.getmtime(cache_file)
            if file_age < (self.cache_days * 24 * 3600):  # 缓存未过期
                with open(cache_file, "r", encoding='utf-8') as f:
                    cached_data = json.load(f)
                    logger.debug(f"使用缓存的CVE数据: {cve_id}")
                    return cached_data
            else:
                logger.info(f"CVE缓存已过期，删除旧缓存: {cve_id}")
                os.remove(cache_file)
        except Exception as e:
            logger.warning(f"读取CVE缓存失败: {cve_id}, 错误: {str(e)}")
            try:
                os.remove(cache_file)
            except:
                pass
        
        return None
    
    def _fetch_from_api(self, cve_id: str, cache_file: str) -> Dict[str, Any]:
        """
        从NVD API获取CVE数据
        
        Args:
            cve_id: CVE编号
            cache_file: 缓存文件路径
            
        Returns:
            Dict[str, Any]: CVE详细信息
        """
        try:
            logger.info(f"从NVD API获取CVE详情: {cve_id}")
            params = {"cveId": cve_id}
            response = requests.get(
                self.api_url, 
                params=params, 
                timeout=self.request_timeout,
                headers={'User-Agent': 'Kali-Security-Tools/1.2.0'}
            )
            response.raise_for_status()
            data = response.json()
            
            # 解析CVE数据
            result = self._parse_cve_data(cve_id, data)
            
            # 缓存结果
            self._cache_result(cache_file, result, cve_id)
            
            return result
            
        except requests.exceptions.Timeout:
            logger.error(f"获取CVE详情超时: {cve_id}")
            return {"error": "请求超时，请稍后重试"}
        except requests.exceptions.RequestException as e:
            logger.error(f"网络请求失败: {cve_id}, 错误: {str(e)}")
            return {"error": f"网络请求失败: {str(e)}"}
        except Exception as e:
            logger.error(f"获取CVE详情时发生未预期错误: {cve_id}, 错误: {str(e)}", exc_info=True)
            return {"error": f"获取CVE详情失败: {str(e)}"}
    
    def _parse_cve_data(self, cve_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        解析NVD API返回的CVE数据
        
        Args:
            cve_id: CVE编号
            data: NVD API返回的原始数据
            
        Returns:
            Dict[str, Any]: 解析后的CVE信息
        """
        # 提取关键信息
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            logger.warning(f"NVD API未返回CVE数据: {cve_id}")
            return {"error": "CVE数据未找到"}
        
        cve_data = vulnerabilities[0].get("cve", {})
        
        # 获取描述信息
        descriptions = cve_data.get("descriptions", [])
        description = descriptions[0].get("value", "暂无描述") if descriptions else "暂无描述"
        
        # 获取CVSS评分
        cvss_info = self._extract_cvss_info(cve_data.get("metrics", {}))
        
        # 获取参考链接
        references = self._extract_references(cve_data.get("references", []))
        
        # 获取受影响的产品
        affected_products = self._extract_affected_products(cve_data.get("configurations", {}))
        
        result = {
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_info["score"],
            "severity": cvss_info["severity"],
            "cvss_version": cvss_info["version"],
            "vector_string": cvss_info["vector"],
            "published_date": cve_data.get("published", "N/A"),
            "last_modified": cve_data.get("lastModified", "N/A"),
            "references": references,
            "affected_products": affected_products,
            "remediation": "建议更新到最新版本或应用厂商补丁",
            "cached_at": datetime.datetime.now().isoformat(),
            "source": "NVD"
        }
        
        return result
    
    def _extract_cvss_info(self, metrics: Dict[str, Any]) -> Dict[str, str]:
        """
        提取CVSS评分信息
        
        Args:
            metrics: NVD API中的metrics数据
            
        Returns:
            Dict[str, str]: CVSS信息字典
        """
        cvss_info = {
            "score": "N/A",
            "severity": "未知",
            "version": "N/A",
            "vector": "N/A"
        }
        
        # 优先使用CVSSv3.1，然后是CVSSv3.0，最后是CVSSv2
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics and metrics[version]:
                cvss_data = metrics[version][0].get("cvssData", {})
                cvss_info["score"] = cvss_data.get("baseScore", "N/A")
                cvss_info["severity"] = cvss_data.get("baseSeverity", "未知")
                cvss_info["version"] = version.replace("cvssMetric", "CVSS ")
                cvss_info["vector"] = cvss_data.get("vectorString", "N/A")
                break
        
        return cvss_info
    
    def _extract_references(self, references: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """
        提取参考链接信息
        
        Args:
            references: NVD API中的references数据
            
        Returns:
            List[Dict[str, str]]: 参考链接列表
        """
        ref_list = []
        for ref in references[:10]:  # 限制最多10个链接
            ref_info = {
                "url": ref.get("url", ""),
                "source": ref.get("source", "未知"),
                "tags": ", ".join(ref.get("tags", []))
            }
            if ref_info["url"]:
                ref_list.append(ref_info)
        
        return ref_list
    
    def _extract_affected_products(self, configurations) -> List[str]:
        """
        提取受影响的产品信息
        
        Args:
            configurations: NVD API中的configurations数据（可能是字典或列表）
            
        Returns:
            List[str]: 受影响的产品列表
        """
        products = set()
        
        try:
            # 处理不同的configurations格式
            if isinstance(configurations, dict):
                nodes = configurations.get("nodes", [])
            elif isinstance(configurations, list):
                nodes = configurations
            else:
                return []
            
            # 简化的产品提取逻辑
            for node in nodes[:5]:  # 限制处理的节点数量
                if not isinstance(node, dict):
                    continue
                    
                cpe_matches = node.get("cpeMatch", [])
                for cpe in cpe_matches[:10]:  # 限制每个节点的CPE数量
                    if not isinstance(cpe, dict):
                        continue
                        
                    cpe_name = cpe.get("criteria", "")
                    if cpe_name and cpe_name.startswith("cpe:2.3:"):
                        # 解析CPE名称，提取产品信息
                        parts = cpe_name.split(":")
                        if len(parts) >= 5:
                            vendor = parts[3]
                            product = parts[4]
                            if vendor != "*" and product != "*":
                                products.add(f"{vendor} {product}")
        except Exception as e:
            logger.warning(f"提取受影响产品信息失败: {str(e)}")
        
        return list(products)[:20]  # 最多返回20个产品
    
    def _cache_result(self, cache_file: str, result: Dict[str, Any], cve_id: str):
        """
        缓存CVE查询结果
        
        Args:
            cache_file: 缓存文件路径
            result: 要缓存的结果
            cve_id: CVE编号
        """
        try:
            with open(cache_file, "w", encoding='utf-8') as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
            logger.debug(f"CVE详情已缓存: {cve_id}")
        except Exception as e:
            logger.warning(f"缓存CVE详情失败: {cve_id}, 错误: {str(e)}")
    
    def clear_cache(self, older_than_days: Optional[int] = None) -> int:
        """
        清理过期的缓存文件
        
        Args:
            older_than_days: 清理多少天前的缓存，默认使用配置的缓存天数
            
        Returns:
            int: 清理的文件数量
        """
        if older_than_days is None:
            older_than_days = self.cache_days
        
        cleared_count = 0
        cutoff_time = time.time() - (older_than_days * 24 * 3600)
        
        try:
            for filename in os.listdir(self.cache_dir):
                if filename.endswith('.json') and filename.startswith('CVE-'):
                    file_path = os.path.join(self.cache_dir, filename)
                    try:
                        if os.path.getmtime(file_path) < cutoff_time:
                            os.remove(file_path)
                            cleared_count += 1
                            logger.debug(f"清理过期缓存: {filename}")
                    except Exception as e:
                        logger.warning(f"清理缓存文件失败: {filename}, 错误: {str(e)}")
        except Exception as e:
            logger.error(f"清理缓存目录失败: {str(e)}")
        
        if cleared_count > 0:
            logger.info(f"清理了 {cleared_count} 个过期的CVE缓存文件")
        
        return cleared_count
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """
        获取缓存统计信息
        
        Returns:
            Dict[str, Any]: 缓存统计信息
        """
        stats = {
            "total_files": 0,
            "total_size_bytes": 0,
            "oldest_file_age_days": 0,
            "newest_file_age_days": 0,
            "cache_dir": self.cache_dir
        }
        
        try:
            current_time = time.time()
            file_ages = []
            
            for filename in os.listdir(self.cache_dir):
                if filename.endswith('.json') and filename.startswith('CVE-'):
                    file_path = os.path.join(self.cache_dir, filename)
                    try:
                        file_stat = os.stat(file_path)
                        stats["total_files"] += 1
                        stats["total_size_bytes"] += file_stat.st_size
                        
                        age_days = (current_time - file_stat.st_mtime) / (24 * 3600)
                        file_ages.append(age_days)
                    except Exception:
                        continue
            
            if file_ages:
                stats["oldest_file_age_days"] = max(file_ages)
                stats["newest_file_age_days"] = min(file_ages)
        
        except Exception as e:
            logger.error(f"获取缓存统计失败: {str(e)}")
        
        return stats


# 全局CVE查询实例
cve_lookup = CVELookup()


def get_cve_details(cve_id: str) -> Dict[str, Any]:
    """
    获取CVE详细信息的便捷函数
    
    Args:
        cve_id: CVE编号
        
    Returns:
        Dict[str, Any]: CVE详细信息
    """
    return cve_lookup.get_cve_details(cve_id)


def clear_cve_cache(older_than_days: Optional[int] = None) -> int:
    """
    清理CVE缓存的便捷函数
    
    Args:
        older_than_days: 清理多少天前的缓存
        
    Returns:
        int: 清理的文件数量
    """
    return cve_lookup.clear_cache(older_than_days)


def get_cve_cache_stats() -> Dict[str, Any]:
    """
    获取CVE缓存统计信息的便捷函数
    
    Returns:
        Dict[str, Any]: 缓存统计信息
    """
    return cve_lookup.get_cache_stats()


if __name__ == "__main__":
    # CVE查询模块测试
    print("=== CVE查询模块测试 ===")
    
    # 测试CVE查询
    test_cve = "CVE-2021-44228"  # Log4j漏洞
    print(f"\n查询CVE: {test_cve}")
    result = get_cve_details(test_cve)
    
    if "error" not in result:
        print(f"CVE ID: {result['cve_id']}")
        print(f"CVSS评分: {result['cvss_score']} ({result['severity']})")
        print(f"描述: {result['description'][:100]}...")
        print(f"发布日期: {result['published_date']}")
    else:
        print(f"查询失败: {result['error']}")
    
    # 测试缓存统计
    print("\n缓存统计:")
    stats = get_cve_cache_stats()
    print(f"缓存文件数: {stats['total_files']}")
    print(f"缓存大小: {stats['total_size_bytes']} 字节")
    print(f"缓存目录: {stats['cache_dir']}")
    
    print("\nCVE查询模块测试完成")