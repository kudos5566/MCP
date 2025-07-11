#!/usr/bin/env python3
import argparse
import datetime
import json
import logging
import os
import sys
import re
import time
import traceback
from typing import Dict, Any, List
import requests
from flask import Flask, request, jsonify, send_file
from io import BytesIO
from excel_report_generator import ExcelReportGenerator
from cve_lookup import CVELookup, get_cve_details
from command_executor import CommandExecutor, execute_command, execute_safe_command
from scan_manager import scan_manager, store_scan_result, get_scan_statistics, generate_single_tool_excel_report
from config import config, logger, API_PORT, DEBUG_MODE, COMMAND_TIMEOUT, MAX_SCAN_HISTORY, MAX_CVE_CACHE_DAYS, API_KEY, ALLOWED_IPS, ENABLE_DANGEROUS_COMMANDS, CACHE_DIR, REPORTS_DIR, NVD_API_URL, NVD_REQUEST_TIMEOUT, NMAP_DEFAULT_ARGS, GOBUSTER_DEFAULT_WORDLIST, NIKTO_DEFAULT_ARGS

# 环境变量加载已在config模块中处理

# 版本信息管理已移至version_info.py模块
from version_info import get_version_info, __version__
from version_info import VersionManager
from tool_checker import ToolChecker, health_check as tool_health_check


# 配置管理已移至config.py模块

# 记录启动时间
start_time = time.time()
logger.info(f"Kali安全工具平台 v{__version__} 启动中...")

app = Flask(__name__)





# API路由扩展
@app.route("/api/command", methods=["POST"])
def generic_command():
    """
    通用命令执行接口
    
    接收JSON格式的命令参数，执行系统命令并返回结果
    包含基础的输入验证和异常处理
    """
    try:
        # 参数验证
        if not request.json:
            logger.warning("接收到空的JSON请求")
            return jsonify({"error": "请求体必须是有效的JSON格式", "success": False}), 400
            
        params = request.json
        command = params.get("command", "")
        
        # 输入验证
        if not command or not isinstance(command, str):
            logger.warning(f"无效的命令参数: {command}")
            return jsonify({"error": "command参数是必需的且必须是字符串", "success": False}), 400
        
        # 基础安全检查 - 防止危险命令
        dangerous_commands = ['rm -rf', 'format', 'del /f', 'shutdown', 'reboot', 'halt']
        if any(dangerous in command.lower() for dangerous in dangerous_commands):
            logger.error(f"检测到危险命令: {command}")
            return jsonify({"error": "检测到潜在危险命令，执行被拒绝", "success": False}), 403
        
        logger.info(f"开始执行命令: {command[:100]}...")  # 只记录前100个字符
        result = execute_command(command)
        
        # 添加执行状态日志
        if result.get('success'):
            logger.info(f"命令执行成功: {command[:50]}...")
        else:
            logger.warning(f"命令执行失败: {command[:50]}..., 错误: {result.get('stderr', '')[:100]}")
        
        return jsonify(result)
        
    except json.JSONDecodeError as e:
        logger.error(f"JSON解析错误: {str(e)}")
        return jsonify({"error": "无效的JSON格式", "success": False}), 400
    except Exception as e:
        logger.error(f"通用命令接口发生未预期错误: {str(e)}", exc_info=True)
        return jsonify({"error": "服务器内部错误，请稍后重试", "success": False}), 500

# 原有路由扩展
@app.route("/api/tools/nmap", methods=["POST"])
def nmap():
    """
    Nmap网络扫描接口
    
    执行Nmap扫描并返回结果，包含CVE漏洞信息提取
    支持自定义扫描类型、端口范围和附加参数
    """
    try:
        # 参数验证
        if not request.json:
            logger.warning("Nmap接口接收到空的JSON请求")
            return jsonify({"error": "请求体必须是有效的JSON格式", "success": False}), 400
            
        params = request.json
        target = params.get("target", "")
        scan_type = params.get("scan_type", "-sV")
        ports = params.get("ports", "")
        additional_args = params.get("additional_args", "-T4 -Pn")
        
        # 输入验证
        if not target or not isinstance(target, str):
            logger.warning(f"Nmap扫描目标无效: {target}")
            return jsonify({"error": "target参数是必需的且必须是有效的IP地址或域名", "success": False}), 400
        
        # 基础目标格式验证
        import socket
        try:
            # 尝试解析域名或验证IP
            socket.gethostbyname(target.split('/')[0])  # 支持CIDR格式
        except socket.gaierror:
            logger.warning(f"无法解析目标地址: {target}")
            return jsonify({"error": "无法解析目标地址，请检查IP或域名格式", "success": False}), 400
        
        # 构建nmap命令
        command = f"nmap {scan_type}"
        if ports:
            command += f" -p {ports}"
        if additional_args:
            command += f" {additional_args}"
        command += f" {target}"
        
        logger.info(f"开始执行Nmap扫描: 目标={target}, 扫描类型={scan_type}")
        
        # 执行扫描
        result = execute_command(command)
        
        # 存储扫描结果
        try:
            store_scan_result("nmap", target, result)
            logger.info(f"Nmap扫描结果已存储: 目标={target}")
        except Exception as e:
            logger.warning(f"存储Nmap扫描结果失败: {str(e)}")
        
        # 提取CVE并分析
        cve_count = 0
        if result.get("stdout"):
            try:
                cves = re.findall(r"CVE-\d{4}-\d{4,7}", result["stdout"])
                if cves:
                    logger.info(f"在Nmap结果中发现 {len(set(cves))} 个CVE")
                    result["cve_details"] = {}
                    for cve in set(cves):
                        try:
                            cve_info = get_cve_details(cve)
                            result["cve_details"][cve] = cve_info
                            cve_count += 1
                        except Exception as e:
                            logger.warning(f"获取CVE {cve} 详情失败: {str(e)}")
                            result["cve_details"][cve] = {"error": "获取CVE详情失败"}
            except Exception as e:
                logger.warning(f"CVE提取过程出错: {str(e)}")
        
        # 生成Excel报告
        try:
            result['command'] = command
            report_id = generate_single_tool_excel_report("nmap", target, result)
            if report_id:
                result['excel_report_id'] = report_id
                result['excel_download_url'] = f"/api/download-report/{report_id}"
                logger.info(f"Nmap扫描Excel报告已生成: {report_id}")
        except Exception as e:
            logger.warning(f"生成Nmap扫描Excel报告失败: {str(e)}")
        
        # 添加扫描统计信息
        if result.get('success'):
            logger.info(f"Nmap扫描完成: 目标={target}, 发现CVE={cve_count}个")
        else:
            logger.warning(f"Nmap扫描失败: 目标={target}, 错误={result.get('stderr', '')[:100]}")
        
        return jsonify(result)
        
    except json.JSONDecodeError as e:
        logger.error(f"Nmap接口JSON解析错误: {str(e)}")
        return jsonify({"error": "无效的JSON格式", "success": False}), 400
    except Exception as e:
        logger.error(f"Nmap接口发生未预期错误: {str(e)}", exc_info=True)
        return jsonify({"error": "Nmap扫描服务暂时不可用，请稍后重试", "success": False}), 500




@app.route("/api/tools/gobuster", methods=["POST"])
def gobuster():
    """Execute gobuster with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        mode = params.get("mode", "dir")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Gobuster called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        # Validate mode
        if mode not in ["dir", "dns", "fuzz", "vhost"]:
            logger.warning(f"Invalid gobuster mode: {mode}")
            return jsonify({
                "error": f"Invalid mode: {mode}. Must be one of: dir, dns, fuzz, vhost"
            }), 400
        
        command = f"gobuster {mode} -u {url} -w {wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        
        # 存储扫描结果
        try:
            store_scan_result("gobuster", url, result)
            logger.info(f"Gobuster扫描结果已存储: 目标={url}")
        except Exception as e:
            logger.warning(f"存储Gobuster扫描结果失败: {str(e)}")
        
        # 生成Excel报告
        try:
            result['command'] = command
            report_id = generate_single_tool_excel_report("gobuster", url, result)
            if report_id:
                result['excel_report_id'] = report_id
                result['excel_download_url'] = f"/api/download-report/{report_id}"
                logger.info(f"Gobuster扫描Excel报告已生成: {report_id}")
        except Exception as e:
            logger.warning(f"生成Gobuster扫描Excel报告失败: {str(e)}")
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in gobuster endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/dirb", methods=["POST"])
def dirb():
    """Execute dirb with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Dirb called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"dirb {url} {wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        
        # 存储扫描结果
        try:
            store_scan_result("dirb", url, result)
            logger.info(f"Dirb扫描结果已存储: 目标={url}")
        except Exception as e:
            logger.warning(f"存储Dirb扫描结果失败: {str(e)}")
        
        # 生成Excel报告
        try:
            result['command'] = command
            report_id = generate_single_tool_excel_report("dirb", url, result)
            if report_id:
                result['excel_report_id'] = report_id
                result['excel_download_url'] = f"/api/download-report/{report_id}"
                logger.info(f"Dirb扫描Excel报告已生成: {report_id}")
        except Exception as e:
            logger.warning(f"生成Dirb扫描Excel报告失败: {str(e)}")
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in dirb endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/nikto", methods=["POST"])
def nikto():
    """Execute nikto with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Nikto called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"nikto -h {target}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        
        # 存储扫描结果
        try:
            store_scan_result("nikto", target, result)
            logger.info(f"Nikto扫描结果已存储: 目标={target}")
        except Exception as e:
            logger.warning(f"存储Nikto扫描结果失败: {str(e)}")
        
        # 生成Excel报告
        try:
            result['command'] = command
            report_id = generate_single_tool_excel_report("nikto", target, result)
            if report_id:
                result['excel_report_id'] = report_id
                result['excel_download_url'] = f"/api/download-report/{report_id}"
                logger.info(f"Nikto扫描Excel报告已生成: {report_id}")
        except Exception as e:
            logger.warning(f"生成Nikto扫描Excel报告失败: {str(e)}")
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nikto endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/sqlmap", methods=["POST"])
def sqlmap():
    """Execute sqlmap with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        data = params.get("data", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("SQLMap called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"sqlmap -u {url} --batch"
        
        if data:
            command += f" --data=\"{data}\""
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        
        # 存储扫描结果
        try:
            store_scan_result("sqlmap", url, result)
            logger.info(f"SQLMap扫描结果已存储: 目标={url}")
        except Exception as e:
            logger.warning(f"存储SQLMap扫描结果失败: {str(e)}")
        
        # 生成Excel报告
        try:
            result['command'] = command
            report_id = generate_single_tool_excel_report("sqlmap", url, result)
            if report_id:
                result['excel_report_id'] = report_id
                result['excel_download_url'] = f"/api/download-report/{report_id}"
                logger.info(f"SQLMap扫描Excel报告已生成: {report_id}")
        except Exception as e:
            logger.warning(f"生成SQLMap扫描Excel报告失败: {str(e)}")
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in sqlmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/metasploit", methods=["POST"])
def metasploit():
    """Execute metasploit module with the provided parameters."""
    try:
        params = request.json
        module = params.get("module", "")
        options = params.get("options", {})
        
        if not module:
            logger.warning("Metasploit called without module parameter")
            return jsonify({
                "error": "Module parameter is required"
            }), 400
        
        # Format options for Metasploit
        options_str = ""
        for key, value in options.items():
            options_str += f" {key}={value}"
        
        # Create an MSF resource script
        resource_content = f"use {module}" + "\n"
        for key, value in options.items():
            resource_content += f"set {key} {value}" + "\n"
        resource_content += "exploit" + "\n"
        
        # Save resource script to a temporary file
        resource_file = "/tmp/mcp_msf_resource.rc"
        with open(resource_file, "w") as f:
            f.write(resource_content)
        
        command = f"msfconsole -q -r {resource_file}"
        result = execute_command(command)
        
        # Clean up the temporary file
        try:
            os.remove(resource_file)
        except Exception as e:
            logger.warning(f"Error removing temporary resource file: {str(e)}")
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in metasploit endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/hydra", methods=["POST"])
def hydra():
    """Execute hydra with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        service = params.get("service", "")
        username = params.get("username", "")
        username_file = params.get("username_file", "")
        password = params.get("password", "")
        password_file = params.get("password_file", "")
        additional_args = params.get("additional_args", "")
        
        if not target or not service:
            logger.warning("Hydra called without target or service parameter")
            return jsonify({
                "error": "Target and service parameters are required"
            }), 400
        
        if not (username or username_file) or not (password or password_file):
            logger.warning("Hydra called without username/password parameters")
            return jsonify({
                "error": "Username/username_file and password/password_file are required"
            }), 400
        
        command = f"hydra -t 4"
        
        if username:
            command += f" -l {username}"
        elif username_file:
            command += f" -L {username_file}"
        
        if password:
            command += f" -p {password}"
        elif password_file:
            command += f" -P {password_file}"
        
        if additional_args:
            command += f" {additional_args}"
        
        command += f" {target} {service}"
        
        result = execute_command(command)
        
        # 存储扫描结果
        try:
            store_scan_result("hydra", target, result)
            logger.info(f"Hydra扫描结果已存储: 目标={target}")
        except Exception as e:
            logger.warning(f"存储Hydra扫描结果失败: {str(e)}")
        
        # 生成Excel报告
        try:
            result['command'] = command
            report_id = generate_single_tool_excel_report("hydra", target, result)
            if report_id:
                result['excel_report_id'] = report_id
                result['excel_download_url'] = f"/api/download-report/{report_id}"
                logger.info(f"Hydra扫描Excel报告已生成: {report_id}")
        except Exception as e:
            logger.warning(f"生成Hydra扫描Excel报告失败: {str(e)}")
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in hydra endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/john", methods=["POST"])
def john():
    """Execute john with the provided parameters."""
    try:
        params = request.json
        hash_file = params.get("hash_file", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        format_type = params.get("format", "")
        additional_args = params.get("additional_args", "")
        
        if not hash_file:
            logger.warning("John called without hash_file parameter")
            return jsonify({
                "error": "Hash file parameter is required"
            }), 400
        
        command = f"john"
        
        if format_type:
            command += f" --format={format_type}"
        
        if wordlist:
            command += f" --wordlist={wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        command += f" {hash_file}"
        
        result = execute_command(command)
        
        # 存储扫描结果
        try:
            store_scan_result("john", hash_file, result)
            logger.info(f"John扫描结果已存储: 目标={hash_file}")
        except Exception as e:
            logger.warning(f"存储John扫描结果失败: {str(e)}")
        
        # 生成Excel报告
        try:
            result['command'] = command
            report_id = generate_single_tool_excel_report("john", hash_file, result)
            if report_id:
                result['excel_report_id'] = report_id
                result['excel_download_url'] = f"/api/download-report/{report_id}"
                logger.info(f"John扫描Excel报告已生成: {report_id}")
        except Exception as e:
            logger.warning(f"生成John扫描Excel报告失败: {str(e)}")
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in john endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/wpscan", methods=["POST"])
def wpscan():
    """Execute wpscan with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("WPScan called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"wpscan --url {url}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        
        # 存储扫描结果
        try:
            store_scan_result("wpscan", url, result)
            logger.info(f"WPScan扫描结果已存储: 目标={url}")
        except Exception as e:
            logger.warning(f"存储WPScan扫描结果失败: {str(e)}")
        
        # 生成Excel报告
        try:
            result['command'] = command
            report_id = generate_single_tool_excel_report("wpscan", url, result)
            if report_id:
                result['excel_report_id'] = report_id
                result['excel_download_url'] = f"/api/download-report/{report_id}"
                logger.info(f"WPScan扫描Excel报告已生成: {report_id}")
        except Exception as e:
            logger.warning(f"生成WPScan扫描Excel报告失败: {str(e)}")
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in wpscan endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/enum4linux", methods=["POST"])
def enum4linux():
    """Execute enum4linux with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "-a")
        
        if not target:
            logger.warning("Enum4linux called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"enum4linux {additional_args} {target}"
        
        result = execute_command(command)
        
        # 存储扫描结果
        try:
            store_scan_result("enum4linux", target, result)
            logger.info(f"Enum4linux扫描结果已存储: 目标={target}")
        except Exception as e:
            logger.warning(f"存储Enum4linux扫描结果失败: {str(e)}")
        
        # 生成Excel报告
        try:
            result['command'] = command
            report_id = generate_single_tool_excel_report("enum4linux", target, result)
            if report_id:
                result['excel_report_id'] = report_id
                result['excel_download_url'] = f"/api/download-report/{report_id}"
                logger.info(f"Enum4linux扫描Excel报告已生成: {report_id}")
        except Exception as e:
            logger.warning(f"生成Enum4linux扫描Excel报告失败: {str(e)}")
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in enum4linux endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/urlfinder", methods=["POST"])
def urlfinder():
    """Execute URLFinder with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        mode = params.get("mode", 1)  # 1=normal, 2=thorough, 3=security
        user_agent = params.get("user_agent", "")
        baseurl = params.get("baseurl", "")
        cookie = params.get("cookie", "")
        domain_name = params.get("domain_name", "")
        url_file = params.get("url_file", "")
        url_file_one = params.get("url_file_one", "")
        config_file = params.get("config_file", "")
        maximum = params.get("maximum", 99999)
        out_file = params.get("out_file", "")
        status = params.get("status", "")
        thread = params.get("thread", 50)
        timeout = params.get("timeout", 5)
        proxy = params.get("proxy", "")
        fuzz = params.get("fuzz", 0)  # 0=no fuzz, 1=decreasing, 2=2combination, 3=3combination
        additional_args = params.get("additional_args", "")
        
        # 验证必需参数
        if not url and not url_file and not url_file_one:
            logger.warning("URLFinder called without url, url_file, or url_file_one parameter")
            return jsonify({
                "error": "URL, url_file, or url_file_one parameter is required"
            }), 400
        
        # 构建URLFinder命令
        command = "URLFinder"
        
        # 添加各种参数
        if url:
            command += f" -u {url}"
        if url_file:
            command += f" -f {url_file}"
        if url_file_one:
            command += f" -ff {url_file_one}"
        if user_agent:
            command += f" -a '{user_agent}'"
        if baseurl:
            command += f" -b {baseurl}"
        if cookie:
            command += f" -c '{cookie}'"
        if domain_name:
            command += f" -d '{domain_name}'"
        if config_file:
            command += f" -i {config_file}"
        if mode != 1:
            command += f" -m {mode}"
        if maximum != 99999:
            command += f" -max {maximum}"
        if out_file:
            command += f" -o {out_file}"
        if status:
            command += f" -s {status}"
        if thread != 50:
            command += f" -t {thread}"
        if timeout != 5:
            command += f" -time {timeout}"
        if proxy:
            command += f" -x {proxy}"
        if fuzz > 0:
            command += f" -z {fuzz}"
        if additional_args:
            command += f" {additional_args}"
        
        logger.info(f"Executing URLFinder command: {command}")
        result = execute_command(command)
        
        # 存储扫描结果用于攻击路径分析
        target_info = url or url_file or url_file_one
        store_scan_result("urlfinder", target_info, result)
        
        # 生成Excel报告
        try:
            result['command'] = command
            report_id = generate_single_tool_excel_report("urlfinder", target_info, result)
            if report_id:
                result['excel_report_id'] = report_id
                result['excel_download_url'] = f"/api/download-report/{report_id}"
                logger.info(f"URLFinder扫描Excel报告已生成: {report_id}")
        except Exception as e:
            logger.warning(f"生成URLFinder扫描Excel报告失败: {str(e)}")
        
        # AI分析功能已移除
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in urlfinder endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


@app.route("/api/version", methods=["GET"])
def get_version_endpoint():
    """
    获取系统版本信息API端点
    
    提供详细的版本信息、更新历史和系统环境信息
    """
    try:
        logger.debug("获取版本信息")
        
        version_info = get_version_info()
        
        # 添加运行时信息
        runtime_info = {
            "uptime_seconds": time.time() - start_time if 'start_time' in globals() else 0,
            "total_scans_processed": len(scan_manager.scan_history),
            "cache_files_count": len([f for f in os.listdir(CACHE_DIR) if f.endswith('.json')]) if os.path.exists(CACHE_DIR) else 0,
            "reports_generated": len(scan_manager.excel_reports),
            "configuration_loaded": True
        }
        
        # 合并版本信息和运行时信息
        response_data = {
            **version_info,
            "runtime_info": runtime_info,
            "version_history": VersionManager.VERSION_HISTORY
        }
        
        logger.info(f"版本信息查询成功: v{__version__}")
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"获取版本信息失败: {str(e)}", exc_info=True)
        return jsonify({
            "error": "获取版本信息失败",
            "details": str(e)
        }), 500


@app.route("/api/statistics", methods=["GET"])
def get_scan_statistics_endpoint():
    """
    获取扫描统计信息API端点
    
    提供系统运行状态、扫描历史统计和性能监控数据
    """
    try:
        logger.debug("获取扫描统计信息")
        
        # 获取基本统计信息
        stats = get_scan_statistics()
        
        # 添加系统信息
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
        
        # 添加配置信息
        config_info = {
            'api_port': API_PORT,
            'debug_mode': DEBUG_MODE,
            'command_timeout': COMMAND_TIMEOUT,
            'max_scan_history': MAX_SCAN_HISTORY,
    
            'cache_dir': CACHE_DIR,
            'reports_dir': REPORTS_DIR
        }
        
        # 使用ToolChecker检查工具可用性
        tools_check_result = ToolChecker.check_all_tools()
        tools_status = {name: info['installed'] for name, info in tools_check_result['tools'].items()}
        
        # 组合所有信息
        response_data = {
            'scan_statistics': stats,
            'system_info': system_info,
            'configuration': config_info,
            'tools_status': tools_status,
            'tools_detailed': tools_check_result,
            'all_tools_available': tools_check_result['summary']['all_required_installed'],
            'server_uptime': 'N/A',  # 可以添加服务器启动时间跟踪
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        return jsonify(response_data)
        
    except ImportError:
        # 如果psutil不可用，返回基本统计信息
        logger.warning("psutil模块不可用，返回基本统计信息")
        stats = get_scan_statistics()
        return jsonify({
            'scan_statistics': stats,
            'system_info': {'error': 'psutil模块不可用'},
            'timestamp': datetime.datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"获取统计信息失败: {str(e)}", exc_info=True)
        return jsonify({
            'error': f'获取统计信息失败: {str(e)}',
            'timestamp': datetime.datetime.now().isoformat()
        }), 500

@app.route("/health", methods=["GET"])
def health_check():
    """
    健康检查端点
    
    提供服务器基本状态和工具可用性检查
    """
    try:
        logger.debug("执行健康检查")
        
        # 使用ToolChecker进行完整健康检查
        health_result = tool_health_check()
        
        # 提取工具状态信息
        tools_check = health_result["checks"]["tools"]
        tools_status = {name: info['installed'] for name, info in tools_check['tools'].items()}
        all_essential_tools_available = tools_check['summary']['all_required_installed']
        
        # 检查缓存目录
        cache_accessible = os.path.exists(CACHE_DIR) and os.access(CACHE_DIR, os.W_OK)
        
        # 检查报告目录
        reports_accessible = os.path.exists(REPORTS_DIR) and os.access(REPORTS_DIR, os.W_OK)
        
        ai_status = "removed"
        ai_provider = "none"
        
        # 根据健康检查结果确定状态
        overall_status = health_result["overall_status"]
        if overall_status == "healthy":
            status = "healthy"
        elif overall_status == "warning":
            status = "degraded"
        else:
            status = "unhealthy"
        
        health_status = {
            "status": status,
            "overall_health": overall_status,
            "ai_status": ai_status,
            "ai_provider": ai_provider, 
            "message": "Kali Linux Tools API Server is running",
            "tools_status": tools_status,
            "all_essential_tools_available": all_essential_tools_available,
            "cache_accessible": cache_accessible,
            "reports_accessible": reports_accessible,
            "scan_history_count": len(scan_manager.scan_history),
            "excel_reports_count": len(scan_manager.excel_reports),
            "detailed_health": health_result,
            "timestamp": datetime.datetime.now().isoformat()
        }
        
        # 添加问题和警告信息
        if "issues" in health_result:
            health_status["issues"] = health_result["issues"]
        if "warnings" in health_result:
            health_status["warnings"] = health_result["warnings"]
        
        # 如果有工具不可用，添加额外警告信息
        if not all_essential_tools_available:
            missing_tools = [tool for tool, available in tools_status.items() if not available]
            additional_warning = f"以下工具不可用: {', '.join(missing_tools)}"
            if "warnings" not in health_status:
                health_status["warnings"] = []
            health_status["warnings"].append(additional_warning)
        
        return jsonify(health_status)
        
    except Exception as e:
        logger.error(f"健康检查失败: {str(e)}", exc_info=True)
        return jsonify({
            "status": "unhealthy",
            "error": f"健康检查失败: {str(e)}",
            "timestamp": datetime.datetime.now().isoformat()
        }), 500

    

@app.route("/mcp/capabilities", methods=["GET"])
def get_capabilities():
    # Return tool capabilities similar to our existing MCP server
    pass

@app.route("/mcp/tools/kali_tools/<tool_name>", methods=["POST"])
def execute_tool(tool_name):
    # Direct tool execution without going through the API server
    pass

@app.route("/api/download-report/<report_id>", methods=["GET"])
def download_excel_report(report_id):
    """下载Excel扫描报告"""
    try:
        report_data = scan_manager.get_excel_report(report_id)
        if report_data is None:
            return jsonify({"error": "Report not found or expired"}), 404
        
        # 创建BytesIO对象
        output = BytesIO(report_data)
        output.seek(0)
        
        # 生成文件名
        filename = f"security_scan_report_{report_id}.xlsx"
        
        logger.info(f"下载Excel报告: {report_id}")
        
        return send_file(
            output,
            as_attachment=True,
            download_name=filename,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        
    except Exception as e:
        logger.error(f"Error downloading report {report_id}: {str(e)}")
        return jsonify({"error": f"Failed to download report: {str(e)}"}), 500

@app.route("/api/reports", methods=["GET"])
def list_reports():
    """列出所有可用的Excel报告"""
    try:
        reports = []
        for report_id in scan_manager.excel_reports.keys():
            reports.append({
                "report_id": report_id,
                "download_url": f"/api/download-report/{report_id}",
                "size_bytes": len(scan_manager.excel_reports[report_id])
            })
        
        return jsonify({
            "reports": reports,
            "total_count": len(reports)
        })
        
    except Exception as e:
        logger.error(f"Error listing reports: {str(e)}")
        return jsonify({"error": f"Failed to list reports: {str(e)}"}), 500

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the Kali Linux API Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=config.API_PORT, help=f"Port for the API server (default: {config.API_PORT})")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    
    # 使用config模块更新配置
    config.update_from_args(args)
    
    logger.info(f"Starting Kali Linux Tools API Server on port {config.API_PORT}")
    app.run(host="0.0.0.0", port=config.API_PORT, debug=config.DEBUG_MODE)
