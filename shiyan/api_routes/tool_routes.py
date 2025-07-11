"""工具相关路由模块

包含所有安全工具的API端点，如nmap、gobuster、nikto等。
"""

import traceback
from flask import Blueprint, request, jsonify
from command_executor import execute_command
from scan_manager import store_scan_result, generate_single_tool_excel_report
from config import logger

# 创建工具路由蓝图
tool_bp = Blueprint('tools', __name__, url_prefix='/api/tools')

# 使用配置中的日志记录器

@tool_bp.route('/nmap', methods=['POST'])
def nmap():
    """Execute nmap with the provided parameters."""
    try:
        params = request.json
        target = params.get('target', '')
        scan_type = params.get('scan_type', 'basic')
        additional_args = params.get('additional_args', '')
        
        if not target:
            logger.warning('Nmap called without target parameter')
            return jsonify({
                'error': 'Target parameter is required'
            }), 400
        
        # 构建nmap命令
        if scan_type == 'basic':
            command = f'nmap {target}'
        elif scan_type == 'syn':
            command = f'nmap -sS {target}'
        elif scan_type == 'udp':
            command = f'nmap -sU {target}'
        elif scan_type == 'comprehensive':
            command = f'nmap -sS -sV -O -A {target}'
        elif scan_type == 'stealth':
            command = f'nmap -sS -T2 {target}'
        elif scan_type == 'aggressive':
            command = f'nmap -T4 -A -v {target}'
        else:
            command = f'nmap {target}'
        
        if additional_args:
            command += f' {additional_args}'
        
        result = execute_command(command)
        
        # 存储扫描结果
        try:
            store_scan_result('nmap', target, result)
            logger.info(f'Nmap扫描结果已存储: 目标={target}')
        except Exception as e:
            logger.warning(f'存储Nmap扫描结果失败: {str(e)}')
        
        # 生成Excel报告
        try:
            result['command'] = command
            report_id = generate_single_tool_excel_report('nmap', target, result)
            if report_id:
                result['excel_report_id'] = report_id
                result['excel_download_url'] = f'/api/download-report/{report_id}'
                logger.info(f'Nmap扫描Excel报告已生成: {report_id}')
        except Exception as e:
            logger.warning(f'生成Nmap扫描Excel报告失败: {str(e)}')
        
        return jsonify(result)
    except Exception as e:
        logger.error(f'Error in nmap endpoint: {str(e)}')
        logger.error(traceback.format_exc())
        return jsonify({
            'error': f'Server error: {str(e)}'
        }), 500

@tool_bp.route('/gobuster', methods=['POST'])
def gobuster():
    """Execute gobuster with the provided parameters."""
    try:
        params = request.json
        url = params.get('url', '')
        wordlist = params.get('wordlist', '/usr/share/wordlists/dirb/common.txt')
        extensions = params.get('extensions', '')
        threads = params.get('threads', 10)
        additional_args = params.get('additional_args', '')
        mode = params.get('mode', 'dir')
        
        if not url:
            logger.warning('Gobuster called without URL parameter')
            return jsonify({
                'error': 'URL parameter is required'
            }), 400
        
        try:
            from security_tools.gobuster_wrapper import GobusterWrapper
            gobuster_wrapper = GobusterWrapper()
            
            # 验证参数
            validation_result = gobuster_wrapper.validate_params(
                url=url,
                wordlist=wordlist,
                extensions=extensions,
                threads=threads,
                additional_args=additional_args
            )
            
            if not validation_result.get('success', False):
                logger.warning(f'Gobuster参数验证失败: {validation_result.get("error", "未知错误")}')
                return jsonify({
                    'error': validation_result.get('error', '参数验证失败')
                }), 400
            
            # 构建命令
            command = gobuster_wrapper.build_command(
                mode=mode,
                url=url,
                wordlist=wordlist,
                extensions=extensions,
                threads=threads,
                additional_args=additional_args
            )
            
            # 执行命令
            result = execute_command(command)
            
            # 使用wrapper解析输出
            if result.get('success', False):
                parsed_result = gobuster_wrapper.parse_output(
                    result.get('stdout', ''),
                    result.get('stderr', '')
                )
                result.update(parsed_result)
                
        except ImportError:
            # 如果wrapper不可用，回退到原始方法
            logger.warning('Gobuster wrapper不可用，使用原始命令构建方法')
            command = f'gobuster dir -u {url} -w {wordlist} -t {threads}'
            
            if extensions:
                command += f' -x {extensions}'
            
            if additional_args:
                command += f' {additional_args}'
            
            result = execute_command(command)
        
        # 存储扫描结果
        try:
            store_scan_result('gobuster', url, result)
            logger.info(f'Gobuster扫描结果已存储: 目标={url}')
        except Exception as e:
            logger.warning(f'存储Gobuster扫描结果失败: {str(e)}')
        
        # 生成Excel报告
        try:
            result['command'] = command
            report_id = generate_single_tool_excel_report('gobuster', url, result)
            if report_id:
                result['excel_report_id'] = report_id
                result['excel_download_url'] = f'/api/download-report/{report_id}'
                logger.info(f'Gobuster扫描Excel报告已生成: {report_id}')
        except Exception as e:
            logger.warning(f'生成Gobuster扫描Excel报告失败: {str(e)}')
        
        return jsonify(result)
    except Exception as e:
        logger.error(f'Error in gobuster endpoint: {str(e)}')
        logger.error(traceback.format_exc())
        return jsonify({
            'error': f'Server error: {str(e)}'
        }), 500

@tool_bp.route('/dirb', methods=['POST'])
def dirb():
    """Execute dirb with the provided parameters."""
    try:
        params = request.json
        url = params.get('url', '')
        wordlist = params.get('wordlist', '/usr/share/dirb/wordlists/common.txt')
        extensions = params.get('extensions', '')
        additional_args = params.get('additional_args', '')
        
        if not url:
            logger.warning('Dirb called without URL parameter')
            return jsonify({
                'error': 'URL parameter is required'
            }), 400
        
        command = f'dirb {url} {wordlist}'
        
        if extensions:
            command += f' -X {extensions}'
        
        if additional_args:
            command += f' {additional_args}'
        
        result = execute_command(command)
        
        # 存储扫描结果
        try:
            store_scan_result('dirb', url, result)
            logger.info(f'Dirb扫描结果已存储: 目标={url}')
        except Exception as e:
            logger.warning(f'存储Dirb扫描结果失败: {str(e)}')
        
        # 生成Excel报告
        try:
            result['command'] = command
            report_id = generate_single_tool_excel_report('dirb', url, result)
            if report_id:
                result['excel_report_id'] = report_id
                result['excel_download_url'] = f'/api/download-report/{report_id}'
                logger.info(f'Dirb扫描Excel报告已生成: {report_id}')
        except Exception as e:
            logger.warning(f'生成Dirb扫描Excel报告失败: {str(e)}')
        
        return jsonify(result)
    except Exception as e:
        logger.error(f'Error in dirb endpoint: {str(e)}')
        logger.error(traceback.format_exc())
        return jsonify({
            'error': f'Server error: {str(e)}'
        }), 500

@tool_bp.route('/nikto', methods=['POST'])
def nikto():
    """Execute nikto with the provided parameters."""
    try:
        params = request.json
        # 支持两种参数名以保持向后兼容性
        host = params.get('host', '') or params.get('target', '')
        port = params.get('port', 80)
        ssl = params.get('ssl', False)
        additional_args = params.get('additional_args', '')
        
        if not host:
            logger.warning('Nikto called without host/target parameter')
            return jsonify({
                'error': 'Host or target parameter is required'
            }), 400
        
        try:
            from security_tools.nikto_wrapper import NiktoWrapper
            nikto_wrapper = NiktoWrapper()
            
            # 验证参数
            validation_result = nikto_wrapper.validate_params(
                host=host,
                port=port,
                ssl=ssl,
                additional_args=additional_args
            )
            
            if not validation_result.get('success', False):
                logger.warning(f'Nikto参数验证失败: {validation_result.get("error", "未知错误")}')
                return jsonify({
                    'error': validation_result.get('error', '参数验证失败')
                }), 400
            
            # 构建命令
            command = nikto_wrapper.build_command(
                host=host,
                port=port,
                ssl=ssl,
                additional_args=additional_args
            )
            
            # 执行命令
            result = execute_command(command)
            
            # 使用wrapper解析输出
            if result.get('success', False):
                parsed_result = nikto_wrapper.parse_output(
                    result.get('stdout', ''),
                    result.get('stderr', '')
                )
                result.update(parsed_result)
                
        except ImportError:
            # 如果wrapper不可用，回退到原始方法
            logger.warning('Nikto wrapper不可用，使用原始命令构建方法')
            command = f'nikto -h {host} -p {port}'
            
            if ssl:
                command += ' -ssl'
            
            if additional_args:
                command += f' {additional_args}'
            
            result = execute_command(command)
        
        # 存储扫描结果
        try:
            store_scan_result('nikto', host, result)
            logger.info(f'Nikto扫描结果已存储: 目标={host}')
        except Exception as e:
            logger.warning(f'存储Nikto扫描结果失败: {str(e)}')
        
        # 生成Excel报告
        try:
            result['command'] = command
            report_id = generate_single_tool_excel_report('nikto', host, result)
            if report_id:
                result['excel_report_id'] = report_id
                result['excel_download_url'] = f'/api/download-report/{report_id}'
                logger.info(f'Nikto扫描Excel报告已生成: {report_id}')
        except Exception as e:
            logger.warning(f'生成Nikto扫描Excel报告失败: {str(e)}')
        
        return jsonify(result)
    except Exception as e:
        logger.error(f'Error in nikto endpoint: {str(e)}')
        logger.error(traceback.format_exc())
        return jsonify({
            'error': f'Server error: {str(e)}'
        }), 500

@tool_bp.route('/sqlmap', methods=['POST'])
def sqlmap():
    """Execute sqlmap with the provided parameters."""
    try:
        params = request.json
        url = params.get('url', '')
        data = params.get('data', '')
        cookie = params.get('cookie', '')
        level = params.get('level', 1)
        risk = params.get('risk', 1)
        additional_args = params.get('additional_args', '')
        
        if not url:
            logger.warning('SQLMap called without URL parameter')
            return jsonify({
                'error': 'URL parameter is required'
            }), 400
        
        command = f'sqlmap -u "{url}" --level={level} --risk={risk} --batch'
        
        if data:
            command += f' --data="{data}"'
        
        if cookie:
            command += f' --cookie="{cookie}"'
        
        if additional_args:
            command += f' {additional_args}'
        
        result = execute_command(command)
        
        # 存储扫描结果
        try:
            store_scan_result('sqlmap', url, result)
            logger.info(f'SQLMap扫描结果已存储: 目标={url}')
        except Exception as e:
            logger.warning(f'存储SQLMap扫描结果失败: {str(e)}')
        
        # 生成Excel报告
        try:
            result['command'] = command
            report_id = generate_single_tool_excel_report('sqlmap', url, result)
            if report_id:
                result['excel_report_id'] = report_id
                result['excel_download_url'] = f'/api/download-report/{report_id}'
                logger.info(f'SQLMap扫描Excel报告已生成: {report_id}')
        except Exception as e:
            logger.warning(f'生成SQLMap扫描Excel报告失败: {str(e)}')
        
        return jsonify(result)
    except Exception as e:
        logger.error(f'Error in sqlmap endpoint: {str(e)}')
        logger.error(traceback.format_exc())
        return jsonify({
            'error': f'Server error: {str(e)}'
        }), 500

@tool_bp.route('/metasploit', methods=['POST'])
def metasploit():
    """Execute metasploit with the provided parameters."""
    try:
        params = request.json
        module = params.get('module', '')
        target = params.get('target', '')
        payload = params.get('payload', '')
        options = params.get('options', {})
        additional_args = params.get('additional_args', '')
        
        if not module or not target:
            logger.warning('Metasploit called without required parameters')
            return jsonify({
                'error': 'Module and target parameters are required'
            }), 400
        
        # 构建msfconsole命令
        commands = [
            f'use {module}',
            f'set RHOSTS {target}'
        ]
        
        if payload:
            commands.append(f'set PAYLOAD {payload}')
        
        for key, value in options.items():
            commands.append(f'set {key} {value}')
        
        commands.append('run')
        commands.append('exit')
        
        # 创建临时脚本文件
        script_content = '\n'.join(commands)
        command = f'echo "{script_content}" | msfconsole -q'
        
        if additional_args:
            command += f' {additional_args}'
        
        result = execute_command(command)
        
        # 存储扫描结果
        try:
            store_scan_result('metasploit', target, result)
            logger.info(f'Metasploit扫描结果已存储: 目标={target}')
        except Exception as e:
            logger.warning(f'存储Metasploit扫描结果失败: {str(e)}')
        
        # 生成Excel报告
        try:
            result['command'] = command
            report_id = generate_single_tool_excel_report('metasploit', target, result)
            if report_id:
                result['excel_report_id'] = report_id
                result['excel_download_url'] = f'/api/download-report/{report_id}'
                logger.info(f'Metasploit扫描Excel报告已生成: {report_id}')
        except Exception as e:
            logger.warning(f'生成Metasploit扫描Excel报告失败: {str(e)}')
        
        return jsonify(result)
    except Exception as e:
        logger.error(f'Error in metasploit endpoint: {str(e)}')
        logger.error(traceback.format_exc())
        return jsonify({
            'error': f'Server error: {str(e)}'
        }), 500

@tool_bp.route('/hydra', methods=['POST'])
def hydra():
    """Execute hydra with the provided parameters."""
    try:
        params = request.json
        target = params.get('target', '')
        service = params.get('service', 'ssh')
        username = params.get('username', '')
        password = params.get('password', '')
        userlist = params.get('userlist', '')
        passlist = params.get('passlist', '')
        port = params.get('port', '')
        additional_args = params.get('additional_args', '')
        
        if not target:
            logger.warning('Hydra called without target parameter')
            return jsonify({
                'error': 'Target parameter is required'
            }), 400
        
        command = f'hydra'
        
        if username:
            command += f' -l {username}'
        elif userlist:
            command += f' -L {userlist}'
        
        if password:
            command += f' -p {password}'
        elif passlist:
            command += f' -P {passlist}'
        
        if port:
            command += f' -s {port}'
        
        command += f' {target} {service}'
        
        if additional_args:
            command += f' {additional_args}'
        
        result = execute_command(command)
        
        # 存储扫描结果
        try:
            store_scan_result('hydra', target, result)
            logger.info(f'Hydra扫描结果已存储: 目标={target}')
        except Exception as e:
            logger.warning(f'存储Hydra扫描结果失败: {str(e)}')
        
        # 生成Excel报告
        try:
            result['command'] = command
            report_id = generate_single_tool_excel_report('hydra', target, result)
            if report_id:
                result['excel_report_id'] = report_id
                result['excel_download_url'] = f'/api/download-report/{report_id}'
                logger.info(f'Hydra扫描Excel报告已生成: {report_id}')
        except Exception as e:
            logger.warning(f'生成Hydra扫描Excel报告失败: {str(e)}')
        
        return jsonify(result)
    except Exception as e:
        logger.error(f'Error in hydra endpoint: {str(e)}')
        logger.error(traceback.format_exc())
        return jsonify({
            'error': f'Server error: {str(e)}'
        }), 500

@tool_bp.route('/john', methods=['POST'])
def john():
    """Execute john with the provided parameters."""
    try:
        params = request.json
        hash_file = params.get('hash_file', '')
        wordlist = params.get('wordlist', '/usr/share/wordlists/rockyou.txt')
        format_type = params.get('format', '')
        additional_args = params.get('additional_args', '')
        
        if not hash_file:
            logger.warning('John called without hash_file parameter')
            return jsonify({
                'error': 'Hash file parameter is required'
            }), 400
        
        command = f'john {hash_file}'
        
        if wordlist:
            command += f' --wordlist={wordlist}'
        
        if format_type:
            command += f' --format={format_type}'
        
        if additional_args:
            command += f' {additional_args}'
        
        result = execute_command(command)
        
        # 存储扫描结果
        try:
            store_scan_result('john', hash_file, result)
            logger.info(f'John扫描结果已存储: 目标={hash_file}')
        except Exception as e:
            logger.warning(f'存储John扫描结果失败: {str(e)}')
        
        # 生成Excel报告
        try:
            result['command'] = command
            report_id = generate_single_tool_excel_report('john', hash_file, result)
            if report_id:
                result['excel_report_id'] = report_id
                result['excel_download_url'] = f'/api/download-report/{report_id}'
                logger.info(f'John扫描Excel报告已生成: {report_id}')
        except Exception as e:
            logger.warning(f'生成John扫描Excel报告失败: {str(e)}')
        
        return jsonify(result)
    except Exception as e:
        logger.error(f'Error in john endpoint: {str(e)}')
        logger.error(traceback.format_exc())
        return jsonify({
            'error': f'Server error: {str(e)}'
        }), 500

@tool_bp.route('/wpscan', methods=['POST'])
def wpscan():
    """Execute wpscan with the provided parameters."""
    try:
        params = request.json
        url = params.get('url', '')
        additional_args = params.get('additional_args', '')
        
        if not url:
            logger.warning('WPScan called without URL parameter')
            return jsonify({
                'error': 'URL parameter is required'
            }), 400
        
        command = f'wpscan --url {url}'
        
        if additional_args:
            command += f' {additional_args}'
        
        result = execute_command(command)
        
        # 存储扫描结果
        try:
            store_scan_result('wpscan', url, result)
            logger.info(f'WPScan扫描结果已存储: 目标={url}')
        except Exception as e:
            logger.warning(f'存储WPScan扫描结果失败: {str(e)}')
        
        # 生成Excel报告
        try:
            result['command'] = command
            report_id = generate_single_tool_excel_report('wpscan', url, result)
            if report_id:
                result['excel_report_id'] = report_id
                result['excel_download_url'] = f'/api/download-report/{report_id}'
                logger.info(f'WPScan扫描Excel报告已生成: {report_id}')
        except Exception as e:
            logger.warning(f'生成WPScan扫描Excel报告失败: {str(e)}')
        
        return jsonify(result)
    except Exception as e:
        logger.error(f'Error in wpscan endpoint: {str(e)}')
        logger.error(traceback.format_exc())
        return jsonify({
            'error': f'Server error: {str(e)}'
        }), 500

@tool_bp.route('/enum4linux', methods=['POST'])
def enum4linux():
    """Execute enum4linux with the provided parameters."""
    try:
        params = request.json
        target = params.get('target', '')
        additional_args = params.get('additional_args', '-a')
        
        if not target:
            logger.warning('Enum4linux called without target parameter')
            return jsonify({
                'error': 'Target parameter is required'
            }), 400
        
        command = f'enum4linux {additional_args} {target}'
        
        result = execute_command(command)
        
        # 存储扫描结果
        try:
            store_scan_result('enum4linux', target, result)
            logger.info(f'Enum4linux扫描结果已存储: 目标={target}')
        except Exception as e:
            logger.warning(f'存储Enum4linux扫描结果失败: {str(e)}')
        
        # 生成Excel报告
        try:
            result['command'] = command
            report_id = generate_single_tool_excel_report('enum4linux', target, result)
            if report_id:
                result['excel_report_id'] = report_id
                result['excel_download_url'] = f'/api/download-report/{report_id}'
                logger.info(f'Enum4linux扫描Excel报告已生成: {report_id}')
        except Exception as e:
            logger.warning(f'生成Enum4linux扫描Excel报告失败: {str(e)}')
        
        return jsonify(result)
    except Exception as e:
        logger.error(f'Error in enum4linux endpoint: {str(e)}')
        logger.error(traceback.format_exc())
        return jsonify({
            'error': f'Server error: {str(e)}'
        }), 500

@tool_bp.route('/urlfinder', methods=['POST'])
def urlfinder():
    """Execute URLFinder with the provided parameters."""
    try:
        params = request.json
        url = params.get('url', '')
        mode = params.get('mode', 1)  # 1=normal, 2=thorough, 3=security
        user_agent = params.get('user_agent', '')
        baseurl = params.get('baseurl', '')
        cookie = params.get('cookie', '')
        domain_name = params.get('domain_name', '')
        url_file = params.get('url_file', '')
        url_file_one = params.get('url_file_one', '')
        config_file = params.get('config_file', '')
        maximum = params.get('maximum', 99999)
        out_file = params.get('out_file', '')
        status = params.get('status', '')
        thread = params.get('thread', 50)
        timeout = params.get('timeout', 5)
        proxy = params.get('proxy', '')
        fuzz = params.get('fuzz', 0)  # 0=no fuzz, 1=decreasing, 2=2combination, 3=3combination
        additional_args = params.get('additional_args', '')
        
        # 验证必需参数
        if not url and not url_file and not url_file_one:
            logger.warning('URLFinder called without url, url_file, or url_file_one parameter')
            return jsonify({
                'error': 'URL, url_file, or url_file_one parameter is required'
            }), 400
        
        # 构建URLFinder命令
        command = 'URLFinder'
        
        # 添加各种参数
        if url:
            command += f' -u {url}'
        if url_file:
            command += f' -f {url_file}'
        if url_file_one:
            command += f' -ff {url_file_one}'
        if user_agent:
            command += f' -a \'{user_agent}\''
        if baseurl:
            command += f' -b {baseurl}'
        if cookie:
            command += f' -c \'{cookie}\''
        if domain_name:
            command += f' -d \'{domain_name}\''
        if config_file:
            command += f' -i {config_file}'
        if mode != 1:
            command += f' -m {mode}'
        if maximum != 99999:
            command += f' -max {maximum}'
        if out_file:
            command += f' -o {out_file}'
        if status:
            command += f' -s {status}'
        if thread != 50:
            command += f' -t {thread}'
        if timeout != 5:
            command += f' -time {timeout}'
        if proxy:
            command += f' -x {proxy}'
        if fuzz > 0:
            command += f' -z {fuzz}'
        if additional_args:
            command += f' {additional_args}'
        
        logger.info(f'Executing URLFinder command: {command}')
        result = execute_command(command)
        
        # 存储扫描结果用于攻击路径分析
        target_info = url or url_file or url_file_one
        store_scan_result('urlfinder', target_info, result)
        
        # 生成Excel报告
        try:
            result['command'] = command
            report_id = generate_single_tool_excel_report('urlfinder', target_info, result)
            if report_id:
                result['excel_report_id'] = report_id
                result['excel_download_url'] = f'/api/download-report/{report_id}'
                logger.info(f'URLFinder扫描Excel报告已生成: {report_id}')
        except Exception as e:
            logger.warning(f'生成URLFinder扫描Excel报告失败: {str(e)}')
        
        return jsonify(result)
    except Exception as e:
        logger.error(f'Error in urlfinder endpoint: {str(e)}')
        logger.error(traceback.format_exc())
        return jsonify({
            'error': f'Server error: {str(e)}'
        }), 500

@tool_bp.route('/command', methods=['POST'])
def execute_custom_command():
    """Execute a custom command."""
    try:
        params = request.json
        command = params.get('command', '')
        
        if not command:
            logger.warning('Custom command called without command parameter')
            return jsonify({
                'error': 'Command parameter is required'
            }), 400
        
        logger.info(f'Executing custom command: {command}')
        result = execute_command(command)
        
        return jsonify(result)
    except Exception as e:
        logger.error(f'Error in custom command endpoint: {str(e)}')
        logger.error(traceback.format_exc())
        return jsonify({
            'error': f'Server error: {str(e)}'
        }), 500