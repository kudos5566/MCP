#!/usr/bin/env python3

import sys
import os
import argparse
import logging
import json
import asyncio
from typing import Dict, Any, Optional
import requests
from mcp.server.fastmcp import FastMCP
# AI适配器导入已移除 

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_REQUEST_TIMEOUT = 300  # 5 minutes default timeout for API requests

class KaliToolsClient:
    """Client for communicating with the Kali Linux Tools API Server"""
    
    def __init__(self, server_url: str, timeout: int = DEFAULT_REQUEST_TIMEOUT):
        """
        Initialize the Kali Tools Client
        
        Args:
            server_url: URL of the Kali Tools API Server
            timeout: Request timeout in seconds
        """
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        logger.info(f"Initialized Kali Tools Client connecting to {server_url}")
        
    def safe_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform a GET request with optional query parameters.
        
        Args:
            endpoint: API endpoint path (without leading slash)
            params: Optional query parameters
            
        Returns:
            Response data as dictionary
        """
        if params is None:
            params = {}

        url = f"{self.server_url}/{endpoint}"

        try:
            logger.debug(f"GET {url} with params: {params}")
            response = requests.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def safe_post(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform a POST request with JSON data.
        
        Args:
            endpoint: API endpoint path (without leading slash)
            json_data: JSON data to send
            
        Returns:
            Response data as dictionary
        """
        url = f"{self.server_url}/{endpoint}"
        
        try:
            logger.debug(f"POST {url} with data: {json_data}")
            response = requests.post(url, json=json_data, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def execute_command(self, command: str) -> Dict[str, Any]:
        """
        Execute a generic command on the Kali server
        
        Args:
            command: Command to execute
            
        Returns:
            Command execution results
        """
        return self.safe_post("api/command", {"command": command})
    
    def check_health(self) -> Dict[str, Any]:
        """
        Check the health of the Kali Tools API Server
        
        Returns:
            Health status information
        """
        return self.safe_get("health")

# EnhancedKaliToolsClient类的AI功能已移除

def setup_mcp_server(kali_client: KaliToolsClient) -> FastMCP:
    """
    Set up the MCP server with all tool functions
    
    Args:
        kali_client: Initialized KaliToolsClient
        
    Returns:
        Configured FastMCP instance
    """
    mcp = FastMCP("kali-mcp-enhanced")

    @mcp.tool()
    def nmap_scan(target: str, scan_type: str = "-sV", ports: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute an Nmap scan against a target. Automatically generates an Excel report.
        
        Args:
            target: The IP address or hostname to scan
            scan_type: Scan type (e.g., -sV for version detection)
            ports: Comma-separated list of ports or port ranges
            additional_args: Additional Nmap arguments
            
        Returns:
            Scan results with Excel report download URL
        """
        data = {
            "target": target,
            "scan_type": scan_type,
            "ports": ports,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/nmap", data)

    @mcp.tool()
    def gobuster_scan(url: str, mode: str = "dir", wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Gobuster to find directories, DNS subdomains, or virtual hosts. Automatically generates an Excel report.
        
        Args:
            url: The target URL
            mode: Scan mode (dir, dns, fuzz, vhost)
            wordlist: Path to wordlist file
            additional_args: Additional Gobuster arguments
            
        Returns:
            Scan results with Excel report download URL
        """
        data = {
            "url": url,
            "mode": mode,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/gobuster", data)

    @mcp.tool()
    def dirb_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Dirb web content scanner. Automatically generates an Excel report.
        
        Args:
            url: The target URL
            wordlist: Path to wordlist file
            additional_args: Additional Dirb arguments
            
        Returns:
            Scan results with Excel report download URL
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/dirb", data)

    @mcp.tool()
    def nikto_scan(target: str, port: int = None, ssl: bool = None, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute Nikto web server scanner. Automatically generates an Excel report.
        
        Args:
            target: The URL, IP address or hostname to scan
            port: The port to scan (auto-detected from URL if not specified)
            ssl: Whether to use SSL (auto-detected from URL if not specified)
            additional_args: Additional Nikto arguments
            
        Returns:
            Scan results with Excel report download URL
        """
        from urllib.parse import urlparse
        
        # Parse the target to extract host, port, and SSL info
        if target.startswith('http://') or target.startswith('https://'):
            parsed = urlparse(target)
            host = parsed.hostname
            
            # Auto-detect SSL from scheme if not explicitly set
            if ssl is None:
                ssl = parsed.scheme == 'https'
            
            # Auto-detect port if not explicitly set
            if port is None:
                if parsed.port:
                    port = parsed.port
                else:
                    port = 443 if ssl else 80
        else:
            # Assume it's a hostname or IP
            host = target
            if port is None:
                port = 80
            if ssl is None:
                ssl = False
        
        data = {
            "host": host,
            "port": port,
            "ssl": ssl,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/nikto", data)

    @mcp.tool()
    def sqlmap_scan(url: str, data: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        Execute SQLmap SQL injection scanner. Automatically generates an Excel report.
        
        Args:
            url: The target URL
            data: POST data string
            additional_args: Additional SQLmap arguments
            
        Returns:
            Scan results with Excel report download URL
        """
        post_data = {
            "url": url,
            "data": data,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/sqlmap", post_data)

    @mcp.tool()
    def metasploit_run(module: str, options: Dict[str, Any] = {}) -> Dict[str, Any]:
        """
        Execute a Metasploit module.
        
        Args:
            module: The Metasploit module path
            options: Dictionary of module options
            
        Returns:
            Module execution results
        """
        data = {
            "module": module,
            "options": options
        }
        return kali_client.safe_post("api/tools/metasploit", data)

    @mcp.tool()
    def hydra_attack(
        target: str, 
        service: str, 
        username: str = "", 
        username_file: str = "", 
        password: str = "", 
        password_file: str = "", 
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute Hydra password cracking tool. Automatically generates an Excel report.
        
        Args:
            target: Target IP or hostname
            service: Service to attack (ssh, ftp, http-post-form, etc.)
            username: Single username to try
            username_file: Path to username file
            password: Single password to try
            password_file: Path to password file
            additional_args: Additional Hydra arguments
            
        Returns:
            Attack results with Excel report download URL
        """
        data = {
            "target": target,
            "service": service,
            "username": username,
            "username_file": username_file,
            "password": password,
            "password_file": password_file,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/hydra", data)

    @mcp.tool()
    def john_crack(
        hash_file: str, 
        wordlist: str = "/usr/share/wordlists/rockyou.txt", 
        format_type: str = "", 
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute John the Ripper password cracker. Automatically generates an Excel report.
        
        Args:
            hash_file: Path to file containing hashes
            wordlist: Path to wordlist file
            format_type: Hash format type
            additional_args: Additional John arguments
            
        Returns:
            Cracking results with Excel report download URL
        """
        data = {
            "hash_file": hash_file,
            "wordlist": wordlist,
            "format": format_type,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/john", data)

    @mcp.tool()
    def wpscan_analyze(url: str, additional_args: str = "") -> Dict[str, Any]:
        """
        Execute WPScan WordPress vulnerability scanner. Automatically generates an Excel report.
        
        Args:
            url: The target WordPress URL
            additional_args: Additional WPScan arguments
            
        Returns:
            Scan results with Excel report download URL
        """
        data = {
            "url": url,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/wpscan", data)

    @mcp.tool()
    def enum4linux_scan(target: str, additional_args: str = "-a") -> Dict[str, Any]:
        """
        Execute Enum4linux Windows/Samba enumeration tool. Automatically generates an Excel report.
        
        Args:
            target: The target IP or hostname
            additional_args: Additional enum4linux arguments
            
        Returns:
            Enumeration results with Excel report download URL
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/enum4linux", data)

    @mcp.tool()
    def urlfinder_scan(
        url: str = "",
        mode: int = 1,
        user_agent: str = "",
        baseurl: str = "",
        cookie: str = "",
        domain_name: str = "",
        url_file: str = "",
        url_file_one: str = "",
        config_file: str = "",
        maximum: int = 99999,
        out_file: str = "",
        status: str = "",
        thread: int = 50,
        timeout: int = 5,
        proxy: str = "",
        fuzz: int = 0,
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        Execute URLFinder to discover URLs and endpoints. Automatically generates an Excel report.
        
        Args:
            url: Target URL to scan
            mode: Scan mode (1=normal, 2=thorough, 3=security)
            user_agent: Custom User-Agent string
            baseurl: Base URL for relative links
            cookie: Cookie string for authentication
            domain_name: Domain name filter
            url_file: File containing multiple URLs
            url_file_one: File with URLs (one per line)
            config_file: Configuration file path
            maximum: Maximum number of URLs to find
            out_file: Output file path
            status: HTTP status codes to filter
            thread: Number of threads to use
            timeout: Request timeout in seconds
            proxy: Proxy server (format: ip:port)
            fuzz: Fuzzing mode (0=no fuzz, 1=decreasing, 2=2combination, 3=3combination)
            additional_args: Additional URLFinder arguments
            
        Returns:
            URL discovery results with Excel report download URL
        """
        data = {
            "url": url,
            "mode": mode,
            "user_agent": user_agent,
            "baseurl": baseurl,
            "cookie": cookie,
            "domain_name": domain_name,
            "url_file": url_file,
            "url_file_one": url_file_one,
            "config_file": config_file,
            "maximum": maximum,
            "out_file": out_file,
            "status": status,
            "thread": thread,
            "timeout": timeout,
            "proxy": proxy,
            "fuzz": fuzz,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/urlfinder", data)

    @mcp.tool()
    def server_health() -> Dict[str, Any]:
        """
        Check the health status of the Kali API server.
        
        Returns:
            Server health information
        """
        return kali_client.check_health()
    
    @mcp.tool()
    def execute_command(command: str) -> Dict[str, Any]:
        """
        Execute an arbitrary command on the Kali server.
        
        Args:
            command: The command to execute
            
        Returns:
            Command execution results
        """
        return kali_client.execute_command(command)
    
    @mcp.tool()
    def download_excel_report(report_id: str, save_path: str = "") -> Dict[str, Any]:
        """
        Download an Excel report generated by a scan tool.
        
        Args:
            report_id: The report ID returned by scan tools
            save_path: Optional local path to save the report
            
        Returns:
            Download status and file information
        """
        try:
            url = f"{kali_client.server_url}/api/reports/{report_id}"
            response = requests.get(url, timeout=kali_client.timeout)
            response.raise_for_status()
            
            if save_path:
                # Save to specified path
                with open(save_path, 'wb') as f:
                    f.write(response.content)
                return {
                    "success": True,
                    "message": f"Report saved to {save_path}",
                    "file_size": len(response.content),
                    "report_id": report_id
                }
            else:
                # Return file content info
                return {
                    "success": True,
                    "message": "Report downloaded successfully",
                    "file_size": len(response.content),
                    "report_id": report_id,
                    "content_type": response.headers.get('content-type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
                }
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to download report {report_id}: {str(e)}")
            return {"error": f"Download failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error downloading report {report_id}: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    return mcp

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the Kali MCP Client")
    parser.add_argument("--server", type=str, required=True, 
                      help="Kali API server URL (required)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
                      help=f"Request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT})")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    # Add subparsers for each tool
    subparsers = parser.add_subparsers(dest='tool_name', help='Tool to run')

    # Nmap subparser
    nmap_parser = subparsers.add_parser('nmap_scan', help='Execute an Nmap scan')
    nmap_parser.add_argument('--target', type=str, required=True, help='The IP address or hostname to scan')
    nmap_parser.add_argument('--scan_type', type=str, default='-sV', help='Scan type (e.g., -sV for version detection)')
    nmap_parser.add_argument('--ports', type=str, default='', help='Comma-separated list of ports or port ranges')
    nmap_parser.add_argument('--additional_args', type=str, default='', help='Additional Nmap arguments')

    # Gobuster subparser
    gobuster_parser = subparsers.add_parser('gobuster_scan', help='Execute Gobuster')
    gobuster_parser.add_argument('--url', type=str, required=True, help='The target URL')
    gobuster_parser.add_argument('--mode', type=str, default='dir', help='Scan mode (dir, dns, fuzz, vhost)')
    gobuster_parser.add_argument('--wordlist', type=str, default='/usr/share/wordlists/dirb/common.txt', help='Path to wordlist file')
    gobuster_parser.add_argument('--additional_args', type=str, default='', help='Additional Gobuster arguments')

    # Dirb subparser
    dirb_parser = subparsers.add_parser('dirb_scan', help='Execute Dirb')
    dirb_parser.add_argument('--url', type=str, required=True, help='The target URL')
    dirb_parser.add_argument('--wordlist', type=str, default='/usr/share/dirb/wordlists/common.txt', help='Path to wordlist file')
    dirb_parser.add_argument('--additional_args', type=str, default='', help='Additional Dirb arguments')

    # Nikto subparser
    nikto_parser = subparsers.add_parser('nikto_scan', help='Execute Nikto')
    nikto_parser.add_argument('--target', type=str, required=True, help='The URL, IP address or hostname to scan')
    nikto_parser.add_argument('--port', type=int, default=None, help='The port to scan (auto-detected from URL if not specified)')
    nikto_parser.add_argument('--ssl', action='store_true', help='Whether to use SSL (auto-detected from URL if not specified)')
    nikto_parser.add_argument('--additional_args', type=str, default='', help='Additional Nikto arguments')

    # SQLmap subparser
    sqlmap_parser = subparsers.add_parser('sqlmap_scan', help='Execute SQLmap')
    sqlmap_parser.add_argument('--url', type=str, required=True, help='The target URL')
    sqlmap_parser.add_argument('--data', type=str, default='', help='POST data string')
    sqlmap_parser.add_argument('--additional_args', type=str, default='', help='Additional SQLmap arguments')

    # Hydra subparser
    hydra_parser = subparsers.add_parser('hydra_attack', help='Execute Hydra')
    hydra_parser.add_argument('--target', type=str, required=True, help='Target IP or hostname')
    hydra_parser.add_argument('--service', type=str, required=True, help='Service to attack (ssh, ftp, http-post-form, etc.)')
    hydra_parser.add_argument('--username', type=str, default='', help='Single username to try')
    hydra_parser.add_argument('--username_file', type=str, default='', help='Path to username file')
    hydra_parser.add_argument('--password', type=str, default='', help='Single password to try')
    hydra_parser.add_argument('--password_file', type=str, default='', help='Path to password file')
    hydra_parser.add_argument('--additional_args', type=str, default='', help='Additional Hydra arguments')

    # John subparser
    john_parser = subparsers.add_parser('john_crack', help='Execute John the Ripper')
    john_parser.add_argument('--hash_file', type=str, required=True, help='Path to file containing hashes')
    john_parser.add_argument('--wordlist', type=str, default='/usr/share/wordlists/rockyou.txt', help='Path to wordlist file')
    john_parser.add_argument('--format_type', type=str, default='', help='Hash format type')
    john_parser.add_argument('--additional_args', type=str, default='', help='Additional John arguments')

    # WPScan subparser
    wpscan_parser = subparsers.add_parser('wpscan_analyze', help='Execute WPScan')
    wpscan_parser.add_argument('--url', type=str, required=True, help='The target WordPress URL')
    wpscan_parser.add_argument('--additional_args', type=str, default='', help='Additional WPScan arguments')

    # Enum4linux subparser
    enum4linux_parser = subparsers.add_parser('enum4linux_scan', help='Execute Enum4linux')
    enum4linux_parser.add_argument('--target', type=str, required=True, help='The target IP or hostname')
    enum4linux_parser.add_argument('--additional_args', type=str, default='-a', help='Additional enum4linux arguments')

    # URLFinder subparser
    urlfinder_parser = subparsers.add_parser('urlfinder_scan', help='Execute URLFinder')
    urlfinder_parser.add_argument('--url', type=str, default='', help='Target URL to scan')
    urlfinder_parser.add_argument('--mode', type=int, default=1, help='Scan mode (1=normal, 2=thorough, 3=security)')
    urlfinder_parser.add_argument('--user_agent', type=str, default='', help='Custom User-Agent string')
    urlfinder_parser.add_argument('--baseurl', type=str, default='', help='Base URL for relative links')
    urlfinder_parser.add_argument('--cookie', type=str, default='', help='Cookie string for authentication')
    urlfinder_parser.add_argument('--domain_name', type=str, default='', help='Domain name filter')
    urlfinder_parser.add_argument('--url_file', type=str, default='', help='File containing multiple URLs')
    urlfinder_parser.add_argument('--url_file_one', type=str, default='', help='File with URLs (one per line)')
    urlfinder_parser.add_argument('--config_file', type=str, default='', help='Configuration file path')
    urlfinder_parser.add_argument('--maximum', type=int, default=99999, help='Maximum number of URLs to find')
    urlfinder_parser.add_argument('--out_file', type=str, default='', help='Output file path')
    urlfinder_parser.add_argument('--status', type=str, default='', help='HTTP status codes to filter')
    urlfinder_parser.add_argument('--thread', type=int, default=50, help='Number of threads to use')
    urlfinder_parser.add_argument('--timeout', type=int, default=5, help='Request timeout in seconds')
    urlfinder_parser.add_argument('--proxy', type=str, default='', help='Proxy server (format: ip:port)')
    urlfinder_parser.add_argument('--fuzz', type=int, default=0, help='Fuzzing mode (0=no fuzz, 1=decreasing, 2=2combination, 3=3combination)')
    urlfinder_parser.add_argument('--additional_args', type=str, default='', help='Additional URLFinder arguments')

    # Server Health subparser
    server_health_parser = subparsers.add_parser('server_health', help='Check server health')

    # Execute Command subparser
    execute_command_parser = subparsers.add_parser('execute_command', help='Execute arbitrary command')
    execute_command_parser.add_argument('--command', type=str, required=True, help='The command to execute')

    # Download Excel Report subparser
    download_report_parser = subparsers.add_parser('download_excel_report', help='Download Excel report')
    download_report_parser.add_argument('--report_id', type=str, required=True, help='The report ID')
    download_report_parser.add_argument('--save_path', type=str, default='', help='Optional local path to save the report')

    return parser.parse_args()

def main():
    """Main entry point for the MCP server."""
    args = parse_args()
    
    # Configure logging based on debug flag
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    # Initialize the Kali Tools client
    kali_client = KaliToolsClient(args.server, args.timeout)
    
    # Check server health and log the result
    health = kali_client.check_health()
    if "error" in health:
        logger.warning(f"Unable to connect to Kali API server at {args.server}: {health['error']}")
        logger.warning("MCP server will start, but tool execution may fail")
    else:
        logger.info(f"Successfully connected to Kali API server at {args.server}")
        logger.info(f"Server health status: {health['status']}")
        if not health.get("all_essential_tools_available", False):
            logger.warning("Not all essential tools are available on the Kali server")
            missing_tools = [tool for tool, available in health.get("tools_status", {}).items() if not available]
            if missing_tools:
                logger.warning(f"Missing tools: {', '.join(missing_tools)}")
    
    mcp = setup_mcp_server(kali_client)
    logger.info("Starting Kali MCP server")
    
    if args.tool_name:
        tool_args = vars(args)
        tool_args.pop('server')
        tool_args.pop('timeout')
        tool_args.pop('debug')
        tool_name = tool_args.pop('tool_name')
        
        # Remove None values from tool_args
        tool_args = {k: v for k, v in tool_args.items() if v is not None}
        
        # Get the tool function from the tool manager
        tool_func = mcp._tool_manager.get_tool(tool_name)
        if tool_func:
            result = asyncio.run(tool_func.run(arguments=tool_args))
            print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print(f"Tool '{tool_name}' not found")
    else:
        mcp.run()

if __name__ == "__main__":
    main()
