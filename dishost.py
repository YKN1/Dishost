#!/usr/bin/env python3
"""
dishost.py - IP Range Scanner with Configurable Health Checks

This script scans IP ranges and performs health checks using various protocols.
Results can be displayed on screen and saved in JSON or CSV formats.
"""

import argparse
import csv
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Dict, List, Optional, Union

import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich import print as rprint


class HealthChecker:
    """Base class for health checks."""
    
    def __init__(self):
        self.timeout = 1.0
    
    def check(self, ip: str) -> Dict:
        """
        Perform health check on an IP.
        
        Args:
            ip: IP address to check
            
        Returns:
            Dict containing check results
        """
        raise NotImplementedError("Subclasses must implement this method")


class ICMPHealthChecker(HealthChecker):
    """ICMP (ping) health checker."""
    
    def __init__(self, count: int = 1, timeout: float = 1.0):
        """
        Initialize ICMP health checker.
        
        Args:
            count: Number of ping packets to send
            timeout: Timeout in seconds
        """
        super().__init__()
        self.count = count
        self.timeout = timeout
    
    def check(self, ip: str) -> Dict:
        """Perform ICMP health check."""
        result = {"ip": ip, "protocol": "icmp", "status": "unknown", "latency": None}
        
        try:
            # Different ping command based on OS
            if sys.platform == "win32":
                ping_cmd = ["ping", "-n", str(self.count), "-w", str(int(self.timeout * 1000)), ip]
            else:
                ping_cmd = ["ping", "-c", str(self.count), "-W", str(int(self.timeout)), ip]
            
            start_time = time.time()
            ping_output = subprocess.run(
                ping_cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                timeout=self.timeout * self.count + 1,
                text=True
            )
            end_time = time.time()
            
            # Check if ping was successful
            if ping_output.returncode == 0:
                result["status"] = "up"
                result["latency"] = round((end_time - start_time) * 1000, 2)  # ms
                
                # Try to extract more precise latency from ping output
                if sys.platform == "win32":
                    match = re.search(r"Average = (\d+)ms", ping_output.stdout)
                else:
                    match = re.search(r"min/avg/max/[^=]+ = [^/]+/([^/]+)/", ping_output.stdout)
                
                if match:
                    result["latency"] = float(match.group(1))
            else:
                result["status"] = "down"
                
        except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
            result["status"] = "down"
            result["error"] = str(e)
        
        return result


class TCPHealthChecker(HealthChecker):
    """TCP port health checker."""
    
    def __init__(self, port: int, timeout: float = 1.0):
        """
        Initialize TCP health checker.
        
        Args:
            port: TCP port to check
            timeout: Connection timeout in seconds
        """
        super().__init__()
        self.port = port
        self.timeout = timeout
    
    def check(self, ip: str) -> Dict:
        """Perform TCP health check."""
        result = {
            "ip": ip, 
            "protocol": "tcp", 
            "port": self.port,
            "status": "unknown", 
            "latency": None
        }
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            start_time = time.time()
            sock.connect((ip, self.port))
            end_time = time.time()
            
            result["status"] = "up"
            result["latency"] = round((end_time - start_time) * 1000, 2)  # ms
            
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            result["status"] = "down"
            result["error"] = str(e)
        
        finally:
            sock.close()
        
        return result


class HTTPHealthChecker(HealthChecker):
    """HTTP/HTTPS health checker."""
    
    def __init__(
        self, 
        port: int = 80, 
        path: str = "/", 
        ssl: bool = False,
        method: str = "GET",
        headers: Dict = None,
        expected_code: int = 200,
        expected_text: str = None,
        timeout: float = 3.0
    ):
        """
        Initialize HTTP health checker.
        
        Args:
            port: HTTP port to check
            path: URL path to request
            ssl: Use HTTPS if True
            method: HTTP method (GET, HEAD, etc.)
            headers: HTTP headers to send
            expected_code: Expected HTTP status code
            expected_text: Text that should be in the response
            timeout: Connection timeout in seconds
        """
        super().__init__()
        self.port = port
        self.path = path
        self.ssl = ssl
        self.method = method
        self.headers = headers or {}
        self.expected_code = expected_code
        self.expected_text = expected_text
        self.timeout = timeout
    
    def check(self, ip: str) -> Dict:
        """Perform HTTP health check."""
        protocol = "https" if self.ssl else "http"
        url = f"{protocol}://{ip}:{self.port}{self.path}"
        
        result = {
            "ip": ip,
            "protocol": protocol,
            "port": self.port,
            "status": "unknown",
            "http_code": None,
            "latency": None,
            "content_match": None
        }
        
        try:
            start_time = time.time()
            response = requests.request(
                method=self.method,
                url=url,
                headers=self.headers,
                timeout=self.timeout,
                verify=False  # Skip SSL verification
            )
            end_time = time.time()
            
            result["http_code"] = response.status_code
            result["latency"] = round((end_time - start_time) * 1000, 2)  # ms
            
            # Check status code
            if response.status_code == self.expected_code:
                result["status"] = "up"
            else:
                result["status"] = "status_mismatch"
            
            # Check for expected text if provided
            if self.expected_text and result["status"] == "up":
                if self.expected_text in response.text:
                    result["content_match"] = True
                else:
                    result["status"] = "content_mismatch"
                    result["content_match"] = False
            
        except requests.exceptions.RequestException as e:
            result["status"] = "down"
            result["error"] = str(e)
        
        return result


class IPScanner:
    """IP scanner with various health check capabilities."""
    
    def __init__(
        self,
        health_checker: HealthChecker,
        max_threads: int = 50,
        progress: bool = True
    ):
        """
        Initialize IP scanner.
        
        Args:
            health_checker: Health checker instance to use
            max_threads: Maximum number of concurrent threads
            progress: Show progress bar if True
        """
        self.health_checker = health_checker
        self.max_threads = max_threads
        self.show_progress = progress
        self.console = Console()
    
    def generate_ips_from_cidr(self, cidr: str) -> List[str]:
        """
        Generate IP addresses from CIDR notation.
        
        Args:
            cidr: CIDR notation (e.g., "192.168.1.0/24")
            
        Returns:
            List of IP addresses
        """
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    
    def generate_ips_from_range(self, start_ip: str, end_ip: str) -> List[str]:
        """
        Generate IP addresses from start and end range.
        
        Args:
            start_ip: Starting IP address
            end_ip: Ending IP address
            
        Returns:
            List of IP addresses
        """
        start = int(ipaddress.IPv4Address(start_ip))
        end = int(ipaddress.IPv4Address(end_ip))
        
        if start > end:
            raise ValueError("Start IP must be less than or equal to end IP")
        
        return [str(ipaddress.IPv4Address(ip)) for ip in range(start, end + 1)]
    
    def scan(self, ips: List[str]) -> List[Dict]:
        """
        Scan a list of IP addresses.
        
        Args:
            ips: List of IP addresses to scan
            
        Returns:
            List of scan results
        """
        results = []
        
        if not ips:
            return results
        
        if self.show_progress:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TextColumn("({task.completed} of {task.total})"),
                console=self.console
            ) as progress:
                task = progress.add_task("Scanning IPs...", total=len(ips))
                
                with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                    for result in executor.map(self.health_checker.check, ips):
                        results.append(result)
                        progress.update(task, advance=1)
        else:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                results = list(executor.map(self.health_checker.check, ips))
        
        return results


class ResultManager:
    """Manages scan results, displays and saves them."""
    
    def __init__(self, console: Console = None):
        """
        Initialize result manager.
        
        Args:
            console: Rich console instance
        """
        self.console = console or Console()
    
    def display_results(self, results: List[Dict]):
        """
        Display scan results on the console.
        
        Args:
            results: List of scan results
        """
        # Count statistics
        total = len(results)
        up_count = sum(1 for r in results if r["status"] == "up")
        down_count = sum(1 for r in results if r["status"] == "down")
        other_count = total - up_count - down_count
        
        # Display summary
        self.console.print(f"\n[bold]Scan Summary[/bold]")
        self.console.print(f"Total IPs scanned: {total}")
        self.console.print(f"UP: [green]{up_count}[/green] | DOWN: [red]{down_count}[/red] | Other: [yellow]{other_count}[/yellow]\n")
        
        # Display results table
        self.console.print("[bold]Detailed Results:[/bold]")
        for result in results:
            ip = result["ip"]
            status = result["status"]
            protocol = result["protocol"]
            
            if status == "up":
                status_color = "green"
            elif status == "down":
                status_color = "red"
            else:
                status_color = "yellow"
            
            # Format specific protocol details
            if protocol == "icmp":
                latency = result.get("latency", "N/A")
                details = f"latency: {latency}ms"
            elif protocol == "tcp":
                port = result.get("port", "N/A")
                latency = result.get("latency", "N/A")
                details = f"port: {port}, latency: {latency}ms"
            elif protocol in ("http", "https"):
                port = result.get("port", "N/A")
                code = result.get("http_code", "N/A")
                latency = result.get("latency", "N/A")
                details = f"port: {port}, code: {code}, latency: {latency}ms"
            else:
                details = ""
            
            self.console.print(
                f"IP: [bold]{ip}[/bold] | Status: [{status_color}]{status}[/{status_color}] | "
                f"Protocol: {protocol} | {details}"
            )
    
    def save_as_json(self, results: List[Dict], filename: str):
        """
        Save results as JSON.
        
        Args:
            results: List of scan results
            filename: Output filename
        """
        with open(filename, 'w') as f:
            # Add metadata
            output = {
                "metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "total_hosts": len(results),
                    "up_hosts": sum(1 for r in results if r["status"] == "up"),
                    "down_hosts": sum(1 for r in results if r["status"] == "down")
                },
                "results": results
            }
            json.dump(output, f, indent=2)
        
        self.console.print(f"Results saved to [bold]{filename}[/bold]")
    
    def save_as_csv(self, results: List[Dict], filename: str):
        """
        Save results as CSV.
        
        Args:
            results: List of scan results
            filename: Output filename
        """
        # Get all possible fields from all results
        fieldnames = set()
        for result in results:
            fieldnames.update(result.keys())
        
        fieldnames = sorted(list(fieldnames))
        
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)
        
        self.console.print(f"Results saved to [bold]{filename}[/bold]")


def parse_headers(headers_str: str) -> Dict:
    """
    Parse headers string into dictionary.
    
    Args:
        headers_str: Headers string in format "Key1:Value1,Key2:Value2"
        
    Returns:
        Dictionary of headers
    """
    if not headers_str:
        return {}
    
    headers = {}
    for header in headers_str.split(','):
        if ':' in header:
            key, value = header.split(':', 1)
            headers[key.strip()] = value.strip()
    
    return headers


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="dishost - IP Range Scanner with Health Checks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a CIDR range with ICMP (ping)
  dishost.py --cidr 192.168.1.0/24 --check icmp
  
  # Scan an IP range with TCP port check
  dishost.py --start 10.0.0.1 --end 10.0.0.10 --check tcp --port 22
  
  # Scan with HTTP check
  dishost.py --cidr 192.168.1.0/24 --check http --port 80 --path /health --expect-code 200
  
  # Save results to files
  dishost.py --cidr 192.168.1.0/24 --check icmp --json results.json --csv results.csv
"""
    )
    
    # IP range arguments
    ip_group = parser.add_argument_group('IP Range (required, use either CIDR or start-end)')
    ip_ex_group = ip_group.add_mutually_exclusive_group(required=True)
    ip_ex_group.add_argument('--cidr', help='CIDR notation (e.g., 192.168.1.0/24)')
    ip_ex_group.add_argument('--start', help='Start IP address')
    
    # Require end IP if start is provided
    parser.add_argument('--end', help='End IP address (required if --start is used)')
    
    # Health check arguments
    check_group = parser.add_argument_group('Health Check Options')
    check_group.add_argument(
        '--check', 
        choices=['icmp', 'tcp', 'http', 'https'], 
        default='icmp',
        help='Health check type (default: icmp)'
    )
    check_group.add_argument('--port', type=int, help='Port for TCP/HTTP check')
    check_group.add_argument('--timeout', type=float, default=1.0, help='Timeout in seconds (default: 1.0)')
    check_group.add_argument('--count', type=int, default=1, help='Ping count for ICMP (default: 1)')
    
    # HTTP specific arguments
    http_group = parser.add_argument_group('HTTP Check Options')
    http_group.add_argument('--path', default='/', help='URL path for HTTP check (default: /)')
    http_group.add_argument('--method', default='GET', help='HTTP method (default: GET)')
    http_group.add_argument('--headers', help='HTTP headers as "Key1:Value1,Key2:Value2"')
    http_group.add_argument('--expect-code', type=int, default=200, help='Expected HTTP status code (default: 200)')
    http_group.add_argument('--expect-text', help='Text that should be in the HTTP response')
    
    # Output arguments
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('--json', help='Save results to JSON file')
    output_group.add_argument('--csv', help='Save results to CSV file')
    output_group.add_argument('--no-progress', action='store_true', help='Hide progress bar')
    output_group.add_argument('--threads', type=int, default=50, help='Maximum number of threads (default: 50)')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.start and not args.end:
        parser.error("--end is required when --start is used")
    
    if args.check in ('tcp', 'http', 'https') and not args.port:
        parser.error(f"--port is required for {args.check} check")
    
    # Generate list of IPs to scan
    try:
        scanner = None
        ip_list = []
        
        if args.cidr:
            ip_list = IPScanner(None).generate_ips_from_cidr(args.cidr)
        else:
            ip_list = IPScanner(None).generate_ips_from_range(args.start, args.end)
        
        # Create appropriate health checker
        if args.check == 'icmp':
            health_checker = ICMPHealthChecker(
                count=args.count,
                timeout=args.timeout
            )
        elif args.check == 'tcp':
            health_checker = TCPHealthChecker(
                port=args.port,
                timeout=args.timeout
            )
        elif args.check in ('http', 'https'):
            headers = parse_headers(args.headers)
            health_checker = HTTPHealthChecker(
                port=args.port,
                path=args.path,
                ssl=args.check == 'https',
                method=args.method,
                headers=headers,
                expected_code=args.expect_code,
                expected_text=args.expect_text,
                timeout=args.timeout
            )
        
        # Create scanner and result manager
        scanner = IPScanner(
            health_checker=health_checker,
            max_threads=args.threads,
            progress=not args.no_progress
        )
        result_manager = ResultManager()
        
        # Perform the scan
        print(f"Scanning {len(ip_list)} IP addresses with {args.check} check...")
        results = scanner.scan(ip_list)
        
        # Display and save results
        result_manager.display_results(results)
        
        if args.json:
            result_manager.save_as_json(results, args.json)
        
        if args.csv:
            result_manager.save_as_csv(results, args.csv)
        
    except (ValueError, ipaddress.AddressValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    
    return 0


if __name__ == "__main__":
    # Disable insecure HTTPS warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    sys.exit(main())