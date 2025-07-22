#  824. komutda hedefi değiştirin ve başlatın

import requests
import datetime
import time
import socket
import ssl
import urllib.parse
import concurrent.futures
from requests.exceptions import RequestException, Timeout, ConnectionError
from typing import Dict, Any, Set, List
from bs4 import BeautifulSoup
from colorama import Fore, Style
import whois
from dataclasses import dataclass, field
from enum import Enum

# --- Vulnerability Definitions ---
class VulnerabilityLevel(Enum):
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

@dataclass
class Vulnerability:
    name: str
    description: str
    url: str
    level: VulnerabilityLevel = VulnerabilityLevel.INFO
    details: Dict[str, Any] = field(default_factory=dict)

    def __str__(self):
        color = {
            VulnerabilityLevel.INFO: Fore.BLUE,
            VulnerabilityLevel.LOW: Fore.CYAN,
            VulnerabilityLevel.MEDIUM: Fore.YELLOW,
            VulnerabilityLevel.HIGH: Fore.MAGENTA,
            VulnerabilityLevel.CRITICAL: Fore.RED,
        }.get(self.level, Fore.WHITE)
        
        return (
            f"{color}--- Vulnerability Found ---{Style.RESET_ALL}\n"
            f"{color}Name:{Style.RESET_ALL} {self.name}\n"
            f"{color}URL:{Style.RESET_ALL} {self.url}\n"
            f"{color}Level:{Style.RESET_ALL} {self.level.value}\n"
            f"{color}Description:{Style.RESET_ALL} {self.description}\n"
            f"{color}Details:{Style.RESET_ALL} {self.details}\n"
            f"{color}---------------------------{Style.RESET_ALL}"
        )

# --- WebScanner Class ---
class WebScanner:
    def __init__(self, target: str, verify_ssl: bool = True, verbose: bool = False, crawl: bool = False, max_urls: int = 100, threads: int = 10, output_file: str = None):
        if not target.startswith(('http://', 'https://')):
            self.target = 'http://' + target # Default to http if no scheme
        else:
            self.target = target
            
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        self.crawl = crawl
        self.max_urls = max_urls
        self.threads = threads
        self.output_file = output_file
        
        self.start_time = time.time()
        self.scanned_urls: Set[str] = set()
        self.queued_urls: Set[str] = {self.target}
        self.found_vulnerabilities: List[Vulnerability] = []
        self.scan_stats = {
            'scan_duration': 0,
            'total_urls_queued': 0,
            'scanned_urls': 0,
            'found_vulnerabilities': 0
        }

        # Hassas dosyalar (Sensitive files)
        self.sensitive_files = [
            '.env', '.git/config', '.git/HEAD', 'wp-config.php', 'config.php', 'configuration.php', 
            'config.yml', 'config.xml', 'settings.php', 'database.php', 'db.php', 'connection.php',
            'credentials.json', 'backup.sql', 'backup.zip', 'backup.tar.gz', 'phpinfo.php', 'info.php', 
            'test.php', 'dump.sql', 'robots.txt', 'sitemap.xml', '.htaccess', 'web.config', 'error_log', 
            'server-status', 'id_rsa', 'id_dsa', '.bash_history', '.DS_Store', 'admin/', 'manager/', 'upload/'
        ]
        
        # CMS tespit kalıpları (CMS detection patterns)
        self.cms_patterns = {
            'WordPress': ['<meta name="generator" content="WordPress', 'wp-content', 'wp-includes', '/wp-login.php'],
            'Joomla': ['<meta name="generator" content="Joomla', '/administrator/', 'com_content', '/templates/'],
            'Drupal': ['<meta name="Generator" content="Drupal', 'Drupal.settings', '/sites/default/'],
            'Magento': ['Mage.Cookies', '/skin/frontend/', '/index.php/admin/'],
            'Shopify': ['cdn.shopify.com', 'Shopify.theme'],
            'Wix': ['X-Wix-Request-Id', 'wix-dropdown', 'wix-image'],
            'Squarespace': ['static1.squarespace.com', 'Y.Squarespace']
        }
        
        # Riskli HTTP Yöntemleri (Risky HTTP Methods)
        self.risky_http_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']

        # XSS Payload
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "\"%3E%3Cscript%3Ealert('XSS')%3C/script%3E" # URL encoded
        ]

        # SQL Injection Payload and error patterns (simplified)
        self.sql_injection_payloads = [
            "' OR 1=1--",
            "\" OR 1=1--",
            "1 UNION SELECT NULL,NULL,NULL--", # Basic union-based
        ]
        self.sql_error_patterns = [
            "You have an error in your SQL syntax",
            "Warning: mysql_fetch_array()",
            "SQLSTATE",
            "ORA-", # Oracle
            "SQL command not properly ended", # Oracle
            "Unclosed quotation mark after the character string", # MSSQL
            "supplied argument is not a valid MySQL",
            "Microsoft OLE DB Provider for ODBC Drivers error",
            "Query failed"
        ]

        # Common subdomain wordlist (for basic enumeration)
        self.subdomain_wordlist = ['www', 'admin', 'dev', 'test', 'api', 'blog', 'mail', 'ftp', 'shop']
    
    def log(self, message: str, level: str = "info") -> None:
        """Verbose mod açıksa mesajları gösterir, farklı seviyelerde renklendirme yapar."""
        if self.verbose:
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            if level == "info":
                print(f"{Fore.CYAN}[{timestamp}]{Style.RESET_ALL} {message}")
            elif level == "warning":
                print(f"{Fore.YELLOW}[{timestamp}]{Style.RESET_ALL} {message}")
            elif level == "error":
                print(f"{Fore.RED}[{timestamp}]{Style.RESET_ALL} {message}")
            elif level == "success":
                print(f"{Fore.GREEN}[{timestamp}]{Style.RESET_ALL} {message}")
            else:
                print(f"[{timestamp}] {message}") # Default color
            
    def run_scan(self) -> Dict[str, Any]:
        """Tarama işlemini başlatır."""
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} '{self.target}' taranıyor...")
        print(f"{Fore.BLUE}[*]{Style.RESET_ALL} Tarama başlatıldı: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        try:
            # İlk olarak hedef siteye erişim kontrolü
            self.log("Hedef siteye erişim kontrolü yapılıyor...", "info")
            try:
                resp = requests.get(self.target, verify=self.verify_ssl, timeout=10)
                resp.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            except (RequestException, Timeout, ConnectionError) as e:
                print(f"{Fore.RED}[!]{Style.RESET_ALL} Hedef siteye erişilemiyor veya hata oluştu: {str(e)}")
                return {'success': False, 'error': f"Hedef siteye erişilemiyor veya hata oluştu: {str(e)}"}
            
            # Temel bilgileri edinme
            self.log("Temel bilgiler toplanıyor...", "info")
            self._gather_basic_info(resp)
            
            # Tarama işlemlerini başlat
            if self.crawl:
                self.log("Site derinlemesine taranıyor (crawl mode)...", "info")
                self._crawl_site()
            else:
                self.log("Tek URL taranıyor...", "info")
                self._scan_url(self.target) # Perform all checks on the initial target
            
            # Tarama istatistiklerini güncelle
            self.scan_stats['scan_duration'] = round(time.time() - self.start_time, 2)
            self.scan_stats['total_urls_queued'] = len(self.queued_urls) + len(self.scanned_urls)
            self.scan_stats['scanned_urls'] = len(self.scanned_urls)
            self.scan_stats['found_vulnerabilities'] = len(self.found_vulnerabilities)
            
            # Sonuçları göster
            self._display_results()
            
            # Sonuçları dosyaya yaz (belirtildiyse)
            if self.output_file:
                self._save_results()
            
        except Exception as e:
            print(f"{Fore.RED}[!]{Style.RESET_ALL} Tarama sırasında beklenmeyen bir hata oluştu: {str(e)}")
            return {'success': False, 'error': str(e)}
            
        return {
            'success': True, 
            'stats': self.scan_stats,
            'vulnerabilities': [
                {
                    'name': v.name,
                    'description': v.description,
                    'url': v.url,
                    'level': v.level.value,
                    'details': v.details
                } for v in self.found_vulnerabilities
            ]
        }

    def _gather_basic_info(self, response: requests.Response) -> None:
        """Hedef site hakkında temel bilgiler topla"""
        self.log(f"{Fore.LIGHTGREEN_EX}--- Temel Bilgiler ---{Style.RESET_ALL}", "info")
        try:
            # Sunucu bilgisi
            server_info = response.headers.get('Server', 'Bilinmiyor')
            self.log(f"  Sunucu: {server_info}")
            if server_info == 'Bilinmiyor':
                self.found_vulnerabilities.append(Vulnerability(
                    name="Missing Server Header",
                    description="The 'Server' header is not present. While sometimes a security measure, it can also indicate misconfiguration.",
                    url=response.url,
                    level=VulnerabilityLevel.INFO,
                    details={"header": "Server", "value": "Not found"}
                ))
            
            # Powered-By bilgisi
            powered_by = response.headers.get('X-Powered-By', 'Bilinmiyor')
            if powered_by != 'Bilinmiyor':
                self.log(f"  X-Powered-By: {powered_by}")
                self.found_vulnerabilities.append(Vulnerability(
                    name="X-Powered-By Header Disclosure",
                    description="The 'X-Powered-By' header reveals technologies used by the server, potentially aiding attackers.",
                    url=response.url,
                    level=VulnerabilityLevel.INFO,
                    details={"header": "X-Powered-By", "value": powered_by}
                ))
            
            # SSL/TLS Bilgisi
            if self.target.startswith('https://'):
                self._check_ssl_certificate(response)
            else:
                self.found_vulnerabilities.append(Vulnerability(
                    name="No HTTPS Used",
                    description="The target site is not using HTTPS, which means communication is unencrypted and vulnerable to eavesdropping.",
                    url=self.target,
                    level=VulnerabilityLevel.HIGH,
                    details={"recommendation": "Implement HTTPS to encrypt data in transit."}
                ))
            
            # IP Adresi ve WHOIS bilgisi
            hostname = urllib.parse.urlparse(self.target).netloc.split(':')[0]
            try:
                ip = socket.gethostbyname(hostname)
                self.log(f"  IP Adresi: {ip}")
                self._gather_whois_info(hostname)
            except socket.gaierror:
                self.log(f"  IP adresi çözümlenemedi: {hostname}", "warning")
            
            # İçerik Tipi
            content_type = response.headers.get('Content-Type', 'Bilinmiyor')
            self.log(f"  İçerik Tipi: {content_type}")
            
            # CMS tespiti
            self._detect_cms(response)

            # Security Headers Check
            self._check_security_headers(response)

        except Exception as e:
            self.log(f"Temel bilgiler toplanamadı: {str(e)}", "error")
        self.log(f"{Fore.LIGHTGREEN_EX}-------------------{Style.RESET_ALL}", "info")

    def _check_ssl_certificate(self, response: requests.Response) -> None:
        """SSL/TLS sertifikası bilgisini kontrol et"""
        try:
            hostname = urllib.parse.urlparse(self.target).netloc
            # Remove port if present
            if ':' in hostname:
                hostname = hostname.split(':')[0]

            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    valid_from = datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y GMT')
                    valid_until = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y GMT')
                    
                    self.log(f"  SSL/TLS Sertifikası:", "info")
                    self.log(f"    Veren Kuruluş: {cert.get('issuer', ((('', ''),),))[0][0][1]}", "info")
                    self.log(f"    Geçerlilik: {valid_from.strftime('%Y-%m-%d')} - {valid_until.strftime('%Y-%m-%d')}", "info")

                    if datetime.datetime.now() > valid_until:
                        self.found_vulnerabilities.append(Vulnerability(
                            name="Expired SSL/TLS Certificate",
                            description=f"The SSL/TLS certificate for {self.target} has expired.",
                            url=self.target,
                            level=VulnerabilityLevel.HIGH,
                            details={"expiration_date": valid_until.strftime('%Y-%m-%d')}
                        ))
                    elif (valid_until - datetime.datetime.now()).days < 30:
                        self.found_vulnerabilities.append(Vulnerability(
                            name="Soon-to-Expire SSL/TLS Certificate",
                            description=f"The SSL/TLS certificate for {self.target} will expire soon (within 30 days).",
                            url=self.target,
                            level=VulnerabilityLevel.MEDIUM,
                            details={"expiration_date": valid_until.strftime('%Y-%m-%d')}
                        ))
        except ssl.SSLError as e:
            self.log(f"SSL/TLS sertifika hatası: {str(e)}", "warning")
            self.found_vulnerabilities.append(Vulnerability(
                name="SSL/TLS Handshake Error",
                description=f"Could not establish a secure connection or verify the SSL certificate for {self.target}.",
                url=self.target,
                level=VulnerabilityLevel.HIGH,
                details={"error": str(e), "recommendation": "Check certificate validity, chain, and server configuration."}
            ))
        except socket.timeout:
            self.log("SSL/TLS sertifika kontrolü zaman aşımına uğradı.", "warning")
        except Exception as e:
            self.log(f"SSL/TLS bilgisi alınamadı: {str(e)}", "error")
        
    def _gather_whois_info(self, hostname: str) -> None:
        """WHOIS bilgilerini al"""
        try:
            # whois kütüphanesi tam alan adını bekler, bazen sadece ana domain'i
            # Hedef URL'den ana domain'i çıkarmaya çalışın
            parsed_url = urllib.parse.urlparse(self.target)
            domain = parsed_url.netloc
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # Try to get the root domain for whois
            parts = domain.split('.')
            if len(parts) > 2:
                # Handle cases like example.co.uk or sub.example.com
                if parts[-2] in ['co', 'com', 'net', 'org', 'gov', 'edu'] and len(parts[-1]) <= 3:
                    domain = ".".join(parts[-3:])
                else:
                    domain = ".".join(parts[-2:])

            w = whois.whois(domain)
            
            if w.creation_date:
                creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                self.log(f"  WHOIS Oluşturma Tarihi: {creation_date.strftime('%Y-%m-%d') if isinstance(creation_date, datetime.datetime) else creation_date}")
            if w.expiration_date:
                expiration_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
                self.log(f"  WHOIS Bitiş Tarihi: {expiration_date.strftime('%Y-%m-%d') if isinstance(expiration_date, datetime.datetime) else expiration_date}")
            if w.registrant_name:
                self.log(f"  WHOIS Kayıt Sahibi: {w.registrant_name}")
            if w.emails:
                self.log(f"  WHOIS E-postalar: {', '.join(w.emails)}")

        except whois.parser.PywhoisError as e:
            self.log(f"WHOIS bilgisi bulunamadı veya hata oluştu: {str(e)}", "warning")
        except Exception as e:
            self.log(f"WHOIS bilgisi alınamadı: {str(e)}", "error")
        
    def _detect_cms(self, response: requests.Response) -> None:
        """CMS platformlarını tespit et"""
        detected_cms = "Bilinmiyor"
        for cms_name, patterns in self.cms_patterns.items():
            for pattern in patterns:
                if pattern in response.text or (response.headers.get('X-Powered-By') and pattern in response.headers.get('X-Powered-By')):
                    detected_cms = cms_name
                    break
            if detected_cms != "Bilinmiyor":
                break
        
        self.log(f"  CMS: {detected_cms}")
        if detected_cms != "Bilinmiyor":
            self.found_vulnerabilities.append(Vulnerability(
                name="CMS Detected",
                description=f"The Content Management System (CMS) '{detected_cms}' was detected. This information can be used by attackers to find known vulnerabilities.",
                url=response.url,
                level=VulnerabilityLevel.INFO,
                details={"cms_name": detected_cms}
            ))

    def _check_security_headers(self, response: requests.Response) -> None:
        """Güvenlik başlıklarını kontrol et"""
        self.log(f"{Fore.LIGHTGREEN_EX}--- Güvenlik Başlıkları Kontrolü ---{Style.RESET_ALL}", "info")
        headers = response.headers
        
        # Strict-Transport-Security (HSTS)
        hsts = headers.get('Strict-Transport-Security')
        if not hsts:
            self.found_vulnerabilities.append(Vulnerability(
                name="Missing HSTS Header",
                description="The Strict-Transport-Security (HSTS) header is missing. This can allow downgrade attacks and cookie hijacking.",
                url=response.url,
                level=VulnerabilityLevel.MEDIUM,
                details={"recommendation": "Implement HSTS to enforce HTTPS. Example: Strict-Transport-Security: max-age=31536000; includeSubDomains"}
            ))
        else:
            self.log(f"  HSTS Başlığı Mevcut: {hsts}")

        # X-Content-Type-Options
        x_content_type_options = headers.get('X-Content-Type-Options')
        if not x_content_type_options or 'nosniff' not in x_content_type_options.lower():
            self.found_vulnerabilities.append(Vulnerability(
                name="Missing or Incomplete X-Content-Type-Options Header",
                description="The X-Content-Type-Options header is missing or does not include 'nosniff'. This can lead to MIME-sniffing attacks.",
                url=response.url,
                level=VulnerabilityLevel.LOW,
                details={"recommendation": "Set X-Content-Type-Options: nosniff"}
            ))
        else:
            self.log(f"  X-Content-Type-Options Başlığı Mevcut: {x_content_type_options}")

        # X-Frame-Options
        x_frame_options = headers.get('X-Frame-Options')
        if not x_frame_options or (('deny' not in x_frame_options.lower()) and ('sameorigin' not in x_frame_options.lower())):
            self.found_vulnerabilities.append(Vulnerability(
                name="Missing or Insecure X-Frame-Options Header",
                description="The X-Frame-Options header is missing or insecurely configured. This can make the site vulnerable to clickjacking attacks.",
                url=response.url,
                level=VulnerabilityLevel.MEDIUM,
                details={"recommendation": "Set X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN"}
            ))
        else:
            self.log(f"  X-Frame-Options Başlığı Mevcut: {x_frame_options}")

        # Content-Security-Policy (CSP)
        csp = headers.get('Content-Security-Policy')
        if not csp:
            self.found_vulnerabilities.append(Vulnerability(
                name="Missing Content-Security-Policy Header",
                description="The Content-Security-Policy (CSP) header is missing. CSP helps prevent various attacks including XSS and data injection.",
                url=response.url,
                level=VulnerabilityLevel.MEDIUM,
                details={"recommendation": "Implement a strong Content-Security-Policy."}
            ))
        else:
            self.log(f"  Content-Security-Policy Başlığı Mevcut: {csp}")

        # Referrer-Policy
        referrer_policy = headers.get('Referrer-Policy')
        if not referrer_policy:
            self.found_vulnerabilities.append(Vulnerability(
                name="Missing Referrer-Policy Header",
                description="The Referrer-Policy header is missing. This can lead to sensitive information leakage through the Referer header.",
                url=response.url,
                level=VulnerabilityLevel.LOW,
                details={"recommendation": "Implement a secure Referrer-Policy (e.g., no-referrer, same-origin, strict-origin-when-cross-origin)."}
            ))
        else:
            self.log(f"  Referrer-Policy Başlığı Mevcut: {referrer_policy}")
        
        # Permissions-Policy (formerly Feature-Policy)
        permissions_policy = headers.get('Permissions-Policy')
        if not permissions_policy:
            self.found_vulnerabilities.append(Vulnerability(
                name="Missing Permissions-Policy Header",
                description="The Permissions-Policy header is missing. This header allows control over browser features and APIs available to the page.",
                url=response.url,
                level=VulnerabilityLevel.LOW,
                details={"recommendation": "Implement a Permissions-Policy to restrict browser features."}
            ))
        else:
            self.log(f"  Permissions-Policy Başlığı Mevcut: {permissions_policy}")

        self.log(f"{Fore.LIGHTGREEN_EX}-----------------------------{Style.RESET_ALL}", "info")

    def _crawl_site(self) -> None:
        """Siteyi crawl yaparak URL'leri tarar"""
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            while self.queued_urls and len(self.scanned_urls) < self.max_urls:
                # Take a batch of URLs to process
                current_batch = list(self.queued_urls)[:min(len(self.queued_urls), self.threads * 2)] # Take more than threads to keep executor busy
                self.queued_urls -= set(current_batch)

                for url in current_batch:
                    if url not in self.scanned_urls:
                        futures[executor.submit(self._scan_url, url)] = url
                
                # Process results from completed futures
                done, _ = concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_COMPLETED)
                for future in done:
                    url = futures.pop(future)
                    try:
                        new_urls = future.result()
                        if new_urls:
                            for new_url in new_urls:
                                # Ensure new_url is absolute and within the target domain
                                absolute_new_url = urllib.parse.urljoin(self.target, new_url)
                                parsed_new = urllib.parse.urlparse(absolute_new_url)
                                parsed_target = urllib.parse.urlparse(self.target)

                                if parsed_new.netloc == parsed_target.netloc:
                                    if absolute_new_url not in self.scanned_urls and absolute_new_url not in self.queued_urls:
                                        if len(self.scanned_urls) + len(self.queued_urls) < self.max_urls:
                                            self.queued_urls.add(absolute_new_url)
                                        else:
                                            self.log(f"Maksimum URL sayısına ulaşıldı ({self.max_urls}). Tarama durduruldu.", "warning")
                                            return
                    except Exception as e:
                        self.log(f"URL tarama hatası {url}: {str(e)}", "error")
            
            # Wait for any remaining futures to complete after the loop condition is met
            concurrent.futures.wait(futures.keys())


    def _scan_url(self, url: str) -> Set[str]:
        """Belirli bir URL'yi tara ve linkleri çıkar"""
        if url in self.scanned_urls:
            return set()
        
        self.log(f"Taranıyor: {url}", "info")
        self.scanned_urls.add(url)
        new_urls = set()

        try:
            resp = requests.get(url, verify=self.verify_ssl, timeout=10)
            resp.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

            # Perform various checks
            self._check_xss_vulnerability(url, resp)
            self._check_sql_injection(url, resp)
            self._check_sensitive_files(url)
            self._check_risky_http_methods(url)
            self._check_directory_listing(url, resp)
            # self._enumerate_subdomains() # This should probably run once per target, not per URL

            if self.crawl:
                new_urls = self._extract_links_from_response(resp, url)

        except (RequestException, Timeout, ConnectionError) as e:
            self.log(f"İstek hatası ({url}): {str(e)}", "error")
            return set()
        except Exception as e:
            self.log(f"URL işleme hatası ({url}): {str(e)}", "error")
            return set()

        return new_urls

    def _extract_links_from_response(self, response: requests.Response, base_url: str) -> Set[str]:
        """Sayfadan linkleri çıkartır"""
        soup = BeautifulSoup(response.text, 'html.parser')
        links = set()
        for link_tag in soup.find_all('a', href=True):
            href = link_tag['href']
            # Convert relative URLs to absolute URLs
            absolute_url = urllib.parse.urljoin(base_url, href)
            
            # Only add links within the same domain as the target
            parsed_absolute = urllib.parse.urlparse(absolute_url)
            parsed_target = urllib.parse.urlparse(self.target)

            if parsed_absolute.netloc == parsed_target.netloc:
                links.add(absolute_url)
        return links
    
    def _check_xss_vulnerability(self, url: str, response: requests.Response) -> None:
        """Reflected XSS açığını kontrol et (basit)"""
        # Sadece URL query parametreleri olan sayfaları kontrol et
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)

        if not query_params:
            return # No query parameters to test

        for param, values in query_params.items():
            for original_value in values:
                for payload in self.xss_payloads:
                    # Construct new URL with payload
                    test_params = query_params.copy()
                    test_params[param] = payload
                    encoded_query = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = parsed_url._replace(query=encoded_query).geturl()

                    try:
                        test_resp = requests.get(test_url, verify=self.verify_ssl, timeout=5)
                        if payload in test_resp.text:
                            self.found_vulnerabilities.append(Vulnerability(
                                name="Reflected XSS Vulnerability",
                                description=f"Possible Reflected Cross-Site Scripting (XSS) vulnerability detected. The payload '{payload}' was reflected in the response.",
                                url=test_url,
                                level=VulnerabilityLevel.HIGH,
                                details={"parameter": param, "payload": payload, "response_status": test_resp.status_code}
                            ))
                            return # Only report once per URL for this basic check
                    except RequestException:
                        continue # Ignore errors for payload requests

    def _check_sql_injection(self, url: str, response: requests.Response) -> None:
        """Basit SQL Enjeksiyonu açığını kontrol et"""
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)

        if not query_params:
            return

        for param, values in query_params.items():
            for original_value in values:
                for payload in self.sql_injection_payloads:
                    test_params = query_params.copy()
                    test_params[param] = original_value + payload # Append payload
                    encoded_query = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = parsed_url._replace(query=encoded_query).geturl()

                    try:
                        test_resp = requests.get(test_url, verify=self.verify_ssl, timeout=5)
                        for error_pattern in self.sql_error_patterns:
                            if error_pattern.lower() in test_resp.text.lower():
                                self.found_vulnerabilities.append(Vulnerability(
                                    name="Possible SQL Injection",
                                    description=f"Potential SQL Injection vulnerability detected. SQL error pattern '{error_pattern}' found in response after injecting payload.",
                                    url=test_url,
                                    level=VulnerabilityLevel.HIGH,
                                    details={"parameter": param, "payload_suffix": payload, "error_pattern": error_pattern, "response_status": test_resp.status_code}
                                ))
                                return # Report once per URL if an error is found
                    except RequestException:
                        continue
    
    def _check_sensitive_files(self, base_url: str) -> None:
        """Hassas dosyaların varlığını kontrol et"""
        parsed_base_url = urllib.parse.urlparse(base_url)
        # Construct URL for common paths (e.g., base_url/path/to/file or base_url/file)
        
        # Determine the "root" for sensitive files check based on the target URL
        # If the target is a directory, append directly. If it's a file, go up one level.
        path_segments = parsed_base_url.path.split('/')
        if '.' in path_segments[-1]: # Appears to be a file
            base_for_sensitive = parsed_base_url._replace(path='/'.join(path_segments[:-1]) + '/').geturl()
        else: # Appears to be a directory or root
            base_for_sensitive = urllib.parse.urljoin(parsed_base_url.scheme + "://" + parsed_base_url.netloc, parsed_base_url.path)
            if not base_for_sensitive.endswith('/'):
                base_for_sensitive += '/'

        for sf in self.sensitive_files:
            test_url = urllib.parse.urljoin(base_for_sensitive, sf)
            # Avoid redundant checks if the sensitive file path is already the current URL
            if test_url == base_url and not sf.startswith('.'): # Allow checking for .env etc. on the root itself
                continue

            try:
                resp = requests.get(test_url, verify=self.verify_ssl, timeout=5)
                # Check for 200 OK and common "not found" indicators in content
                # This is a heuristic, a 404 is definitive, but a 200 with generic "not found" page is trickier.
                if resp.status_code == 200 and ("not found" not in resp.text.lower() and "sayfa bulunamadı" not in resp.text.lower()):
                    self.found_vulnerabilities.append(Vulnerability(
                        name="Sensitive File Disclosure",
                        description=f"Potentially sensitive file or directory '{sf}' found and accessible.",
                        url=test_url,
                        level=VulnerabilityLevel.HIGH,
                        details={"status_code": resp.status_code, "file_path": sf}
                    ))
            except RequestException:
                continue

    def _check_risky_http_methods(self, url: str) -> None:
        """Riskli HTTP yöntemlerinin etkin olup olmadığını kontrol et"""
        for method in self.risky_http_methods:
            try:
                resp = requests.request(method, url, verify=self.verify_ssl, timeout=5)
                # Success for PUT usually means 200/201/204
                # Success for DELETE usually means 200/202/204
                # Success for TRACE is 200 (echoes request)
                if 200 <= resp.status_code < 300: # Check for success codes
                    if method == 'TRACE' and '<!DOCTYPE html>' not in resp.text.lower() and 'trace / ' in resp.text.lower():
                        # TRACE method might reflect headers, look for specific trace output
                        self.found_vulnerabilities.append(Vulnerability(
                            name=f"Enabled Risky HTTP Method: {method}",
                            description=f"The HTTP TRACE method is enabled on {url}. This could potentially be used for Cross-Site Tracing (XST) attacks.",
                            url=url,
                            level=VulnerabilityLevel.MEDIUM,
                            details={"method": method, "status_code": resp.status_code, "response_body_snippet": resp.text[:100]}
                        ))
                    elif method != 'TRACE': # For PUT/DELETE/CONNECT, any 2xx success is risky
                         self.found_vulnerabilities.append(Vulnerability(
                            name=f"Enabled Risky HTTP Method: {method}",
                            description=f"The HTTP {method} method is enabled on {url}. This could allow unauthorized modification or deletion of resources.",
                            url=url,
                            level=VulnerabilityLevel.HIGH,
                            details={"method": method, "status_code": resp.status_code}
                        ))
            except RequestException:
                continue

    def _check_directory_listing(self, url: str, response: requests.Response) -> None:
        """Dizin listeleme açığını kontrol et"""
        # Check if the URL is likely a directory (ends with / or no file extension)
        parsed_url = urllib.parse.urlparse(url)
        path = parsed_url.path
        if not path.endswith('/') and '.' in path.split('/')[-1]: # If it's a file, skip
            return

        # Attempt to access with a trailing slash if not already present
        test_url = url
        if not test_url.endswith('/'):
            test_url += '/'

        try:
            resp = requests.get(test_url, verify=self.verify_ssl, timeout=5)
            # Look for common directory listing patterns in the HTML
            if resp.status_code == 200:
                if any(pattern in resp.text for pattern in ['Index of /', '<title>Directory listing for', 'Parent Directory', '<pre>']):
                    self.found_vulnerabilities.append(Vulnerability(
                        name="Directory Listing Enabled",
                        description=f"Directory listing is enabled on {test_url}. This can expose sensitive files and directory structures.",
                        url=test_url,
                        level=VulnerabilityLevel.MEDIUM,
                        details={"status_code": resp.status_code, "detected_patterns": ["Index of /", "Parent Directory"]}
                    ))
        except RequestException:
            pass

    def _enumerate_subdomains(self) -> None:
        """Basit alt alan adı numaralandırması yap"""
        self.log(f"{Fore.LIGHTGREEN_EX}--- Alt Alan Adı Numaralandırması ---{Style.RESET_ALL}", "info")
        parsed_target = urllib.parse.urlparse(self.target)
        base_domain = parsed_target.netloc
        if ':' in base_domain: # remove port if present
            base_domain = base_domain.split(':')[0]
        
        # Get root domain for subdomain enumeration (e.g., example.com from www.example.com)
        domain_parts = base_domain.split('.')
        if len(domain_parts) > 2:
            if domain_parts[-2] in ['co', 'com', 'net', 'org', 'gov', 'edu'] and len(domain_parts[-1]) <= 3:
                root_domain = ".".join(domain_parts[-3:])
            else:
                root_domain = ".".join(domain_parts[-2:])
        else:
            root_domain = base_domain


        found_subdomains = set()
        for sub in self.subdomain_wordlist:
            subdomain_full = f"{sub}.{root_domain}"
            try:
                # Try to resolve IP
                ip_address = socket.gethostbyname(subdomain_full)
                # Try to make a request to see if it's an active web server
                test_url = f"{parsed_target.scheme}://{subdomain_full}"
                try:
                    requests.head(test_url, verify=self.verify_ssl, timeout=3) # Use HEAD request for efficiency
                    if subdomain_full not in found_subdomains:
                        self.log(f"  Alt Alan Adı Bulundu: {subdomain_full} ({ip_address})", "info")
                        found_subdomains.add(subdomain_full)
                        self.found_vulnerabilities.append(Vulnerability(
                            name="Subdomain Found",
                            description=f"An active subdomain '{subdomain_full}' was discovered.",
                            url=test_url,
                            level=VulnerabilityLevel.INFO,
                            details={"subdomain": subdomain_full, "ip_address": ip_address}
                        ))
                except (RequestException, Timeout, ConnectionError):
                    # Could resolve IP but no active web server, or connection error
                    self.log(f"  Alt Alan Adı Çözümlendi ama erişilemiyor/HTTP servisi yok: {subdomain_full} ({ip_address})", "warning")
            except socket.gaierror:
                # Subdomain does not resolve
                pass
        self.log(f"{Fore.LIGHTGREEN_EX}-----------------------------------{Style.RESET_ALL}", "info")


    def _display_results(self) -> None:
        """Sonuçları ekrana yazdırır"""
        print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} Tarama tamamlandı.")
        print(f"  Tarama süresi: {self.scan_stats['scan_duration']} saniye")
        print(f"  Toplam keşfedilen/sıraya alınan URL: {self.scan_stats['total_urls_queued']}")
        print(f"  Taranan URL'ler: {self.scan_stats['scanned_urls']}")
        print(f"  Bulunan güvenlik açıkları: {self.scan_stats['found_vulnerabilities']}")
        
        if self.found_vulnerabilities:
            print(f"\n{Fore.RED}--- Bulunan Güvenlik Açıkları ---{Style.RESET_ALL}")
            # Group vulnerabilities by level for better readability
            vulnerabilities_by_level = {level: [] for level in VulnerabilityLevel}
            for vuln in self.found_vulnerabilities:
                vulnerabilities_by_level[vuln.level].append(vuln)
            
            # Print in order of severity
            for level in [VulnerabilityLevel.CRITICAL, VulnerabilityLevel.HIGH, VulnerabilityLevel.MEDIUM, VulnerabilityLevel.LOW, VulnerabilityLevel.INFO]:
                if vulnerabilities_by_level[level]:
                    print(f"\n{level.value} Seviyesi Açıklar ({len(vulnerabilities_by_level[level])}):")
                    for vuln in vulnerabilities_by_level[level]:
                        print(f"  - {Fore.RED if level in [VulnerabilityLevel.CRITICAL, VulnerabilityLevel.HIGH] else Fore.YELLOW if level == VulnerabilityLevel.MEDIUM else Fore.CYAN if level == VulnerabilityLevel.LOW else Fore.BLUE}{vuln.name}{Style.RESET_ALL} (URL: {vuln.url})")
                        if self.verbose: # Show details in verbose mode
                            print(f"    Açıklama: {vuln.description}")
                            if vuln.details:
                                print(f"    Detaylar: {vuln.details}")
        else:
            print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} Herhangi bir güvenlik açığı bulunamadı (basit taramada).")
            print(f"{Fore.YELLOW}[*]{Style.RESET_ALL} Unutmayın: Bu, kapsamlı bir güvenlik açığı tarayıcısı değildir ve derinlemesine testler gereklidir.")

    def _save_results(self) -> None:
        """Sonuçları bir dosyaya kaydeder"""
        self.log(f"Sonuçlar dosyaya kaydediliyor: {self.output_file}", "info")
        try:
            with open(self.output_file, 'w', encoding='utf-8') as f:
                f.write(f"Web Tarama Raporu - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Hedef: {self.target}\n")
                f.write(f"Tarama Süresi: {self.scan_stats['scan_duration']} saniye\n")
                f.write(f"Toplam Keşfedilen/Sıraya Alınan URL: {self.scan_stats['total_urls_queued']}\n")
                f.write(f"Taranan URL'ler: {self.scan_stats['scanned_urls']}\n")
                f.write(f"Bulunan Güvenlik Açıkları: {self.scan_stats['found_vulnerabilities']}\n")
                f.write("\n" + "="*50 + "\n")
                f.write("BULUNAN GÜVENLİK AÇIKLARI\n")
                f.write("="*50 + "\n")
                
                if not self.found_vulnerabilities:
                    f.write("Herhangi bir güvenlik açığı bulunamadı (basit taramada).\n")
                else:
                    # Sort vulnerabilities by level
                    sorted_vulnerabilities = sorted(self.found_vulnerabilities, key=lambda x: x.level.value, reverse=True)
                    for vuln in sorted_vulnerabilities:
                        f.write(f"\nAdı: {vuln.name}\n")
                        f.write(f"URL: {vuln.url}\n")
                        f.write(f"Seviye: {vuln.level.value}\n")
                        f.write(f"Açıklama: {vuln.description}\n")
                        if vuln.details:
                            f.write(f"Detaylar: {vuln.details}\n")
                        f.write("-" * 40 + "\n")
            self.log(f"Sonuçlar başarıyla '{self.output_file}' dosyasına kaydedildi.", "success")
        except IOError as e:
            self.log(f"Sonuçlar dosyaya kaydedilirken hata oluştu: {str(e)}", "error")

# --- Example Usage ---
if __name__ == "__main__":
    # Örnek kullanım:
    # 1. Sadece temel bilgi toplama ve belirli URL'yi tarama:
    # scanner_single = WebScanner('https://example.com', verbose=True, crawl=False, output_file='scan_report_single.txt')
    # scanner_single.run_scan()

    # 2. Siteyi derinlemesine tarama (crawl) ve tüm bulunan URL'leri kontrol etme:
    # Dikkat: max_urls ve threads değerlerini büyük siteler için ayarlayın.
    # Kendi yerel test sunucunuzda deneyin veya izin verilen sitelerde kullanın.
    # Örneğin, bir test sitesi: 'http://testphp.vulnweb.com/' veya 'http://dvwa.local/'
    
    # Hedef olarak kendi IP'nizi veya bir test sunucusunu kullanın.
    # Lütfen yasal ve etik sınırlar içinde kalın. İzinsiz tarama yapmayın.
    # Örneğin: 'http://localhost:8000'
    scanner_crawl = WebScanner('http://10.0.2.34/', verbose=True, crawl=True, max_urls=50, threads=5, output_file='scan_report_crawl.txt')
    scanner_crawl.run_scan()

    # Eğer sadece subdomain taraması yapmak isterseniz, tarama başlatmadan önce
    # _enumerate_subdomains'i doğrudan çağırabilirsiniz (ya da ayrı bir fonksiyon olarak tasarlayabilirsiniz).
    # scanner_subdomain = WebScanner('https://example.com', verbose=True)
    # scanner_subdomain._enumerate_subdomains()
