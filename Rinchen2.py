# KULLANIMI: 			python3 rinchen2.py http://10.0.2.15 -c -v  


#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import requests
import datetime
import time
import socket
import ssl
import urllib.parse
import concurrent.futures
import os
import sys
import json
import re
from enum import Enum
from typing import Dict, Any, Set, List, Optional
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
import whois

# Renkli çıktı için başlatma
init(autoreset=True)

class VulnerabilityLevel(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class Vulnerability:
    def __init__(self, name: str, description: str, url: str, level: VulnerabilityLevel, details: str = ""):
        self.name = name
        self.description = description
        self.url = url
        self.level = level
        self.details = details

class WebScanner:
    def __init__(self, target: str, verify_ssl: bool = True, verbose: bool = False, 
                 crawl: bool = False, max_urls: int = 100, threads: int = 10, 
                 output_file: str = None, timeout: int = 10, user_agent: str = None,
                 headers: Dict[str, str] = None, cookies: Dict[str, str] = None):
        
        self.target = self._normalize_url(target)
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        self.crawl = crawl
        self.max_urls = max_urls
        self.threads = threads
        self.output_file = output_file
        self.timeout = timeout
        self.user_agent = user_agent or "WebSecScanner/2.0"
        self.headers = headers or {}
        self.cookies = cookies or {}
        
        self.start_time = time.time()
        self.scanned_urls = set()
        self.queued_urls = {self.target}
        self.found_vulnerabilities = []
        self.scan_stats = {
            'scan_duration': 0,
            'total_urls': 0,
            'scanned_urls': 0,
            'found_vulnerabilities': 0,
            'start_time': datetime.datetime.now().isoformat()
        }

        # Gelişmiş hassas dosya listesi
        self.sensitive_files = [
            '.env', '.git/config', 'wp-config.php', 'config.php',
            'configuration.php', 'settings.php', 'database.php',
            'backup.sql', 'backup.zip', 'phpinfo.php', 'robots.txt',
            '.htaccess', 'web.config', 'error_log', 'server-status',
            'admin/', 'wp-admin/', 'administrator/', 'login/',
            'api/', 'graphql', 'swagger.json', 'config.json'
        ]

        # Gelişmiş CMS tespit kalıpları
        self.cms_patterns = {
            'WordPress': ['wp-content', 'wp-includes', '/wp-login.php', 'wp-json'],
            'Joomla': ['/administrator/', 'com_content', '/templates/', 'joomla'],
            'Drupal': ['Drupal.settings', '/sites/default/', '/core/misc/drupal.js'],
            'Magento': ['Mage.Cookies', '/skin/frontend/', '/media/js/mage'],
            'Laravel': ['/storage/framework/', 'mix-manifest.json', 'laravel_session']
        }

        # Gelişmiş test payload'ları
        self.xss_payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            'javascript:alert(1)'
        ]
        
        self.sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1 --",
            "' UNION SELECT null,table_name FROM information_schema.tables--",
            "' OR SLEEP(5)--"
        ]
        
        self.risky_http_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH']
        self.security_headers = [
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Strict-Transport-Security',
            'Referrer-Policy'
        ]

    def _normalize_url(self, url: str) -> str:
        """URL'yi standart formata getirir"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url.rstrip('/')

    def log(self, message: str, level: str = "info") -> None:
        """Renkli log mesajları"""
        colors = {
            "info": Fore.CYAN,
            "warning": Fore.YELLOW,
            "error": Fore.RED,
            "success": Fore.GREEN
        }
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        if self.verbose or level in ("error", "warning"):
            print(f"{colors.get(level, Fore.CYAN)}[{timestamp}][{level.upper()}]{Style.RESET_ALL} {message}")

    def _detect_cms(self, html_content: str) -> Optional[str]:
        """CMS tespiti yapar"""
        detected = False
        for cms_name, patterns in self.cms_patterns.items():
            for pattern in patterns:
                if re.search(pattern, html_content, re.IGNORECASE):
                    self.log(f"CMS Tespit Edildi: {cms_name}", "success")
                    return cms_name
        return None

    def _check_ssl(self) -> None:
        """SSL sertifikasını kontrol eder"""
        if not self.target.startswith('https://'):
            return
            
        try:
            hostname = urllib.parse.urlparse(self.target).netloc
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    subject = dict(x[0] for x in cert['subject'])
                    issuer = dict(x[0] for x in cert['issuer'])
                    
                    self.log(f"SSL Sertifikası Bilgileri:", "info")
                    self.log(f"  Konu: {subject.get('commonName', 'Bilinmiyor')}")
                    self.log(f"  Veren: {issuer.get('organizationName', 'Bilinmiyor')}")
                    self.log(f"  Geçerlilik: {cert.get('notBefore')} - {cert.get('notAfter')}")
                    
                    # SSL/TLS zayıflıkları kontrolü
                    cipher = ssock.cipher()
                    if cipher:
                        self.log(f"  Kullanılan Şifreleme: {cipher[0]} (TLS {cipher[1]})")
                        if 'SSL' in cipher[0] or 'TLSv1' in cipher[0]:
                            self._add_vulnerability(
                                "Zayıf Şifreleme Algoritması",
                                "Sunucu zayıf SSL/TLS şifrelemesi kullanıyor",
                                self.target,
                                VulnerabilityLevel.HIGH,
                                f"Kullanılan şifreleme: {cipher[0]}"
                            )
        except Exception as e:
            self.log(f"SSL kontrol hatası: {str(e)}", "warning")

    def _make_request(self, url: str, method: str = "GET", **kwargs) -> Optional[requests.Response]:
        """HTTP isteği yapar"""
        try:
            headers = {**self.headers, 'User-Agent': self.user_agent}
            resp = requests.request(
                method,
                url,
                verify=self.verify_ssl,
                timeout=self.timeout,
                headers=headers,
                cookies=self.cookies,
                **kwargs
            )
            return resp
        except RequestException as e:
            self.log(f"İstek hatası ({url}): {str(e)}", "warning")
            return None

    def _extract_links(self, html: str, base_url: str) -> Set[str]:
        """HTML'den linkleri çıkarır"""
        soup = BeautifulSoup(html, 'html.parser')
        links = set()
        
        # Tüm olası link kaynaklarını kontrol et
        for tag in soup.find_all(['a', 'link', 'img', 'script', 'iframe', 'form']):
            for attr in ['href', 'src', 'action']:
                if attr in tag.attrs:
                    url = tag[attr].strip()
                    if url and not url.startswith(('javascript:', 'mailto:', 'tel:', '#')):
                        absolute_url = urllib.parse.urljoin(base_url, url)
                        links.add(absolute_url)
        return links

    def _check_xss(self, url: str) -> None:
        """XSS açıklarını kontrol eder"""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        if not params:
            return
            
        for param in params:
            for payload in self.xss_payloads:
                test_url = self._inject_payload(url, param, payload)
                resp = self._make_request(test_url)
                
                if resp and payload in resp.text:
                    self._add_vulnerability(
                        "XSS Açığı",
                        f"Reflected XSS tespit edildi: {param} parametresi",
                        test_url,
                        VulnerabilityLevel.HIGH,
                        f"Payload: {payload}"
                    )
                    break

    def _check_sql_injection(self, url: str) -> None:
        """SQL Injection açıklarını kontrol eder"""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        if not params:
            return
            
        for param in params:
            for payload in self.sql_payloads:
                test_url = self._inject_payload(url, param, payload)
                resp = self._make_request(test_url)
                
                if resp and any(err in resp.text.lower() for err in ['sql', 'syntax', 'mysql', 'error']):
                    self._add_vulnerability(
                        "SQL Injection",
                        f"SQL Injection açığı tespit edildi: {param} parametresi",
                        test_url,
                        VulnerabilityLevel.CRITICAL,
                        f"Payload: {payload}"
                    )
                    break

    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        """URL'ye payload enjekte eder"""
        parsed = urllib.parse.urlparse(url)
        query = urllib.parse.parse_qs(parsed.query)
        query[param] = [payload]
        new_query = urllib.parse.urlencode(query, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    def _check_sensitive_files(self, base_url: str) -> None:
        """Hassas dosyaları kontrol eder"""
        for file_path in self.sensitive_files:
            test_url = urllib.parse.urljoin(base_url, file_path)
            resp = self._make_request(test_url)
            
            if resp and resp.status_code == 200:
                content_length = int(resp.headers.get('Content-Length', 0))
                if content_length < 1000000:  # 1MB'den küçük dosyaları kontrol et
                    self._add_vulnerability(
                        "Hassas Dosya Erişimi",
                        f"Hassas dosya erişilebilir: {file_path}",
                        test_url,
                        VulnerabilityLevel.HIGH if any(x in file_path for x in ['config', 'admin']) else VulnerabilityLevel.MEDIUM
                    )

    def _check_directory_listing(self, url: str) -> None:
        """Dizin listeleme açığını kontrol eder"""
        parsed = urllib.parse.urlparse(url)
        dir_path = os.path.dirname(parsed.path)
        
        if not dir_path:
            return
            
        test_url = urllib.parse.urljoin(url, dir_path + '/')
        resp = self._make_request(test_url)
        
        if resp and resp.status_code == 200:
            if ('<directory' in resp.text.lower() or 
                '<title>Index of' in resp.text.lower() or
                ('<a href="' in resp.text and 'Parent Directory' in resp.text)):
                self._add_vulnerability(
                    "Dizin Listeleme Açığı",
                    "Dizin listeleme özelliği etkin",
                    test_url,
                    VulnerabilityLevel.MEDIUM
                )

    def _check_http_methods(self) -> None:
        """Riskli HTTP metodlarını kontrol eder"""
        methods = ['OPTIONS'] + self.risky_http_methods
        for method in methods:
            resp = self._make_request(self.target, method=method)
            if resp and resp.status_code not in [405, 501]:
                self._add_vulnerability(
                    f"Riskli HTTP Metodu: {method}",
                    f"Riskli HTTP metodu etkin: {method}",
                    self.target,
                    VulnerabilityLevel.MEDIUM,
                    f"HTTP {method} metodu {resp.status_code} durum koduyla yanıt veriyor"
                )

    def _check_security_headers(self, response: requests.Response) -> None:
        """Eksik güvenlik başlıklarını kontrol eder"""
        missing_headers = [h for h in self.security_headers if h not in response.headers]
        
        if missing_headers:
            for header in missing_headers:
                severity = VulnerabilityLevel.HIGH if header in ['Content-Security-Policy', 'Strict-Transport-Security'] else VulnerabilityLevel.MEDIUM
                self._add_vulnerability(
                    f"Eksik Güvenlik Başlığı: {header}",
                    f"Önemli güvenlik başlığı eksik: {header}",
                    self.target,
                    severity
                )

    def _add_vulnerability(self, name: str, description: str, url: str, level: VulnerabilityLevel, details: str = ""):
        """Yeni güvenlik açığı ekler"""
        vuln = Vulnerability(name, description, url, level, details)
        self.found_vulnerabilities.append(vuln)
        self.log(f"Bulunan açık: {name} ({url})", "error")

    def _scan_url(self, url: str) -> Set[str]:
        """Tek bir URL'yi tara"""
        self.log(f"Taranıyor: {url}", "info")
        self.scanned_urls.add(url)
        
        resp = self._make_request(url)
        if not resp:
            return set()
            
        # Güvenlik kontrolleri
        self._check_xss(url)
        self._check_sql_injection(url)
        self._check_sensitive_files(url)
        self._check_directory_listing(url)
        
        # Yeni URL'ler çıkar
        return self._extract_links(resp.text, url) if self.crawl else set()

    def _crawl_site(self) -> None:
        """Siteyi crawl eder"""
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            while self.queued_urls and len(self.scanned_urls) < self.max_urls:
                current_batch = list(self.queued_urls)[:50]
                self.queued_urls -= set(current_batch)
                
                for url in current_batch:
                    if url not in self.scanned_urls:
                        futures[executor.submit(self._scan_url, url)] = url
                
                for future in concurrent.futures.as_completed(futures):
                    url = futures[future]
                    try:
                        new_urls = future.result()
                        for new_url in new_urls:
                            if (new_url not in self.scanned_urls and 
                                new_url not in self.queued_urls and
                                urllib.parse.urlparse(new_url).netloc == urllib.parse.urlparse(self.target).netloc):
                                self.queued_urls.add(new_url)
                    except Exception as e:
                        self.log(f"URL tarama hatası {url}: {str(e)}", "error")

    def _display_results(self):
        """Sonuçları göster"""
        print(f"\n{Fore.GREEN}=== TARAMA SONUÇLARI ===")
        print(f"Hedef: {self.target}")
        print(f"Başlangıç Zamanı: {self.scan_stats['start_time']}")
        print(f"Tarama Süresi: {self.scan_stats['scan_duration']} saniye")
        print(f"Taranan URL Sayısı: {self.scan_stats['scanned_urls']}")
        print(f"Bulunan Güvenlik Açıkları: {self.scan_stats['found_vulnerabilities']}{Style.RESET_ALL}")
        
        if self.found_vulnerabilities:
            print(f"\n{Fore.RED}=== BULUNAN GÜVENLİK AÇIKLARI ===")
            for vuln in sorted(self.found_vulnerabilities, key=lambda x: x.level.value, reverse=True):
                print(f"\n{Fore.RED}[{vuln.level.name}] {vuln.name}{Style.RESET_ALL}")
                print(f"URL: {vuln.url}")
                print(f"Açıklama: {vuln.description}")
                if vuln.details:
                    print(f"Detay: {vuln.details}")

    def _save_results(self):
        """Sonuçları dosyaya kaydeder"""
        try:
            result = {
                'metadata': {
                    'target': self.target,
                    'scan_date': datetime.datetime.now().isoformat(),
                    'scan_duration': self.scan_stats['scan_duration'],
                    'scanned_urls': self.scan_stats['scanned_urls']
                },
                'vulnerabilities': [vars(v) for v in self.found_vulnerabilities]
            }
            
            with open(self.output_file, 'w') as f:
                json.dump(result, f, indent=2)
                
            self.log(f"Sonuçlar kaydedildi: {self.output_file}", "success")
        except Exception as e:
            self.log(f"Sonuçlar kaydedilemedi: {str(e)}", "error")

    def run_scan(self) -> Dict[str, Any]:
        """Taramayı başlat"""
        try:
            # Başlangıç kontrolleri
            resp = self._make_request(self.target)
            if not resp:
                return {'success': False, 'error': "Hedefe erişilemedi"}
            
            # Temel bilgiler
            self.log(f"Sunucu: {resp.headers.get('Server', 'Bilinmiyor')}")
            self.log(f"X-Powered-By: {resp.headers.get('X-Powered-By', 'Bilinmiyor')}")
            
            # CMS tespiti
            cms = self._detect_cms(resp.text)
            if cms:
                self.log(f"Tespit Edilen CMS: {cms}", "success")
            
            # Güvenlik başlıkları
            self._check_security_headers(resp)
            
            # SSL kontrolü
            self._check_ssl()
            
            # HTTP metodları kontrolü
            self._check_http_methods()
            
            # Ana tarama işlemi
            if self.crawl:
                self._crawl_site()
            else:
                self._scan_url(self.target)
            
            # İstatistikleri güncelle
            self.scan_stats.update({
                'scan_duration': round(time.time() - self.start_time, 2),
                'total_urls': len(self.scanned_urls),
                'scanned_urls': len(self.scanned_urls),
                'found_vulnerabilities': len(self.found_vulnerabilities)
            })
            
            # Sonuçları işle
            self._display_results()
            if self.output_file:
                self._save_results()
                
            return {
                'success': True,
                'stats': self.scan_stats,
                'vulnerabilities': [vars(v) for v in self.found_vulnerabilities]
            }
            
        except Exception as e:
            self.log(f"Tarama hatası: {str(e)}", "error")
            return {'success': False, 'error': str(e)}

def parse_arguments():
    """Komut satırı argümanlarını parse eder"""
    parser = argparse.ArgumentParser(description='Gelişmiş Web Güvenlik Tarayıcısı')
    parser.add_argument('target', help='Taranacak hedef URL (örn: http://10.0.2.23)')
    parser.add_argument('-o', '--output', help='Sonuç dosyası yolu')
    parser.add_argument('-v', '--verbose', action='store_true', help='Detaylı çıktı')
    parser.add_argument('-c', '--crawl', action='store_true', help='Siteyi crawl et')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Thread sayısı (varsayılan: 5)')
    return parser.parse_args()

def main():
    args = parse_arguments()
    
    print(f"{Fore.GREEN}=== Gelişmiş Web Güvenlik Tarayıcısı ===")
    print(f"{Fore.YELLOW}Uyarı: Sadece izin verdiğiniz sistemleri tarayın!{Style.RESET_ALL}\n")
    
    scanner = WebScanner(
        target=args.target,
        verbose=args.verbose,
        crawl=args.crawl,
        output_file=args.output,
        threads=args.threads
    )
    
    result = scanner.run_scan()
    
    if not result['success']:
        print(f"\n{Fore.RED}Tarama başarısız: {result['error']}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Tarama kullanıcı tarafından durduruldu.{Style.RESET_ALL}")
        sys.exit(1)
