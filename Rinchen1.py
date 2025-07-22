# 135. satıra targeti yaz ve başlat. 
 
 

import requests
import datetime
import time
import socket
import ssl
import urllib.parse
import concurrent.futures
from requests.exceptions import RequestException
from typing import Dict, Any, Set
from bs4 import BeautifulSoup
from colorama import Fore, Style
import whois
from enum import Enum

# Basit bir Vulnerability sınıfı
class EnumLevel(str, Enum):

    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"

class Vulnerability:
    def __init__(self, name, description, url, level, details):
        self.name = name
        self.description = description
        self.url = url
        self.level = level
        self.details = details

class WebScanner:
    def __init__(self, target: str, verify_ssl: bool = True, verbose: bool = False, crawl: bool = False, max_urls: int = 100, threads: int = 10, output_file: str = None):
        self.target = target if target.startswith("http") else f"http://{target}"
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        self.crawl = crawl
        self.max_urls = max_urls
        self.threads = threads
        self.output_file = output_file

        self.start_time = time.time()
        self.scanned_urls = set()
        self.queued_urls = {self.target}
        self.found_vulnerabilities = []
        self.scan_stats = {
            'scan_duration': 0,
            'total_urls': 0,
            'scanned_urls': 0,
            'found_vulnerabilities': 0
        }

        self.sensitive_files = ['.env', 'wp-config.php', 'config.php', 'robots.txt']
        self.cms_patterns = {
            'WordPress': ['wp-content'],
            'Drupal': ['Drupal.settings'],
        }

    def log(self, message: str) -> None:
        if self.verbose:
            print(f"{Fore.CYAN}[{datetime.datetime.now().strftime('%H:%M:%S')}] {message}{Style.RESET_ALL}")

    def run_scan(self):
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} Tarama başlatıldı: {self.target}")
        try:
            resp = requests.get(self.target, verify=self.verify_ssl)
            if resp.status_code != 200:
                print(f"{Fore.RED}[!]{Style.RESET_ALL} Erişilemedi. Kod: {resp.status_code}")
                return
            self._gather_basic_info(resp)
            if self.crawl:
                self._crawl_site()
            else:
                self._scan_url(self.target)

            self.scan_stats['scan_duration'] = round(time.time() - self.start_time, 2)
            self.scan_stats['total_urls'] = len(self.scanned_urls)
            self.scan_stats['scanned_urls'] = len(self.scanned_urls)
            self.scan_stats['found_vulnerabilities'] = len(self.found_vulnerabilities)
            self._display_results()

        except Exception as e:
            print(f"{Fore.RED}[HATA]{Style.RESET_ALL} {e}")

    def _gather_basic_info(self, response):
        self.log("Sunucu bilgileri alınıyor...")
        try:
            print(f"  Server: {response.headers.get('Server', 'Yok')}")
            print(f"  X-Powered-By: {response.headers.get('X-Powered-By', 'Yok')}")
            hostname = urllib.parse.urlparse(self.target).netloc.split(':')[0]
            ip = socket.gethostbyname(hostname)
            self.log(f"IP: {ip}")
            w = whois.whois(hostname)
            self.log(f"WHOIS: {w.creation_date} - {w.expiration_date}")
        except:
            self.log("Temel bilgi alınamadı.")

    def _crawl_site(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            while self.queued_urls and len(self.scanned_urls) < self.max_urls:
                batch = list(self.queued_urls)[:50]
                self.queued_urls -= set(batch)
                for url in batch:
                    if url not in self.scanned_urls:
                        executor.submit(self._scan_url, url)

    def _scan_url(self, url):
        if url in self.scanned_urls:
            return
        self.log(f"Taranıyor: {url}")
        self.scanned_urls.add(url)
        try:
            resp = requests.get(url, verify=self.verify_ssl)
            for sensitive in self.sensitive_files:
                test_url = f"{url.rstrip('/')}/{sensitive}"
                r = requests.get(test_url, verify=self.verify_ssl)
                if r.status_code == 200 and len(r.text) > 10:
                    self.found_vulnerabilities.append(Vulnerability("Sensitive File", f"Bulundu: {sensitive}", test_url, EnumLevel.HIGH, "Dosya erişilebilir"))
            for cms, patterns in self.cms_patterns.items():
                if any(pat in resp.text for pat in patterns):
                    self.log(f"CMS Tespit edildi: {cms}")
        except:
            self.log(f"URL taranamadı: {url}")

    def _display_results(self):
        print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} Tarama tamamlandı.")
        print(f"  Taranan URL: {len(self.scanned_urls)}")
        print(f"  Bulunan Açıklar: {len(self.found_vulnerabilities)}")
        for vuln in self.found_vulnerabilities:
            print(f"{Fore.RED}- {vuln.name} @ {vuln.url} ({vuln.level}){Style.RESET_ALL}")

if __name__ == "__main__":
    scanner = WebScanner("http://10.0.2.34", verbose=True, crawl=True)
    scanner.run_scan()
