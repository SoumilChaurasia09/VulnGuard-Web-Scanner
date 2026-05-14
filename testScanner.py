import requests
from bs4 import BeautifulSoup
import urllib.parse
import colorama
import re
import csv
import json
from concurrent.futures import ThreadPoolExecutor
from tabulate import tabulate
from time import time
import sys
from typing import List, Dict, Set
from collections import Counter

class WebSecurityScanner:
    def __init__(self, target_url: str, max_depth: int = 3):
        self.target_url = target_url
        self.max_depth = max_depth
        self.visited_urls: Set[str] = set()
        self.vulnerabilities: List[Dict] = []
        self.session = requests.Session()
        colorama.init()
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    def normalize_url(self, url: str) -> str:
        parsed = urllib.parse.urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def crawl(self, url: str, depth: int = 0) -> None:
        if depth > self.max_depth or url in self.visited_urls:
            return

        try:
            self.visited_urls.add(url)
            response = self.session.get(url, verify=False, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')

            links = soup.find_all('a', href=True)
            for link in links:
                next_url = urllib.parse.urljoin(url, link['href'])
                if next_url.startswith(self.target_url) and next_url not in self.visited_urls:
                    self.crawl(next_url, depth + 1)

        except requests.exceptions.RequestException as e:
            print(f"Request error crawling {url}: {str(e)}")
        except Exception as e:
            print(f"Error crawling {url}: {str(e)}")

    def check_sql_injection(self, url: str) -> None:
        sql_payloads = ["'", "1' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--"]
        for payload in sql_payloads:
            try:
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                for param in params:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={payload}")
                    response = self.session.get(test_url, verify=False)

                    if any(error in response.text.lower() for error in ['sql', 'mysql', 'sqlite', 'postgresql', 'oracle']):
                        self.report_vulnerability({
                            'type': 'SQL Injection',
                            'url': url,
                            'parameter': param,
                            'payload': payload
                        })
            except Exception as e:
                print(f"Error testing SQL injection on {url}: {str(e)}")

    def check_xss(self, url: str) -> None:
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
        for payload in xss_payloads:
            try:
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                for param in params:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={urllib.parse.quote(payload)}")
                    response = self.session.get(test_url, verify=False)

                    if payload in response.text:
                        self.report_vulnerability({
                            'type': 'Cross-Site Scripting (XSS)',
                            'url': url,
                            'parameter': param,
                            'payload': payload
                        })
            except Exception as e:
                print(f"Error testing XSS on {url}: {str(e)}")

    def check_sensitive_info(self, url: str) -> None:
        sensitive_patterns = {
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'api_key': r'api[_-]?key[_-]?([\'\"|`])([a-zA-Z0-9]{32,45})\1'
        }
        try:
            response = self.session.get(url, verify=False)
            for info_type, pattern in sensitive_patterns.items():
                matches = re.finditer(pattern, response.text)
                for match in matches:
                    self.report_vulnerability({
                        'type': 'Sensitive Info Exposure',
                        'url': url,
                        'parameter': info_type,
                        'payload': match.group(0)
                    })
        except Exception as e:
            print(f"Error checking sensitive information on {url}: {str(e)}")

    def scan(self) -> List[Dict]:
        print(f"\n{colorama.Fore.BLUE}Starting security scan of {self.target_url}{colorama.Style.RESET_ALL}\n")
        start_time = time()
        self.crawl(self.target_url)

        with ThreadPoolExecutor(max_workers=5) as executor:
            for url in self.visited_urls:
                executor.submit(self.check_sql_injection, url)
                executor.submit(self.check_xss, url)
                executor.submit(self.check_sensitive_info, url)

        end_time = time()
        duration = round(end_time - start_time, 2)

        self.display_results(duration)
        self.save_results()

        return self.vulnerabilities

    def report_vulnerability(self, vulnerability: Dict) -> None:
        self.vulnerabilities.append(vulnerability)

    def display_results(self, duration: float) -> None:
        print("\n==========================================")
        print("        🛡️  Web Security Scan Report       ")
        print("==========================================")
        print(f"📍 Target URL: {self.target_url}")
        print(f"🔍 Max Depth: {self.max_depth}")
        print(f"🔧 Scanned URLs: {len(self.visited_urls)}")
        print(f"⚠️  Vulnerabilities Found: {len(self.vulnerabilities)}\n")

        if self.vulnerabilities:
            table = [
                [v['type'], v['url'], v.get('parameter', 'N/A'), v.get('payload', 'N/A')]
                for v in self.vulnerabilities
            ]
            print(tabulate(table, headers=["Type", "URL", "Param", "Payload"], tablefmt="plain"))

            # Display counts for each vulnerability type
            vuln_counts = Counter(v['type'] for v in self.vulnerabilities)

            print("\n------------------------------------------")
            print("📊  Summary")
            print("------------------------------------------")
            for vuln_type, count in vuln_counts.items():
                print(f"⚠️  {vuln_type}: {count}")
        else:
            print("✅ No vulnerabilities found!")

        print("\n------------------------------------------")
        print(f"✅ Scanned URLs:    {len(self.visited_urls)}")
        print(f"⚠️ Vulnerabilities: {len(self.vulnerabilities)}")
        print(f"⏱️ Duration:         {duration} seconds")
        print("==========================================\n")

    def save_results(self) -> None:
        # Save to CSV
        fieldnames = ["type", "url", "parameter", "payload"]
        with open("scan_results.csv", "w", newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.vulnerabilities)

        # Save to JSON
        with open("scan_results.json", "w", encoding='utf-8') as jsonfile:
            json.dump(self.vulnerabilities, jsonfile, indent=4)

        print(f"📁 Results saved as 'scan_results.csv' and 'scan_results.json'")

# Run the scanner
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <target_url>")
        sys.exit(1)

    target_url = sys.argv[1]
    scanner = WebSecurityScanner(target_url)
    scanner.scan()
