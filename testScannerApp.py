import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from threading import Thread
import requests
from bs4 import BeautifulSoup
import urllib.parse
import colorama
import re
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Set
from reportlab.lib.pagesizes import LETTER
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

class WebSecurityScanner:
    """Scans a website for vulnerabilities and displays real-time output"""
    
    def __init__(self, target_url: str, max_depth: int = 3, output_callback=None):
        self.target_url = target_url
        self.max_depth = max_depth
        self.visited_urls: Set[str] = set()
        self.vulnerabilities: List[Dict] = []
        self.session = requests.Session()
        self.output_callback = output_callback
        colorama.init()
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    def log_output(self, message: str):
        """Logs output in real-time"""
        if self.output_callback:
            self.output_callback(message)

    def normalize_url(self, url: str) -> str:
        """Normalize URL to its base format"""
        parsed = urllib.parse.urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def crawl(self, url: str, depth: int = 0) -> None:
        """Recursively crawls URLs up to max depth"""
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
                    self.log_output(f"Crawling: {next_url}")
                    self.crawl(next_url, depth + 1)
                    
        except Exception as e:
            self.log_output(f"Error crawling {url}: {str(e)}")

    def check_sql_injection(self, url: str) -> None:
        """Tests SQL Injection vulnerabilities"""
        sql_payloads = ["'", "1' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--"]
        for payload in sql_payloads:
            try:
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                for param in params:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={payload}")
                    response = self.session.get(test_url, verify=False)
                    if any(error in response.text.lower() for error in ['sql', 'mysql', 'sqlite', 'postgresql', 'oracle']):
                        vuln = {'type': 'SQL Injection', 'url': url, 'parameter': param, 'payload': payload}
                        self.report_vulnerability(vuln)
                        self.log_output(f"SQL Injection found: {vuln}")
            except Exception as e:
                self.log_output(f"Error testing SQL injection on {url}: {str(e)}")

    def check_xss(self, url: str) -> None:
        """Tests XSS vulnerabilities"""
        xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", "javascript:alert('XSS')"]
        for payload in xss_payloads:
            try:
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                for param in params:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={urllib.parse.quote(payload)}")
                    response = self.session.get(test_url, verify=False)
                    if payload in response.text:
                        vuln = {'type': 'Cross-Site Scripting (XSS)', 'url': url, 'parameter': param, 'payload': payload}
                        self.report_vulnerability(vuln)
                        self.log_output(f"XSS found: {vuln}")
            except Exception as e:
                self.log_output(f"Error testing XSS on {url}: {str(e)}")

    def check_sensitive_info(self, url: str) -> None:
        """Checks for sensitive information exposure"""
        sensitive_patterns = {
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'api_key': r'api[_-]?key[_-]?([\'\"|`])([a-zA-Z0-9]{32,45})\1'
        }
        try:
            response = self.session.get(url, verify=False)
            for info_type, pattern in sensitive_patterns.items():
                matches = re.finditer(pattern, response.text)
                for match in matches:
                    vuln = {'type': 'Sensitive Info', 'url': url, 'info_type': info_type, 'match': match.group()}
                    self.report_vulnerability(vuln)
                    self.log_output(f"Sensitive info found: {vuln}")
        except Exception as e:
            self.log_output(f"Error checking sensitive info on {url}: {str(e)}")

    def scan(self) -> List[Dict]:
        """Starts the scanning process"""
        self.log_output("Starting scan...")
        self.crawl(self.target_url)

        with ThreadPoolExecutor(max_workers=5) as executor:
            for url in self.visited_urls:
                executor.submit(self.check_sql_injection, url)
                executor.submit(self.check_xss, url)
                executor.submit(self.check_sensitive_info, url)

        return self.vulnerabilities

    def report_vulnerability(self, vulnerability: Dict) -> None:
        """Adds found vulnerabilities to the list"""
        self.vulnerabilities.append(vulnerability)


def export_to_pdf(vulnerabilities):
    """Exports vulnerabilities to a PDF report"""
    filename = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF Files", "*.pdf")])
    if not filename:
        return
    
    doc = SimpleDocTemplate(filename, pagesize=LETTER)
    styles = getSampleStyleSheet()
    content = []

    content.append(Paragraph("Website Vulnerability Scan Report", styles['Title']))
    content.append(Spacer(1, 12))

    for vuln in vulnerabilities:
        content.append(Paragraph(str(vuln), styles['Normal']))
        content.append(Spacer(1, 12))
    
    doc.build(content)
    messagebox.showinfo("Export Complete", f"Report saved to {filename}")


def run_scan(target_url, output_text):
    """Runs the scan and displays real-time output"""
    output_text.delete(1.0, tk.END)

    def output_callback(message):
        output_text.insert(tk.END, message + "\n")
        output_text.see(tk.END)

    scanner = WebSecurityScanner(target_url, output_callback=output_callback)
    vulnerabilities = scanner.scan()

    export_button.config(state=tk.NORMAL)
    return vulnerabilities


def start_scan():
    """Starts the scan in a separate thread"""
    target_url = url_entry.get()
    Thread(target=lambda: run_scan(target_url, output_text)).start()


def export_report():
    """Exports the scan report to PDF"""
    vulnerabilities = run_scan(url_entry.get(), output_text)
    export_to_pdf(vulnerabilities)


# GUI Setup
app = tk.Tk()
app.title("Website Vulnerability Scanner")
app.geometry("700x550")

frame = ttk.Frame(app)
frame.pack(pady=10)

url_label = ttk.Label(frame, text="Target URL:")
url_label.pack(side=tk.LEFT, padx=5)

url_entry = ttk.Entry(frame, width=50)
url_entry.pack(side=tk.LEFT, padx=5)

scan_button = ttk.Button(frame, text="Scan", command=start_scan)
scan_button.pack(side=tk.LEFT, padx=5)

export_button = ttk.Button(frame, text="Export PDF", command=export_report, state=tk.DISABLED)
export_button.pack(side=tk.LEFT, padx=5)

output_text = tk.Text(app, height=25, width=80)
output_text.pack(padx=10, pady=10)

app.mainloop()
