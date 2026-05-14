import requests
from bs4 import BeautifulSoup
import threading
import argparse

# Define default headers to mimic a browser
HEADERS = {
    'User-Agent': 'Mozilla/5.0'
}

# Extract all forms and links from the given URL
def extract_links_forms(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        soup = BeautifulSoup(r.text, 'html.parser')
        forms = soup.find_all("form")  # Get all forms
        links = [a['href'] for a in soup.find_all("a", href=True)]  # Get all links
        return forms, links
    except Exception as e:
        print("[ERROR] Failed to crawl:", e)
        return [], []

# XSS detection by injecting a simple script payload
def detect_xss(url, log):
    log("[*] Checking for XSS...")
    payload = "<script>alert('XSS')</script>"
    test_url = f"{url}?q={payload}"
    try:
        r = requests.get(test_url, headers=HEADERS)
        if payload in r.text:
            log("[!] XSS Detected!")
        else:
            log("[-] No XSS.")
    except:
        log("[ERROR] Could not complete XSS check.")

# CSRF detection by checking for missing CSRF tokens in POST forms
def detect_csrf(forms, log):
    log("[*] Checking for CSRF...")
    for form in forms:
        if form.get("method", "get").lower() == "post":  # Only check POST forms
            inputs = form.find_all("input")
            has_token = any("csrf" in inp.get("name", "").lower() for inp in inputs)
            if not has_token:
                log("[!] Possible CSRF Risk: No CSRF token detected in a POST form.")

# SQLi detection using a common SQL injection payload
def detect_sqli(url, log):
    log("[*] Checking for SQLi...")
    payload = "' OR '1'='1"
    test_url = f"{url}?id={payload}"
    try:
        r = requests.get(test_url, headers=HEADERS)
        # Check for known SQL error patterns in the response
        errors = ["you have an error in your sql syntax", "mysql_fetch", "ORA-"]
        if any(err in r.text.lower() for err in errors):
            log("[!] SQL Injection Detected!")
        else:
            log("[-] No SQLi.")
    except:
        log("[ERROR] Could not complete SQLi check.")

# Lightweight DoS simulation by sending multiple requests in parallel
def detect_dos(url, log):
    log("[*] Testing lightweight DoS (use responsibly)...")
    confirm = input("[!] Are you sure you want to run a DoS test? (y/n): ").strip().lower()
    if confirm != 'y':
        log("[-] Skipping DoS test.")
        return

    def flood():
        for _ in range(10):
            try:
                requests.get(url, headers=HEADERS, timeout=5)
            except:
                pass

    threads = [threading.Thread(target=flood) for _ in range(10)]  # Create 10 threads
    for t in threads: t.start()
    for t in threads: t.join()
    log("[!] DoS simulation completed (check server logs manually).")

# Info leakage detection by checking for sensitive headers/content
def detect_info_leakage(url, log):
    log("[*] Checking for Information Leakage...")
    try:
        r = requests.get(url, headers=HEADERS)
        leaks = ["x-powered-by", "server", "php", ".git", "config.json"]
        for leak in leaks:
            if leak.lower() in r.text.lower() or leak.lower() in str(r.headers).lower():
                log(f"[!] Potential Info Leakage: {leak}.")
    except:
        log("[ERROR] Could not complete info leakage check.")

# Check for missing security headers (indicating misconfiguration)
def detect_misconfig(url, log):
    log("[*] Checking for Security Misconfiguration...")
    try:
        r = requests.get(url, headers=HEADERS)
        missing_headers = ["X-Content-Type-Options", "X-Frame-Options", "Strict-Transport-Security"]
        for h in missing_headers:
            if h not in r.headers:
                log(f"[!] Missing security header: {h}.")
    except:
        log("[ERROR] Could not complete misconfiguration check.")

# Check for outdated software by identifying known technologies in response and headers
def detect_outdated_components(url, log):
    log("[*] Checking for outdated components...\n")
    try:
        r = requests.get(url, headers=HEADERS)
        # Sample known technologies and their latest versions
        techs = {
            "jquery": {
                "name": "jQuery",
                "url": "https://jquery.com/",
                "latest_version": "3.6.0",
                "cve": "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=jquery"
            },
            "apache": {
                "name": "Apache HTTP Server",
                "url": "https://httpd.apache.org/",
                "latest_version": "2.4.54",
                "cve": "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=apache"
            },
            "nginx": {
                "name": "Nginx",
                "url": "https://nginx.org/",
                "latest_version": "1.23.1",
                "cve": "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=nginx"
            },
            "php": {
                "name": "PHP",
                "url": "https://www.php.net/",
                "latest_version": "8.0.12",
                "cve": "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=php"
            },
            "wordpress": {
                "name": "WordPress",
                "url": "https://wordpress.org/",
                "latest_version": "5.8.1",
                "cve": "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=wordpress"
            }
        }

        # Check if any known tech keywords appear in the HTML or headers
        found = {t: techs[t] for t in techs if t in r.text.lower() or t in str(r.headers).lower()}
        
        if found:
            log("** Outdated Components Detected **\n")
            for tech, details in found.items():
                log(f"  - {details['name']}:")
                log(f"      Latest Version: {details['latest_version']}")
                log(f"      Official Site: {details['url']}")
                log(f"      CVE Information: {details['cve']}\n")
        else:
            log("[-] No outdated components detected.")
    except:
        log("[ERROR] Could not complete outdated components check.")

# Run selected scans on the target
def scan_site(url, args, forms):
    logs = []

    def log_print(msg):
        print(msg)
        logs.append(msg)

    log_print(f"\n--- Starting Scan on {url} ---\n")

    # Run the appropriate scans based on CLI flags
    if args.all or args.xss:
        detect_xss(url, log_print)
    if args.all or args.csrf:
        detect_csrf(forms, log_print)
    if args.all or args.sqli:
        detect_sqli(url, log_print)
    if args.all or args.dos:
        detect_dos(url, log_print)
    if args.all or args.info:
        detect_info_leakage(url, log_print)
    if args.all or args.misconfig:
        detect_misconfig(url, log_print)
    if args.all or args.components:
        detect_outdated_components(url, log_print)

    log_print("\n--- Scan Complete ---\n")

    # Save results to a file if specified
    if args.output:
        with open(args.output, "w") as f:
            f.write("\n".join(logs))
        print(f"[+] Report saved to {args.output}")

# Parse command-line arguments
def parse_args():
    parser = argparse.ArgumentParser(
        description="🔍 Simple Python Web Vulnerability Scanner"
    )

    # Required argument
    parser.add_argument("url", help="Target site URL (e.g., https://example.com)")

    # Optional individual scan toggles
    parser.add_argument("--xss", action="store_true", help="Enable XSS check")
    parser.add_argument("--sqli", action="store_true", help="Enable SQL Injection check")
    parser.add_argument("--csrf", action="store_true", help="Enable CSRF check")
    parser.add_argument("--dos", action="store_true", help="Enable DoS simulation (requires confirmation)")
    parser.add_argument("--info", action="store_true", help="Enable info leakage check")
    parser.add_argument("--misconfig", action="store_true", help="Enable misconfiguration check")
    parser.add_argument("--components", action="store_true", help="Enable outdated components check")

    # Run all checks
    parser.add_argument("--all", action="store_true", help="Run all checks")

    # Output file for saving the scan report
    parser.add_argument("--output", type=str, help="Save results to a file (e.g., report.txt)")

    return parser.parse_args()

# Main driver function
def main():
    args = parse_args()
    url = args.url

    # Prepend http if missing
    if not url.startswith("http"):
        url = "http://" + url

    # Crawl forms and then start scan
    forms, _ = extract_links_forms(url)
    scan_site(url, args, forms)

# Entry point
if __name__ == "__main__":
    main()
