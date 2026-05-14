# scanner.py
import requests
from bs4 import BeautifulSoup
import threading

HEADERS = {'User-Agent': 'Mozilla/5.0'}

def extract_links_forms(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        soup = BeautifulSoup(r.text, 'html.parser')
        forms = soup.find_all("form")
        return forms
    except:
        return []

def detect_xss(url):
    payload = "<script>alert('XSS')</script>"
    test_url = f"{url}?q={payload}"
    r = requests.get(test_url, headers=HEADERS)
    return "[!] XSS Detected!" if payload in r.text else "[-] No XSS."

def detect_csrf(forms):
    for form in forms:
        if form.get("method", "get").lower() == "post":
            if "csrf" not in str(form).lower():
                return "[!] Possible CSRF Risk (no token detected)."
    return "[-] No CSRF."

def detect_sqli(url):
    payload = "' OR '1'='1"
    test_url = f"{url}?id={payload}"
    r = requests.get(test_url, headers=HEADERS)
    errors = ["you have an error", "mysql_fetch", "ORA-"]
    return "[!] SQL Injection Detected!" if any(err in r.text.lower() for err in errors) else "[-] No SQLi."

def detect_dos(url):
    def flood():
        for _ in range(10):
            try:
                requests.get(url, headers=HEADERS, timeout=5)
            except:
                pass
    threads = [threading.Thread(target=flood) for _ in range(10)]
    for t in threads: t.start()
    for t in threads: t.join()
    return "[*] Lightweight DoS test completed."

def detect_info_leakage(url):
    r = requests.get(url, headers=HEADERS)
    leaks = ["x-powered-by", "server", "php", ".git", "config.json"]
    for leak in leaks:
        if leak.lower() in r.text.lower() or leak.lower() in str(r.headers).lower():
            return f"[!] Info Leak Found: {leak}"
    return "[-] No Information Leakage."

def detect_misconfig(url):
    r = requests.get(url, headers=HEADERS)
    missing = ["X-Content-Type-Options", "X-Frame-Options", "Strict-Transport-Security"]
    findings = [f"[!] Missing Header: {h}" for h in missing if h not in r.headers]
    return findings if findings else ["[-] No Misconfigurations."]

def detect_outdated_components(url):
    r = requests.get(url, headers=HEADERS)
    techs = ["php", "wordpress", "jquery", "apache", "nginx"]
    found = [f"[!] Outdated Tech Detected: {t}" for t in techs if t in r.text.lower() or t in str(r.headers).lower()]
    return found if found else ["[-] No Outdated Components."]

def run_all_checks(url):
    forms = extract_links_forms(url)
    results = [
        detect_xss(url),
        detect_csrf(forms),
        detect_sqli(url),
        detect_dos(url),
        detect_info_leakage(url),
    ]
    results.extend(detect_misconfig(url))
    results.extend(detect_outdated_components(url))
    return results
