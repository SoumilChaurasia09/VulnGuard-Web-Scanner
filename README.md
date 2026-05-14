# VulnGuard-Web-Scanner

## Advanced Web Vulnerability Scanner

VulnGuard-Web-Scanner is a Python-based cybersecurity project designed to identify common web application vulnerabilities through automated scanning and analysis.

The project combines Flask, Requests, BeautifulSoup, Tkinter, and multi-threaded scanning techniques to provide both web-based and desktop-based vulnerability assessment environments.

It is capable of detecting multiple common web security issues including:
- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Information Leakage
- Security Misconfigurations
- Outdated Components
- Sensitive Data Exposure

---

# Repository

```text
https://github.com/SoumilChaurasia09/VulnGuard-Web-Scanner
```

---

# Features

## Vulnerability Detection

### Supported Security Checks

- SQL Injection Detection
- Cross-Site Scripting Detection
- CSRF Detection
- Information Leakage Detection
- Security Header Analysis
- Outdated Technology Detection
- Lightweight DoS Simulation
- Sensitive Information Exposure Detection

---

## Scanning Features

- Recursive website crawling
- URL parameter testing
- Form inspection
- Multi-threaded scanning
- Real-time scan logging
- Automated payload injection
- HTTP header analysis
- Technology fingerprinting

---

## Reporting & Export

- TXT Report Export
- CSV Report Export
- JSON Report Export
- PDF Report Export

---

## Interfaces

### Flask Web Interface
- Browser-based scanner
- Interactive scanning
- Result display page

### Tkinter Desktop GUI
- Real-time scan output
- PDF export support
- Interactive controls

### Command-Line Scanner
- Lightweight scanning
- Fast execution
- Detailed console reports

---

# Project Structure

```bash
VulnGuard-Web-Scanner/
│
├── templates/
│   └── index.html
│
├── app.py
├── scanner.py
├── sc.py
├── testScanner.py
├── testScannerApp.py
├── scan_report.txt
│
├── scan_results.csv
├── scan_results.json
│
└── README.md
```

---

## Example Console Scan Output

```text
--- Starting Scan on http://testphp.vulnweb.com/ ---

[*] Checking for XSS...
[-] No XSS.

[*] Checking for CSRF...
[!] Possible CSRF Risk detected.

[*] Checking for SQLi...
[-] No SQLi.

[*] Checking for Information Leakage...
[!] Potential Info Leakage: server

[*] Checking for outdated components...
[!] Outdated Tech Detected: PHP

--- Scan Complete ---
```

---

# Technologies Used

| Technology | Purpose |
|------------|----------|
| Python | Core Development |
| Flask | Web Application |
| Tkinter | Desktop GUI |
| Requests | HTTP Request Handling |
| BeautifulSoup | HTML Parsing |
| ReportLab | PDF Report Export |
| Threading | Parallel Scanning |
| CSV/JSON | Report Storage |

---

# Installation

## Clone Repository

```bash
git clone https://github.com/SoumilChaurasia09/VulnGuard-Web-Scanner.git
cd VulnGuard-Web-Scanner
```

---

## Install Dependencies

```bash
pip install flask requests beautifulsoup4 reportlab colorama tabulate
```

---

# Running the Project

## Run Flask Web Version

```bash
python app.py
```

Open browser:

```text
http://127.0.0.1:5000
```

---

## Run Advanced Scanner

```bash
python sc.py https://example.com
```

---

## Run Tkinter GUI Version

```bash
python testScannerApp.py
```

---

# Vulnerability Detection Techniques

## SQL Injection Detection

Tests URL parameters using SQL payloads such as:

```text
' OR '1'='1
```

Checks application responses for database-related error patterns.

---

## Cross-Site Scripting Detection

Injects XSS payloads including:

```html
<script>alert('XSS')</script>
```

Detects reflected script execution possibilities.

---

## CSRF Detection

Analyzes forms for missing CSRF protection tokens.

---

## Information Leakage Detection

Checks for:
- Server information disclosure
- X-Powered-By headers
- Public .git exposure
- Config file exposure
- PHP disclosure

---

## Security Misconfiguration Detection

Detects missing security headers:
- X-Frame-Options
- X-Content-Type-Options
- Strict-Transport-Security

---

## Outdated Component Detection

Scans for technologies such as:
- PHP
- Apache
- Nginx
- jQuery
- WordPress

Provides associated CVE reference links.

---

# Example Scan Result

```text
[*] Checking for XSS...
[-] No XSS.

[*] Checking for SQLi...
[-] No SQLi.

[*] Checking for Information Leakage...
[!] Potential Info Leakage: server

[*] Checking for outdated components...
[!] Outdated Tech Detected: jquery

--- Scan Complete ---
```

---

# Exported Reports

Generated reports may include:
- Vulnerability type
- Affected URL
- Parameters tested
- Payload used
- Security findings
- Scan summary

Supported export formats:
- TXT
- CSV
- JSON
- PDF

---

# Requirements

- Python 3.9+
- Internet Connection
- Windows/Linux/macOS

---

# Future Improvements

- Authentication testing
- Login brute-force detection
- Subdomain scanning
- Directory brute forcing
- Port scanning integration
- OWASP Top 10 mapping
- API vulnerability scanning
- Real-time dashboards
- Session security analysis
- Dark mode UI

---

# Use Cases

- Ethical hacking practice
- Web application testing
- Cybersecurity learning
- Educational demonstrations
- Security auditing
- Vulnerability assessment

---

# Security & Ethics Notice

This project is intended strictly for:
- Educational purposes
- Authorized security testing
- Ethical cybersecurity research

Do not scan websites or systems without proper authorization.

---

# Repository Topics

```text
python
cybersecurity
web-security
vulnerability-scanner
ethical-hacking
flask
tkinter
sql-injection
xss
csrf
security-testing
owasp
```

---

# License

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files to deal in the Software
without restriction.

---

# Acknowledgements

- Python
- Flask
- Requests
- BeautifulSoup
- ReportLab
- Open-source cybersecurity community

---

# Star the Repository

If you found this project useful, consider starring the repository.
