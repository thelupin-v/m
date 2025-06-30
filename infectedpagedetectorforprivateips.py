import requests
import re
from urllib.parse import urljoin

# Known suspicious script signatures/URLs (expand as needed)
KNOWN_MALWARE_SIGNATURES = [
    r"hook\.js",  # BeEF hook typical script filename
    r"beef",      # generic beef references
    r"reptile",   # example for Reptile framework
    r"exploit",   # generic suspicious string
    r"eval\(",    # eval usage in inline scripts (potentially suspicious)
    r"document\.write",  # suspicious dynamic content injection
    r"iframe",    # drive-by download may use hidden iframes
    r"download",  # script triggering downloads
    r"base64,",   # large base64 inline code (obfuscation)
]

# Additional known suspicious domains or URLs (example)
KNOWN_MALWARE_DOMAINS = [
    "maliciousdomain.com",
    "badscript.example",
]

def scan_page_for_virus(url):
    try:
        print(f"[*] Fetching {url}")
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        html = resp.text.lower()

        # Check for known malware script includes
        malware_found = False
        found_signatures = []

        # Check script tags and inline scripts
        scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE)
        script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)

        # Check inline scripts for suspicious patterns
        for script_content in scripts:
            for pattern in KNOWN_MALWARE_SIGNATURES:
                if re.search(pattern, script_content):
                    malware_found = True
                    found_signatures.append(f"Inline script matched pattern: {pattern}")

        # Check external script src URLs for known malicious filenames or domains
        for src in script_srcs:
            full_src = urljoin(url, src)
            for pattern in KNOWN_MALWARE_SIGNATURES:
                if re.search(pattern, full_src):
                    malware_found = True
                    found_signatures.append(f"Script src matched pattern: {pattern} -> {full_src}")

            for domain in KNOWN_MALWARE_DOMAINS:
                if domain in full_src:
                    malware_found = True
                    found_signatures.append(f"Script src matched known bad domain: {full_src}")

        # Detect suspicious iframe usage
        iframes = re.findall(r'<iframe[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
        for iframe_src in iframes:
            full_iframe_src = urljoin(url, iframe_src)
            for pattern in KNOWN_MALWARE_SIGNATURES:
                if re.search(pattern, full_iframe_src):
                    malware_found = True
                    found_signatures.append(f"Iframe src matched pattern: {pattern} -> {full_iframe_src}")

        # Detect suspicious inline event handlers or code (very naive)
        if re.search(r'onload\s*=|onerror\s*=', html):
            found_signatures.append("Possible suspicious event handlers (onload/onerror) found")

        # Report
        if malware_found or found_signatures:
            print("[!] WARNING: Potential malware indicators detected on page!")
            for sig in found_signatures:
                print("  -", sig)
        else:
            print("[+] No obvious malware indicators found on the page.")

    except requests.RequestException as e:
        print(f"[ERROR] Failed to fetch page: {e}")

if __name__ == "__main__":
    test_url = input("Enter URL to scan: ").strip()
    scan_page_for_virus(test_url)
