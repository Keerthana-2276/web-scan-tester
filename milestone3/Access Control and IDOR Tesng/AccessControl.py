#!/usr/bin/env python3
"""
access_control_test.py

Week 6: Access Control & IDOR testing (conservative, authenticated).
- Login to a target app (DVWA defaults)
- Scan a single target page for links and forms containing ID-like params
- Try horizontal/vertical manipulations (numeric offsets, big IDs, string payloads)
- Record suspicious responses in access_findings.json

Configure constants below (base_host, target_page, credentials) before running.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
import json
import time
import re
import sys

# ---------------- CONFIG ----------------
base_host = "http://localhost:8080"
login_page = base_host + "/login.php"
target_page = base_host + "/vulnerabilities/weak_id/"   # change as needed
username = "admin"
password = "password"

# Candidate param names that often hold object IDs
ID_PARAM_CANDIDATES = ["id", "userid", "user", "uid", "docid", "resource_id", "post", "item", "file", "profile"]

# conservative test strategies
ID_OFFSETS = [-1, 1, 2]     # check neighbours (horizontal)
BIG_IDS = [999999, 1000000] # high IDs (vertical / out-of-range)
STRING_PAYLOADS = ["admin", "test", "1' OR '1'='1"]  # conservative string tests

DELAY = 0.2      # polite delay between requests
TIMEOUT = 8
OUTPUT_FILE = "access_findings.json"
# ----------------------------------------

session = requests.Session()
findings = []

# Patterns for "forbidden"/"unauthorized" messages (heuristic)
FORBID_RE = re.compile(r"403|401|access denied|not authorized|you do not have permission|login required", re.IGNORECASE)

def suggested_fixes():
    return {
        "enforce_server_side_authorization": "Always check authorization on the server before returning object data.",
        "use_non_guessable_ids": "Use UUIDs or hashids instead of sequential integers.",
        "implement_rbac_or_abac": "Use RBAC or ABAC to enforce who can perform what action on which objects.",
        "audit_and_rate_limit": "Log access and throttle suspicious enumeration patterns.",
        "least_privilege": "Apply least privilege to users and service accounts."
    }

# ---------- Helpers ----------
def get_login_tokens():
    """GET login page and return hidden inputs (CSRF-like tokens)"""
    try:
        r = session.get(login_page, timeout=TIMEOUT)
    except Exception as e:
        print("[!] Cannot fetch login page:", e)
        return {}
    soup = BeautifulSoup(r.text or "", "html.parser")
    hidden = {}
    form = soup.find("form")
    if not form:
        return {}
    for hid in form.find_all("input", {"type": "hidden"}):
        n = hid.get("name")
        if n:
            hidden[n] = hid.get("value", "")
    return hidden

def login():
    tokens = get_login_tokens()
    payload = {}
    payload.update(tokens)
    payload.update({"username": username, "password": password, "Login": "Login"})
    try:
        r = session.post(login_page, data=payload, timeout=TIMEOUT, allow_redirects=True)
    except Exception as e:
        print("[!] Login request failed:", e)
        return False
    # heuristic success check
    if r is not None and ("Logout" in r.text or "DVWA" in r.text or "logout.php" in r.text):
        print("[+] Login successful.")
        return True
    print("[-] Login may have failed.")
    return False

def parse_links_and_forms(html, base_url):
    """Return same-host links and form metadata for a page."""
    soup = BeautifulSoup(html, "html.parser")
    links = []
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.startswith("javascript:") or href.startswith("mailto:"):
            continue
        links.append(urljoin(base_url, href))
    forms = []
    for form in soup.find_all("form"):
        inputs = []
        for inp in form.find_all(['input','select','textarea']):
            inputs.append({"name": inp.get("name"), "type": inp.get("type"), "value": inp.get("value")})
        forms.append({"action": form.get("action"), "method": (form.get("method") or "get").lower(), "inputs": inputs})
    return links, forms

def likely_id_keys(qs):
    """Return keys in querystring that look like IDs."""
    found = []
    for k in qs.keys():
        if k.lower() in ID_PARAM_CANDIDATES or re.search(r"id|uid|user|post|item|file|profile|doc", k, re.IGNORECASE):
            found.append(k)
    return found

def is_forbidden(resp):
    """Heuristic whether response denotes forbidden/unauthorized."""
    if resp is None:
        return False
    if resp.status_code in (401, 403):
        return True
    text = resp.text or ""
    return bool(FORBID_RE.search(text))

# ---------- Testing strategies ----------
def test_url_for_idor(url):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if not qs:
        return []
    id_keys = likely_id_keys(qs)
    if not id_keys:
        return []

    local_findings = []
    try:
        base_resp = session.get(url, timeout=TIMEOUT)
        base_text = base_resp.text or ""
        base_code = base_resp.status_code if base_resp is not None else None
    except Exception:
        base_text = ""
        base_code = None

    private_hint = any(x in (base_text or "").lower() for x in ("your profile","your account","private","only you","logged in as"))

    for key in id_keys:
        original_value = qs.get(key,[None])[0]
        # numeric tests
        try:
            val_int = int(original_value)
            for off in ID_OFFSETS:
                new_val = val_int + off
                new_qs = {k:v[0] for k,v in qs.items()}
                new_qs[key] = str(new_val)
                new_url = parsed._replace(query=urlencode(new_qs)).geturl()
                time.sleep(DELAY)
                try:
                    resp = session.get(new_url, timeout=TIMEOUT)
                except Exception:
                    resp = None
                text = resp.text if resp is not None else ""
                code = resp.status_code if resp is not None else None
                rel_change = abs(len(text) - len(base_text)) / max(1, len(base_text))
                # heuristics for suspicious access
                if ((private_hint and code==200 and rel_change>0.1 and not is_forbidden(resp))
                    or (not private_hint and code==200 and rel_change>0.5)):
                    local_findings.append({
                        "type":"idor_numeric_offset",
                        "original_url": url,
                        "tested_url": new_url,
                        "param": key,
                        "original_value": original_value,
                        "tested_value": str(new_val),
                        "status_code": code,
                        "rel_change": rel_change,
                        "note":"Neighbor ID returned different content; possible horizontal access control issue."
                    })
            # big-id checks
            for big in BIG_IDS:
                new_qs = {k:v[0] for k,v in qs.items()}
                new_qs[key] = str(big)
                new_url = parsed._replace(query=urlencode(new_qs)).geturl()
                time.sleep(DELAY)
                try:
                    resp = session.get(new_url, timeout=TIMEOUT)
                except Exception:
                    resp = None
                if resp is not None and resp.status_code==200 and len((resp.text or ""))>50 and not is_forbidden(resp):
                    local_findings.append({
                        "type":"idor_big_id_accessible",
                        "original_url": url,
                        "tested_url": new_url,
                        "param": key,
                        "tested_value": str(big),
                        "status_code": resp.status_code,
                        "note":"Large ID returned content; possible weak validation."
                    })
        except (ValueError, TypeError):
            # string param tests
            for payload in STRING_PAYLOADS:
                new_qs = {k:v[0] for k,v in qs.items()}
                new_qs[key] = payload
                new_url = parsed._replace(query=urlencode(new_qs)).geturl()
                time.sleep(DELAY)
                try:
                    resp = session.get(new_url, timeout=TIMEOUT)
                except Exception:
                    resp = None
                text = resp.text if resp is not None else ""
                code = resp.status_code if resp is not None else None
                rel_change = abs(len(text) - len(base_text)) / max(1, len(base_text))
                if code==200 and rel_change>0.2 and not is_forbidden(resp):
                    local_findings.append({
                        "type":"idor_string_test",
                        "original_url": url,
                        "tested_url": new_url,
                        "param": key,
                        "original_value": original_value,
                        "tested_value": payload,
                        "status_code": code,
                        "rel_change": rel_change,
                        "note":"String substitution changed content; suspicious."
                    })
    return local_findings

def test_form_for_idor(page_url, form):
    action = form.get("action")
    method = form.get("method","get").lower()
    action_url = urljoin(page_url, action) if action else page_url
    baseline = {}
    for inp in form.get("inputs", []):
        n = inp.get("name")
        if not n:
            continue
        baseline[n] = inp.get("value") or "test"
    id_keys = [k for k in baseline.keys() if re.search(r"id|uid|user|post|item|file|profile|doc", k, re.IGNORECASE)]
    if not id_keys:
        return []

    local_findings = []
    try:
        if method=="post":
            base_resp = session.post(action_url, data=baseline, timeout=TIMEOUT)
        else:
            base_resp = session.get(action_url, params=baseline, timeout=TIMEOUT)
    except Exception:
        base_resp = None
    base_text = base_resp.text if base_resp is not None else ""
    for k in id_keys:
        v = baseline.get(k)
        try:
            vint = int(v)
            for off in ID_OFFSETS:
                test_data = dict(baseline)
                test_data[k] = str(vint+off)
                time.sleep(DELAY)
                try:
                    if method=="post":
                        resp = session.post(action_url, data=test_data, timeout=TIMEOUT)
                    else:
                        resp = session.get(action_url, params=test_data, timeout=TIMEOUT)
                except Exception:
                    resp = None
                text = resp.text if resp is not None else ""
                code = resp.status_code if resp is not None else None
                rel_change = abs(len(text) - len(base_text)) / max(1, len(base_text))
                if code==200 and rel_change>0.1 and not is_forbidden(resp):
                    local_findings.append({
                        "type":"idor_form_numeric_offset",
                        "action_url": action_url,
                        "param": k,
                        "original_value": v,
                        "tested_value": str(vint+off),
                        "status_code": code,
                        "rel_change": rel_change,
                        "note":"Form numeric ID offset returned different content."
                    })
        except (ValueError, TypeError):
            for payload in STRING_PAYLOADS:
                test_data = dict(baseline)
                test_data[k] = payload
                time.sleep(DELAY)
                try:
                    if method=="post":
                        resp = session.post(action_url, data=test_data, timeout=TIMEOUT)
                    else:
                        resp = session.get(action_url, params=test_data, timeout=TIMEOUT)
                except Exception:
                    resp = None
                text = resp.text if resp is not None else ""
                code = resp.status_code if resp is not None else None
                rel_change = abs(len(text) - len(base_text)) / max(1, len(base_text))
                if code==200 and rel_change>0.2 and not is_forbidden(resp):
                    local_findings.append({
                        "type":"idor_form_string_test",
                        "action_url": action_url,
                        "param": k,
                        "original_value": v,
                        "tested_value": payload,
                        "status_code": code,
                        "rel_change": rel_change,
                        "note":"Form string substitution changed content; suspicious."
                    })
    return local_findings

# ---------- Main ----------
def main():
    print("[*] Starting Access Control & IDOR testing")
    if not login():
        print("Exiting: login failed.")
        sys.exit(1)

    try:
        r = session.get(target_page, timeout=TIMEOUT)
    except Exception as e:
        print("[!] Cannot fetch target page:", e)
        sys.exit(1)
    html = r.text or ""
    links, forms = parse_links_and_forms(html, target_page)

    # keep only same-host links
    base_netloc = urlparse(base_host).netloc
    in_scope_links = [l for l in links if urlparse(l).netloc==base_netloc]

    # test links
    checked = set()
    for u in in_scope_links:
        if u in checked:
            continue
        checked.add(u)
        try:
            res = test_url_for_idor(u)
            if res:
                findings.extend(res)
        except Exception as e:
            print("Error testing URL:", u, e)
        time.sleep(DELAY)

    # test forms from target page
    for f in forms:
        try:
            res = test_form_for_idor(target_page, f)
            if res:
                findings.extend(res)
        except Exception as e:
            print("Error testing form:", e)
        time.sleep(DELAY)

    output = {
        "target_page": target_page,
        "scanned_links": in_scope_links,
        "forms_scanned": len(forms),
        "access_findings": findings,
        "suggested_fixes": suggested_fixes()
    }
    with open(OUTPUT_FILE, "w", encoding="utf-8") as fh:
        json.dump(output, fh, indent=2, ensure_ascii=False)

    print("[+] IDOR test complete. Findings:", len(findings))
    print("Results saved to", OUTPUT_FILE)

if __name__ == "__main__":
    main()
