"""
access_control_testing.py

Week 6: Access Control and IDOR Testing module.

- Logs in to a target web app (DVWA defaults).
- Scans a target page for URLs and forms containing likely object IDs (query param named 'id', 'user', 'uid', etc.).
- Performs conservative ID manipulations to test horizontal and vertical access control flaws.
- Records findings in access_findings.json and provides remediation suggestions.

CAUTION: Only run against systems you own or are authorized to test. This script is intentionally non-destructive and throttled.
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
target_page = base_host + "/vulnerabilities/weak_id/"   # example DVWA page with IDOR-like behavior
username = "admin"
password = "password"

# id-like parameter names to look for
ID_PARAM_CANDIDATES = ["id", "userid", "user", "uid", "document", "file", "post", "item", "profile", "account"]

# manipulation strategies (conservative)
ID_OFFSETS = [-1, 1, 2]        # horizontal checks (neighboring IDs)
BIG_IDS = [999999, 1000000]    # likely out-of-range
STRING_PAYLOADS = ["1' OR '1'='1", "admin", "testuser"]  # only used where param value is a string

DELAY = 0.2                    # polite delay between requests (seconds)
TIMEOUT = 8

OUTPUT_FILE = "access_findings.json"
# ----------------------------------------

session = requests.Session()
findings = []

# heuristics for "forbidden" / "unauthorized" strings (case-insensitive)
FORBIDDEN_SIGNS = [
    r"403 Forbidden", r"access denied", r"not authorized", r"not authenticated",
    r"you do not have permission", r"authorization required", r"login required"
]
FORBID_RE = re.compile("|".join([s.replace(" ", r"\s+") for s in FORBIDDEN_SIGNS]), re.IGNORECASE)

def suggested_fixes():
    return {
        "enforce_server_side_authorization": "Always enforce authorization on server-side before returning object data. Never rely only on unpredictable client checks.",
        "use_id_mapping_or_random_ids": "Use non-guessable object references (UUIDs, GUIDs, or hashids) or mapping tables rather than sequential numeric IDs.",
        "implement_rbac_or_abac": "Design and enforce Role-Based (RBAC) or Attribute-Based (ABAC) access control to ensure only permitted principals access objects.",
        "least_privilege": "Ensure users/app components have minimal privileges required.",
        "audit_logging": "Log access attempts and alert on unusual access patterns (many different IDs from same user).",
        "test_and_review": "Perform authorization tests as part of QA and security reviews; add automated tests for access control rules."
    }

# ---------------- Helpers ----------------

def parse_links_and_forms(html, url):
    """
    Return:
      - list of same-host links found on page (absolute URLs)
      - list of form metadata: {action, method, inputs: [{name, type, value}]}
    """
    soup = BeautifulSoup(html, "html.parser")
    links = []
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.startswith("javascript:") or href.startswith("mailto:"):
            continue
        links.append(urljoin(url, href))

    forms = []
    for form in soup.find_all("form"):
        inputs = []
        for i in form.find_all(['input','textarea','select']):
            inputs.append({"name": i.get("name"), "type": i.get("type"), "value": i.get("value")})
        forms.append({"action": form.get("action"), "method": (form.get("method") or "get").lower(), "inputs": inputs})
    return links, forms

def likely_id_params(qs):
    """Return only keys that look like id/object identifiers."""
    ids = []
    for k in qs.keys():
        if k.lower() in ID_PARAM_CANDIDATES or re.search(r"id|uid|user|post|item|file|doc|account|profile", k, re.IGNORECASE):
            ids.append(k)
    return ids

def normalize_netloc(n):
    return n.replace("127.0.0.1", "localhost").lower() if n else ""

def is_forbidden(text, status_code):
    """Heuristic whether response indicates forbidden/denied."""
    if status_code in (401, 403):
        return True
    if text and FORBID_RE.search(text):
        return True
    return False

# ---------------- Login ----------------

def do_login():
    """Login using simple token extraction (DVWA-style)."""
    try:
        r = session.get(login_page, timeout=TIMEOUT)
    except Exception as e:
        print("[!] Cannot reach login page:", e)
        return False
    soup = BeautifulSoup(r.text or "", "html.parser")
    hidden = {}
    form = soup.find("form")
    if form:
        for hid in form.find_all("input", {"type":"hidden"}):
            name = hid.get("name")
            if name:
                hidden[name] = hid.get("value", "")
    payload = {}
    payload.update(hidden)
    payload["username"] = username
    payload["password"] = password
    payload.setdefault("Login", "Login")
    try:
        r2 = session.post(login_page, data=payload, timeout=TIMEOUT, allow_redirects=True)
        if r2 is not None and ("Logout" in r2.text or "DVWA" in r2.text):
            print("[+] Login successful.")
            return True
        else:
            print("[-] Login may have failed.")
            return False
    except Exception as e:
        print("[!] Login error:", e)
        return False

# ---------------- Testing strategies ----------------

def test_url_for_idor(original_url):
    """
    Given a URL, detect id-like query params and attempt manipulations.
    Record any case where manipulating the id returns data while original indicates user-specific content.
    """
    parsed = urlparse(original_url)
    qs = parse_qs(parsed.query)
    if not qs:
        return []
    id_keys = likely_id_params(qs)
    local_findings = []
    if not id_keys:
        return []

    # build baseline response
    try:
        base_resp = session.get(original_url, timeout=TIMEOUT)
        base_text = base_resp.text if base_resp is not None else ""
        base_code = base_resp.status_code if base_resp is not None else None
    except Exception:
        base_text = ""
        base_code = None

    # If baseline shows "your account" or private indicator, we should test manipulation
    private_indicators = ["your profile", "your account", "private", "only you", "logged in as"]
    private_flag = any(x in (base_text or "").lower() for x in private_indicators)

    for key in id_keys:
        original_value = qs.get(key, [""])[0]
        # only attempt numeric offsets when numeric
        try:
            val_int = int(original_value)
            # offset tests (neighbor IDs)
            for off in ID_OFFSETS:
                new_val = val_int + off
                new_qs = dict((k, v[0]) for k, v in qs.items())
                new_qs[key] = str(new_val)
                new_query = urlencode(new_qs)
                new_url = parsed._replace(query=new_query).geturl()
                time.sleep(DELAY)
                try:
                    resp = session.get(new_url, timeout=TIMEOUT)
                    text = resp.text if resp is not None else ""
                    code = resp.status_code if resp is not None else None
                except Exception:
                    text = ""
                    code = None

                # If we can access a resource that is different than baseline (e.g., shows another user's data),
                # or the baseline was private but this returned 200 and content changed, flag possible IDOR.
                rel_change = 0.0
                try:
                    rel_change = abs(len(text or "") - len(base_text or "")) / max(1, len(base_text or ""))
                except Exception:
                    rel_change = 0.0

                # condition heuristics
                if (private_flag and code == 200 and rel_change > 0.1 and not is_forbidden(text, code)) or (not private_flag and code == 200 and rel_change > 0.5):
                    local_findings.append({
                        "type": "idor_numeric_offset",
                        "original_url": original_url,
                        "tested_url": new_url,
                        "param": key,
                        "original_value": original_value,
                        "tested_value": str(new_val),
                        "status_code": code,
                        "rel_length_change": rel_change,
                        "notes": "Neighbor ID returned different content; possible horizontal access control issue."
                    })

            # big ID tests
            for big in BIG_IDS:
                new_qs = dict((k, v[0]) for k, v in qs.items())
                new_qs[key] = str(big)
                new_query = urlencode(new_qs)
                new_url = parsed._replace(query=new_query).geturl()
                time.sleep(DELAY)
                try:
                    resp = session.get(new_url, timeout=TIMEOUT)
                    text = resp.text if resp is not None else ""
                    code = resp.status_code if resp is not None else None
                except Exception:
                    text = ""
                    code = None

                if code == 200 and not is_forbidden(text, code) and len(text or "") > 50:
                    local_findings.append({
                        "type": "idor_big_id_accessible",
                        "original_url": original_url,
                        "tested_url": new_url,
                        "param": key,
                        "tested_value": str(big),
                        "status_code": code,
                        "notes": "Very large ID returned content. Resource enumeration or poor validation possible."
                    })

        except ValueError:
            # original value not numeric — try string payloads (be conservative)
            for payload in STRING_PAYLOADS:
                new_qs = dict((k, v[0]) for k, v in qs.items())
                new_qs[key] = payload
                new_query = urlencode(new_qs)
                new_url = parsed._replace(query=new_query).geturl()
                time.sleep(DELAY)
                try:
                    resp = session.get(new_url, timeout=TIMEOUT)
                    text = resp.text if resp is not None else ""
                    code = resp.status_code if resp is not None else None
                except Exception:
                    text = ""
                    code = None

                # If swapping in another username or tautology-like payload returns 200 with different content -> suspicious
                rel_change = abs(len(text or "") - len(base_text or "")) / max(1, len(base_text or ""))
                if code == 200 and rel_change > 0.2 and not is_forbidden(text, code):
                    local_findings.append({
                        "type": "idor_string_test",
                        "original_url": original_url,
                        "tested_url": new_url,
                        "param": key,
                        "original_value": original_value,
                        "tested_value": payload,
                        "status_code": code,
                        "rel_length_change": rel_change,
                        "notes": "String substitution changed content — possible IDOR or injection vector."
                    })

    return local_findings

def test_form_for_idor(page_url, form):
    """
    For a given form metadata (action/method/inputs), find id-like inputs and attempt edits.
    We submit with payloads but do not try to create or delete resources.
    """
    local_findings = []
    action = form.get("action")
    method = (form.get("method") or "get").lower()
    action_url = urljoin(page_url, action) if action else page_url

    # baseline form data -> copy actual default values where available
    baseline = {}
    for inp in form.get("inputs", []):
        n = inp.get("name")
        if not n:
            continue
        baseline[n] = inp.get("value") or "test"

    id_keys = [k for k in baseline.keys() if re.search(r"id|uid|user|post|item|file|doc|account|profile", k, re.IGNORECASE)]
    if not id_keys:
        return []

    # get baseline response
    try:
        if method == "post":
            base_resp = session.post(action_url, data=baseline, timeout=TIMEOUT)
        else:
            base_resp = session.get(action_url, params=baseline, timeout=TIMEOUT)
        base_text = base_resp.text if base_resp is not None else ""
        base_code = base_resp.status_code if base_resp is not None else None
    except Exception:
        base_text = ""
        base_code = None

    for k in id_keys:
        v = baseline.get(k, "")
        try:
            vint = int(v)
            for off in ID_OFFSETS:
                test_data = dict(baseline)
                test_data[k] = str(vint + off)
                time.sleep(DELAY)
                try:
                    if method == "post":
                        resp = session.post(action_url, data=test_data, timeout=TIMEOUT)
                    else:
                        resp = session.get(action_url, params=test_data, timeout=TIMEOUT)
                    text = resp.text if resp is not None else ""
                    code = resp.status_code if resp is not None else None
                except Exception:
                    text = ""
                    code = None
                rel_change = abs(len(text or "") - len(base_text or "")) / max(1, len(base_text or ""))
                if code == 200 and rel_change > 0.1 and not is_forbidden(text, code):
                    local_findings.append({
                        "type": "idor_form_numeric_offset",
                        "action_url": action_url,
                        "param": k,
                        "original_value": v,
                        "tested_value": str(vint + off),
                        "status_code": code,
                        "rel_length_change": rel_change,
                        "notes": "Form numeric ID offset returned different content."
                    })
        except ValueError:
            for payload in STRING_PAYLOADS:
                test_data = dict(baseline)
                test_data[k] = payload
                time.sleep(DELAY)
                try:
                    if method == "post":
                        resp = session.post(action_url, data=test_data, timeout=TIMEOUT)
                    else:
                        resp = session.get(action_url, params=test_data, timeout=TIMEOUT)
                    text = resp.text if resp is not None else ""
                    code = resp.status_code if resp is not None else None
                except Exception:
                    text = ""
                    code = None
                rel_change = abs(len(text or "") - len(base_text or "")) / max(1, len(base_text or ""))
                if code == 200 and rel_change > 0.2 and not is_forbidden(text, code):
                    local_findings.append({
                        "type": "idor_form_string_test",
                        "action_url": action_url,
                        "param": k,
                        "original_value": v,
                        "tested_value": payload,
                        "status_code": code,
                        "rel_length_change": rel_change,
                        "notes": "Form string substitution changed content; possible IDOR or poor validation."
                    })

    return local_findings

# ---------------- Main flow ----------------

def main():
    print("[*] Starting Access Control and IDOR testing")
    if not do_login():
        print("Exiting due to login failure.")
        sys.exit(1)

    # fetch target page
    try:
        r = session.get(target_page, timeout=TIMEOUT)
    except Exception as e:
        print("[!] Cannot fetch target page:", e)
        sys.exit(1)
    html = r.text if r is not None else ""
    links, forms = parse_links_and_forms(html, target_page)

    # limit scope to same-host links
    parsed_base = urlparse(base_host)
    base_netloc = normalize_netloc(parsed_base.netloc)
    in_scope_links = []
    for link in links:
        p = urlparse(link)
        if normalize_netloc(p.netloc) == base_netloc:
            in_scope_links.append(link)

    # test links for idor
    checked_urls = set()
    for url in in_scope_links:
        if url in checked_urls:
            continue
        checked_urls.add(url)
        try:
            res = test_url_for_idor(url)
            if res:
                findings.extend(res)
        except Exception as e:
            print("Error testing URL:", url, e)
        time.sleep(DELAY)

    # test forms found on the original page
    for f in forms:
        try:
            res = test_form_for_idor(target_page, f)
            if res:
                findings.extend(res)
        except Exception as e:
            print("Error testing form:", e)
        time.sleep(DELAY)

    # Save findings
    output = {
        "target_page": target_page,
        "scanned_links": list(in_scope_links),
        "forms_scanned": len(forms),
        "access_findings": findings,
        "suggested_fixes": suggested_fixes()
    }
    with open(OUTPUT_FILE, "w", encoding="utf-8") as fh:
        json.dump(output, fh, indent=2, ensure_ascii=False)

    print("[+] IDOR test complete.")
    print(f"Links scanned: {len(in_scope_links)}, Forms scanned: {len(forms)}, Findings: {len(findings)}")
    print(f"Results saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
