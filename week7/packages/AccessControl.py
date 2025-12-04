"""
Access Control & IDOR Testing Module (Package Version)

This module:
- Logs into DVWA
- Scans a target page for IDOR parameters in links & forms
- Performs conservative ID manipulations
- Generates access_findings.json
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
target_page = base_host + "/vulnerabilities/weak_id/"
username = "admin"
password = "password"

ID_PARAM_CANDIDATES = ["id", "userid", "user", "uid", "document", "file", "post", "item", "profile", "account"]

ID_OFFSETS = [-1, 1, 2]
BIG_IDS = [999999, 1000000]
STRING_PAYLOADS = ["1' OR '1'='1", "admin", "testuser"]

DELAY = 0.2
TIMEOUT = 8

OUTPUT_FILE = "access_findings.json"
# ----------------------------------------

session = requests.Session()
findings = []

FORBIDDEN_SIGNS = [
    r"403 Forbidden", r"access denied", r"not authorized", r"not authenticated",
    r"you do not have permission", r"authorization required", r"login required"
]
FORBID_RE = re.compile("|".join([s.replace(" ", r"\s+") for s in FORBIDDEN_SIGNS]), re.IGNORECASE)


def suggested_fixes():
    return {
        "enforce_server_side_authorization": "Always enforce authorization on server-side before returning object data.",
        "use_id_mapping_or_random_ids": "Use UUIDs, GUIDs, or hashids instead of sequential IDs.",
        "implement_rbac_or_abac": "Use RBAC/ABAC to restrict access to user roles.",
        "least_privilege": "Restrict privileges to only what is necessary.",
        "audit_logging": "Log access attempts and detect unusual patterns.",
        "test_and_review": "Include authorization tests in QA and CI automation."
    }


# ---------------- Helpers ----------------

def parse_links_and_forms(html, url):
    soup = BeautifulSoup(html, "html.parser")
    links = []
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href.startswith("javascript:") and not href.startswith("mailto:"):
            links.append(urljoin(url, href))

    forms = []
    for form in soup.find_all("form"):
        inputs = []
        for i in form.find_all(['input', 'textarea', 'select']):
            inputs.append({"name": i.get("name"), "type": i.get("type"), "value": i.get("value")})
        forms.append({"action": form.get("action"), "method": (form.get("method") or "get").lower(), "inputs": inputs})

    return links, forms


def likely_id_params(qs):
    ids = []
    for k in qs.keys():
        if k.lower() in ID_PARAM_CANDIDATES or re.search(r"id|uid|user|post|item|file|doc|account|profile", k, re.IGNORECASE):
            ids.append(k)
    return ids


def normalize_netloc(n):
    return n.replace("127.0.0.1", "localhost").lower() if n else ""


def is_forbidden(text, status_code):
    if status_code in (401, 403):
        return True
    return bool(text and FORBID_RE.search(text))


# ---------------- Login Function ----------------

def do_login():
    try:
        r = session.get(login_page, timeout=TIMEOUT)
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

    payload = hidden.copy()
    payload["username"] = username
    payload["password"] = password
    payload.setdefault("Login", "Login")

    try:
        r2 = session.post(login_page, data=payload, timeout=TIMEOUT, allow_redirects=True)
        if r2 is not None and ("Logout" in r2.text or "DVWA" in r2.text):
            print("[+] Login successful.")
            return True
        print("[-] Login may have failed.")
        return False
    except Exception as e:
        print("[!] Login error:", e)
        return False


# ---------------- IDOR Testing ----------------

def test_url_for_idor(original_url):
    parsed = urlparse(original_url)
    qs = parse_qs(parsed.query)
    if not qs:
        return []

    id_keys = likely_id_params(qs)
    if not id_keys:
        return []

    local_findings = []

    # baseline response
    try:
        base_resp = session.get(original_url, timeout=TIMEOUT)
        base_text = base_resp.text if base_resp else ""
        base_code = base_resp.status_code if base_resp else None
    except Exception:
        base_text = ""
        base_code = None

    private_indicators = ["your profile", "your account", "private", "only you", "logged in as"]
    private_flag = any(x in base_text.lower() for x in private_indicators)

    for key in id_keys:
        original_value = qs.get(key, [""])[0]

        # Numeric Case
        try:
            v_int = int(original_value)

            # Test neighbor IDs
            for off in ID_OFFSETS:
                new_qs = {k: v[0] for k, v in qs.items()}
                new_qs[key] = str(v_int + off)
                new_url = parsed._replace(query=urlencode(new_qs)).geturl()

                time.sleep(DELAY)
                try:
                    resp = session.get(new_url, timeout=TIMEOUT)
                    text = resp.text if resp else ""
                    code = resp.status_code if resp else None
                except Exception:
                    continue

                rel_change = abs(len(text) - len(base_text)) / max(1, len(base_text))

                if (private_flag and code == 200 and rel_change > 0.1) or (not private_flag and rel_change > 0.5):
                    local_findings.append({
                        "type": "idor_numeric_offset",
                        "original_url": original_url,
                        "tested_url": new_url,
                        "param": key,
                        "tested_value": str(v_int + off),
                        "status_code": code,
                        "rel_length_change": rel_change
                    })

            # Test big numbers
            for big in BIG_IDS:
                new_qs = {k: v[0] for k, v in qs.items()}
                new_qs[key] = str(big)
                new_url = parsed._replace(query=urlencode(new_qs)).geturl()

                time.sleep(DELAY)
                try:
                    resp = session.get(new_url, timeout=TIMEOUT)
                    text = resp.text if resp else ""
                    code = resp.status_code if resp else None
                except Exception:
                    continue

                if code == 200 and len(text) > 50:
                    local_findings.append({
                        "type": "idor_big_id_accessible",
                        "tested_url": new_url,
                        "param": key,
                        "tested_value": str(big),
                        "status_code": code
                    })

        except ValueError:
            # String payloads
            for payload in STRING_PAYLOADS:
                new_qs = {k: v[0] for k, v in qs.items()}
                new_qs[key] = payload
                new_url = parsed._replace(query=urlencode(new_qs)).geturl()

                time.sleep(DELAY)
                try:
                    resp = session.get(new_url, timeout=TIMEOUT)
                    text = resp.text if resp else ""
                    code = resp.status_code if resp else None
                except Exception:
                    continue

                rel_change = abs(len(text) - len(base_text)) / max(1, len(base_text))

                if code == 200 and rel_change > 0.2:
                    local_findings.append({
                        "type": "idor_string_test",
                        "tested_url": new_url,
                        "param": key,
                        "tested_value": payload,
                        "status_code": code
                    })

    return local_findings


# ---------------- Form Testing ----------------

def test_form_for_idor(page_url, form):
    local_findings = []

    action = form.get("action")
    method = form.get("method")
    action_url = urljoin(page_url, action) if action else page_url

    baseline = {inp["name"]: inp.get("value") or "test" for inp in form.get("inputs", []) if inp.get("name")}

    id_keys = [k for k in baseline if re.search(r"id|uid|user|post|item|file|doc|account|profile", k, re.IGNORECASE)]
    if not id_keys:
        return []

    # baseline response
    try:
        if method == "post":
            base_resp = session.post(action_url, data=baseline, timeout=TIMEOUT)
        else:
            base_resp = session.get(action_url, params=baseline, timeout=TIMEOUT)
        base_text = base_resp.text if base_resp else ""
    except Exception:
        base_text = ""

    for key in id_keys:
        v = baseline[key]

        # Numeric case
        try:
            v_int = int(v)

            for off in ID_OFFSETS:
                test_data = baseline.copy()
                test_data[key] = str(v_int + off)

                time.sleep(DELAY)
                try:
                    if method == "post":
                        resp = session.post(action_url, data=test_data, timeout=TIMEOUT)
                    else:
                        resp = session.get(action_url, params=test_data, timeout=TIMEOUT)
                except Exception:
                    continue

                text = resp.text if resp else ""
                rel_change = abs(len(text) - len(base_text)) / max(1, len(base_text))

                if rel_change > 0.1:
                    local_findings.append({
                        "type": "idor_form_numeric_offset",
                        "action_url": action_url,
                        "param": key,
                        "tested_value": str(v_int + off),
                    })

        except ValueError:
            # String case
            for payload in STRING_PAYLOADS:
                test_data = baseline.copy()
                test_data[key] = payload

                time.sleep(DELAY)
                try:
                    if method == "post":
                        resp = session.post(action_url, data=test_data, timeout=TIMEOUT)
                    else:
                        resp = session.get(action_url, params=test_data, timeout=TIMEOUT)
                except Exception:
                    continue

                text = resp.text if resp else ""
                rel_change = abs(len(text) - len(base_text)) / max(1, len(base_text))

                if rel_change > 0.2:
                    local_findings.append({
                        "type": "idor_form_string_test",
                        "action_url": action_url,
                        "param": key,
                        "tested_value": payload
                    })

    return local_findings


# ---------------- Main RUN function (for package) ----------------

def run():
    print("[*] Starting Access Control & IDOR Testing...")

    if not do_login():
        print("[!] Login failed.")
        return

    try:
        r = session.get(target_page, timeout=TIMEOUT)
    except Exception as e:
        print("[!] Cannot fetch target page:", e)
        return

    html = r.text if r else ""
    links, forms = parse_links_and_forms(html, target_page)

    seed_urls = [
    f"{target_page}?id=1",
    f"{target_page}?id=2",
    f"{target_page}?id=3",
    f"{target_page}?id=4",
]

    links.extend(seed_urls)

    parsed_base = urlparse(base_host)
    base_netloc = normalize_netloc(parsed_base.netloc)

    in_scope = [
        link for link in links
        if normalize_netloc(urlparse(link).netloc) == base_netloc
    ]

    checked = set()
    for url in in_scope:
        if url not in checked:
            checked.add(url)
            result = test_url_for_idor(url)
            if result:
                findings.extend(result)
        time.sleep(DELAY)

    for f in forms:
        result = test_form_for_idor(target_page, f)
        if result:
            findings.extend(result)
        time.sleep(DELAY)

    
    # Convert raw findings to report-compatible format
    final_findings = []

    for f in findings:
        final_findings.append({
            "test": "Access Control / IDOR",
            "url": f.get("tested_url") or f.get("original_url"),
            "param": f.get("param"),
            "details": f,
            "vulnerable": True  # mark as success to show HIGH severity
        })

    output = {
        "findings": final_findings,
        "suggested_fixes": suggested_fixes()
    }

    
    # output = {
    #     "target_page": target_page,
    #     "scanned_links": in_scope,
    #     "forms_scanned": len(forms),
    #     "access_findings": findings,
    #     "suggested_fixes": suggested_fixes()
    # }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as fh:
        json.dump(output, fh, indent=2, ensure_ascii=False)

    print(f"[+] Test Complete → {OUTPUT_FILE} generated.")
