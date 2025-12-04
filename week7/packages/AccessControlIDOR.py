"""
AccessControlIDOR.py
Package-ready IDOR (Insecure Direct Object Reference) scanner.

This module:
 - Logs into DVWA
 - Attempts horizontal/vertical privilege escalation via ID parameters
 - Tests URLs and forms for IDOR vulnerabilities
 - Outputs idor_findings.json
 - Can be imported safely into main.py using:  from packages.AccessControlIDOR import run
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import json
import time
import re
import copy

# ---------------- CONFIG ----------------
BASE_HOST = "http://localhost:8080"
LOGIN_URL = BASE_HOST + "/login.php"
TARGET_PAGE = BASE_HOST + "/vulnerabilities/weak_id/"

USERNAME = "admin"
PASSWORD = "password"

ID_PARAM_CANDIDATES = ["id", "uid", "user", "userid", "item", "post", "file", "profile"]
ID_OFFSETS = [-1, 1, 2]
BIG_IDS = [999999, 1000000]
STRING_PAYLOADS = ["admin", "guest", "test123"]

TIMEOUT = 8
DELAY = 0.15

OUTPUT_FILE = "idor_findings.json"
# ----------------------------------------

session = requests.Session()
idor_findings = []

FORBID_RE = re.compile(
    r"(403|401|access denied|not authorized|forbidden|permission|login required)",
    re.IGNORECASE
)

# ================== LOGIN ==================
def get_login_tokens():
    try:
        r = session.get(LOGIN_URL, timeout=TIMEOUT)
    except Exception:
        return {}

    soup = BeautifulSoup(r.text or "", "html.parser")
    form = soup.find("form")
    if not form:
        return {}

    tokens = {}
    for tag in form.find_all("input", {"type": "hidden"}):
        if tag.get("name"):
            tokens[tag["name"]] = tag.get("value", "")

    return tokens


def login():
    tokens = get_login_tokens()
    payload = {**tokens, "username": USERNAME, "password": PASSWORD, "Login": "Login"}

    try:
        r = session.post(LOGIN_URL, data=payload, timeout=TIMEOUT, allow_redirects=True)
    except:
        return False

    return ("Logout" in r.text or "DVWA" in r.text)


# ================== HELPERS ==================
def parse_forms_and_links(html, base_url):
    soup = BeautifulSoup(html, "html.parser")

    links = [
        urljoin(base_url, a["href"])
        for a in soup.find_all("a", href=True)
        if not a["href"].startswith(("javascript:", "mailto:"))
    ]

    forms = []
    for f in soup.find_all("form"):
        inputs = []
        for i in f.find_all(["input", "select", "textarea"]):
            inputs.append({
                "name": i.get("name"),
                "value": i.get("value", ""),
                "type": i.get("type", "text")
            })

        forms.append({
            "method": (f.get("method") or "get").lower(),
            "action": f.get("action"),
            "inputs": inputs
        })

    return links, forms


def extract_id_keys(query_params):
    return [
        k for k in query_params.keys()
        if k.lower() in ID_PARAM_CANDIDATES or "id" in k.lower()
    ]


def forbidden(resp):
    if resp is None:
        return False
    return resp.status_code in (401, 403) or bool(FORBID_RE.search(resp.text or ""))


# ================== IDOR TESTS ==================

def test_url_for_idor(url):
    """
    Tests IDOR by modifying query parameters of a URL.
    """
    results = []

    parsed = urlparse(url)
    qs = parse_qs(parsed.query)

    if not qs:
        return []

    id_keys = extract_id_keys(qs)
    if not id_keys:
        return []

    try:
        baseline = session.get(url, timeout=TIMEOUT)
        baseline_text = baseline.text or ""
    except:
        baseline_text = ""

    # Loop through ID parameters
    for param in id_keys:

        # Numeric attacks first
        for off in ID_OFFSETS:
            try:
                new_value = str(int(qs[param][0]) + off)
            except:
                continue

            new_qs = copy.deepcopy(qs)
            new_qs[param] = [new_value]

            new_url = parsed._replace(query=urlencode({k: v[0] for k, v in new_qs.items()})).geturl()

            try:
                r = session.get(new_url, timeout=TIMEOUT)
                text = r.text or ""
            except:
                continue

            if text != baseline_text and not forbidden(r):
                results.append({
                    "test": "IDOR_URL",
                    "url": new_url,
                    "param": param,
                    "value_used": new_value,
                    "vulnerable": True
                })

            time.sleep(DELAY)

        # Big numeric IDs
        for big in BIG_IDS:
            new_qs = copy.deepcopy(qs)
            new_qs[param] = [str(big)]
            new_url = parsed._replace(query=urlencode({k: v[0] for k, v in new_qs.items()})).geturl()

            try:
                r = session.get(new_url, timeout=TIMEOUT)
                text = r.text or ""
            except:
                continue

            if text != baseline_text and not forbidden(r):
                results.append({
                    "test": "IDOR_URL_BIG_ID",
                    "url": new_url,
                    "param": param,
                    "value_used": big,
                    "vulnerable": True
                })

            time.sleep(DELAY)

        # Strings
        for s in STRING_PAYLOADS:
            new_qs = copy.deepcopy(qs)
            new_qs[param] = [s]
            new_url = parsed._replace(query=urlencode({k: v[0] for k, v in new_qs.items()})).geturl()

            try:
                r = session.get(new_url, timeout=TIMEOUT)
                text = r.text or ""
            except:
                continue

            if text != baseline_text and not forbidden(r):
                results.append({
                    "test": "IDOR_URL_STRING",
                    "url": new_url,
                    "param": param,
                    "value_used": s,
                    "vulnerable": True
                })

            time.sleep(DELAY)

    return results


def test_form_for_idor(page_url, form):
    """
    Attempts IDOR by modifying form fields that look like IDs.
    """
    results = []

    action_url = urljoin(page_url, form.get("action"))
    method = form.get("method", "get")

    base_payload = {
        i["name"]: i.get("value", "1")
        for i in form["inputs"]
        if i.get("name")
    }

    try:
        baseline = session.post(action_url, data=base_payload) if method == "post" else session.get(action_url, params=base_payload)
        baseline_text = baseline.text or ""
    except:
        baseline_text = ""

    id_keys = [
        k for k in base_payload.keys()
        if k.lower() in ID_PARAM_CANDIDATES or "id" in k.lower()
    ]

    for key in id_keys:
        for off in ID_OFFSETS:
            try:
                new_val = str(int(base_payload[key]) + off)
            except:
                continue

            mutated = base_payload.copy()
            mutated[key] = new_val

            try:
                r = session.post(action_url, data=mutated) if method == "post" else session.get(action_url, params=mutated)
                text = r.text or ""
            except:
                continue

            if text != baseline_text and not forbidden(r):
                results.append({
                    "test": "IDOR_FORM",
                    "url": action_url,
                    "param": key,
                    "value_used": new_val,
                    "vulnerable": True
                })

            time.sleep(DELAY)

    return results


# ================== MAIN RUN FUNCTION ==================
def run():
    print("[*] Running IDOR scanner...")

    if not login():
        print("[-] Login failed for IDOR scanner.")
        return None

    try:
        r = session.get(TARGET_PAGE, timeout=TIMEOUT)
    except Exception:
        print("[-] Cannot load target IDOR page.")
        return None

    html = r.text or ""
    links, forms = parse_forms_and_links(html, TARGET_PAGE)

    base_host = urlparse(BASE_HOST).netloc
    valid_links = [l for l in links if urlparse(l).netloc == base_host]

    # test URLs
    for l in valid_links:
        try:
            res = test_url_for_idor(l)
            if res:
                idor_findings.extend(res)
        except:
            pass

        time.sleep(DELAY)

    # test forms
    for f in forms:
        try:
            res = test_form_for_idor(TARGET_PAGE, f)
            if res:
                idor_findings.extend(res)
        except:
            pass

        time.sleep(DELAY)

    # save file
    out = {
    "target_page": TARGET_PAGE,
    "links_scanned": valid_links,
    "forms_scanned": len(forms),
    "findings": idor_findings       # IMPORTANT FIX
}


    with open(OUTPUT_FILE, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, ensure_ascii=False)

    print("[+] IDOR scan finished. Output:", OUTPUT_FILE)
    return OUTPUT_FILE


# Standalone execution
if __name__ == "__main__":
    run()
