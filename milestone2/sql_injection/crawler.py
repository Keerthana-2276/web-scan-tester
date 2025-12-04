"""
crawler_sqli_only.py

Logs in to DVWA and runs non-destructive SQL-injection heuristics
against the vulnerabilities/sqli page (and any same-host links found
starting from that page).

Outputs:
  - metadata.json
  - sql_findings.json
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import json
import copy
import re
import sys
import time

# -------- CONFIG --------
base_host = "http://localhost:8080"
login_page = base_host + "/login.php"
target_start = base_host + "/vulnerabilities/sqli/"   # page you requested
username = "admin"
password = "password"
# ------------------------

visited = set()
metadata_list = []
sql_findings = []

# Non-destructive SQL payloads (common tests)
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

# Helpers
def form_action_url(base, action):
    if not action:
        return base
    return urljoin(base, action)

def suggested_fixes():
    return {
        "parameterized_queries": "Use prepared statements / parameterized queries. Do not concatenate user input into SQL.",
        "input_validation": "Validate and sanitize inputs by type and length. Use allow-lists where possible.",
        "least_privilege": "Ensure the DB account used by the app has only necessary privileges.",
        "error_handling": "Do not display raw SQL errors to users; log them server-side instead.",
        "use_orm_or_safe_api": "Consider using an ORM or database API that defaults to parameterized queries."
    }

def compare_responses(baseline_text, test_text):
    baseline_len = len(baseline_text or "")
    test_len = len(test_text or "")
    if baseline_len == 0:
        rel_change = 1.0 if test_len > 0 else 0.0
    else:
        rel_change = abs(test_len - baseline_len) / baseline_len

    reflected = False
    for p in SQL_PAYLOADS:
        snippet = p.strip()[:8]
        if snippet and snippet in (test_text or ""):
            reflected = True
            break

    error_found = bool(SQL_ERROR_RE.search(test_text or ""))
    return {"rel_change": rel_change, "reflected": reflected, "error_found": error_found}

# Testing functions
def test_form(session, base_url, form):
    findings = []
    action = form.get("action")
    method = (form.get("method") or "get").lower()
    action_url = form_action_url(base_url, action)
    inputs = form.get("inputs", [])

    baseline_data = {}
    for inp in inputs:
        name = inp.get("name")
        if not name:
            continue
        baseline_data[name] = "test"

    try:
        if method == "post":
            baseline_resp = session.post(action_url, data=baseline_data, timeout=8, allow_redirects=True)
        else:
            baseline_resp = session.get(action_url, params=baseline_data, timeout=8, allow_redirects=True)
        baseline_text = baseline_resp.text if baseline_resp is not None else ""
    except Exception:
        baseline_text = ""

    for payload in SQL_PAYLOADS:
        for target_field in list(baseline_data.keys()) + ["ALL_FIELDS"]:
            test_data = baseline_data.copy()
            if target_field == "ALL_FIELDS":
                for k in test_data.keys():
                    test_data[k] = payload
            else:
                if target_field in test_data:
                    test_data[target_field] = payload
                else:
                    continue

            try:
                if method == "post":
                    resp = session.post(action_url, data=test_data, timeout=8, allow_redirects=True)
                else:
                    resp = session.get(action_url, params=test_data, timeout=8, allow_redirects=True)
                test_text = resp.text if resp is not None else ""
            except Exception:
                test_text = ""
                resp = None

            comp = compare_responses(baseline_text, test_text)
            if comp["error_found"] or comp["reflected"] or comp["rel_change"] > 0.25:
                findings.append({
                    "action_url": action_url,
                    "method": method,
                    "injected_field": target_field,
                    "payload": payload,
                    "error_found": comp["error_found"],
                    "reflected": comp["reflected"],
                    "rel_length_change": comp["rel_change"],
                    "status_code": resp.status_code if resp is not None else None
                })

    return findings

def test_url_params(session, url):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if not qs:
        return []
    findings = []
    try:
        baseline_resp = session.get(url, timeout=8, allow_redirects=True)
        baseline_text = baseline_resp.text if baseline_resp is not None else ""
    except Exception:
        baseline_text = ""

    for param in qs.keys():
        for payload in SQL_PAYLOADS:
            test_qs = copy.deepcopy(qs)
            test_qs[param] = [payload]
            new_query = urlencode({k: v[0] for k, v in test_qs.items()})
            new_url = parsed._replace(query=new_query).geturl()
            try:
                resp = session.get(new_url, timeout=8, allow_redirects=True)
                test_text = resp.text if resp is not None else ""
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
                    "status_code": resp.status_code if resp is not None else None
                })
    return findings

def _normalize_netloc(netloc):
    if not netloc:
        return ""
    return netloc.replace("127.0.0.1", "localhost").lower()

# Crawl logic limited to same-host starting from target_start
def crawl(session, url, base_netloc):
    if url in visited:
        return
    visited.add(url)
    print("Crawling:", url)
    try:
        r = session.get(url, timeout=8)
        html = r.text if r is not None else ""
        soup = BeautifulSoup(html, "html.parser")

        # Extract forms and test them
        forms = soup.find_all('form')
        form_data = []
        for form in forms:
            inputs = []
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                inputs.append({"name": input_tag.get("name"), "type": input_tag.get("type")})
            form_meta = {"action": form.get("action"), "method": form.get("method"), "inputs": inputs}
            form_data.append(form_meta)

            findings = test_form(session, url, form_meta)
            for f in findings:
                f["source_page"] = url
            sql_findings.extend(findings)

        metadata_list.append({"url": url, "forms": form_data})

        # Test URL params on the current page
        url_param_findings = test_url_params(session, url)
        for f in url_param_findings:
            f["source_page"] = url
        sql_findings.extend(url_param_findings)

        # Optionally follow same-host links found here (keeps scope limited)
        parsed_start_netloc_norm = _normalize_netloc(base_netloc)
        for link in soup.find_all('a', href=True):
            next_url = urljoin(url, link['href'])
            parsed_next = urlparse(next_url)
            if parsed_next.scheme not in ("http", "https", ""):
                continue
            next_netloc_norm = _normalize_netloc(parsed_next.netloc)
            if next_netloc_norm == parsed_start_netloc_norm:
                normalized = parsed_next._replace(fragment="").geturl()
                if normalized not in visited:
                    time.sleep(0.1)
                    crawl(session, normalized, base_netloc)

    except Exception as e:
        print("Error crawling", url, ":", e)

# Login routine
def do_login(session):
    try:
        resp = session.get(login_page, timeout=8)
    except Exception as e:
        print("[!] Cannot reach login page:", e)
        return False

    soup = BeautifulSoup(resp.text or "", "html.parser")
    hidden_inputs = {}
    form = soup.find("form")
    if form:
        for hid in form.find_all("input", {"type": "hidden"}):
            name = hid.get("name")
            if name:
                hidden_inputs[name] = hid.get("value", "")

    login_data = {}
    login_data.update(hidden_inputs)
    login_data["username"] = username
    login_data["password"] = password
    login_data["Login"] = "Login"

    try:
        resp2 = session.post(login_page, data=login_data, timeout=8, allow_redirects=True)
        if resp2 is not None and ("Logout" in resp2.text or "logout.php" in resp2.text or "DVWA" in resp2.text):
            print("[+] Login appears successful.")
            return True
        else:
            print("[-] Login may have failed. Check credentials or login form field names.")
            return False
    except Exception as e:
        print("[!] Login request failed:", e)
        return False

# Main
if __name__ == "__main__":
    session = requests.Session()
    parsed_base = urlparse(base_host)
    base_netloc = parsed_base.netloc

    print("Attempting login to target...")
    if not do_login(session):
        print("Exiting. Fix login and try again.")
        sys.exit(1)

    # Start crawling & testing from the sqli page
    crawl(session, target_start, base_netloc)

    # Save outputs
    output = {
        "crawled_pages": metadata_list,
        "sql_findings": sql_findings,
        "suggested_fixes": suggested_fixes()
    }

    with open("metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata_list, f, indent=2, ensure_ascii=False)

    with open("sql_findings.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print("Crawling and SQL testing complete.")
    print(f"Pages crawled: {len(metadata_list)}, SQL findings: {len(sql_findings)}")
    print("Results saved to metadata.json and sql_findings.json")
