"""
auth_session_testing.py

Week 5: Authentication & Session Testing module.

Capabilities:
 - Check default/weak credentials from a small list
 - Safe, throttled brute-force simulation (limit attempts + delay)
 - Inspect session cookie flags (HttpOnly, Secure, SameSite)
 - Session fixation test (set session id before login, see if server honors it after login)
 - Session hijack test (reuse logged-in cookie in a separate client)
 - Output findings to auth_findings.json

Config carefully before running (target_host + login path). Designed for DVWA on localhost by default.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import json
import time
import sys

# ---------------- CONFIG ----------------
base_host = "http://localhost:8080"
login_path = "/login.php"          # endpoint to POST credentials (change if different)
protected_path = "/vulnerabilities/sqli/"  # an authenticated page to check access
username_field = "username"        # change if your login form uses different field names
password_field = "password"
submit_name = "Login"              # submit field name/value DVWA expects

# Credentials / brute-force settings (modify safely)
CHECK_CREDS = [("admin", "password"), ("admin", "admin"), ("root", "root"), ("test", "test")]
BRUTEFORCE_WORDLIST = ["password", "123456", "admin", "letmein", "dvwa", "qwerty"]
BRUTEFORCE_MAX_TRIES = 5          # absolute cap on attempts (keeps test safe)
BRUTEFORCE_DELAY = 1.0            # seconds between attempts

# Timeout and politeness
REQUEST_TIMEOUT = 8
# ----------------------------------------

findings = []  # collect findings here

def save_findings():
    """Write findings to a JSON file for reporting."""
    out = {"findings": findings, "recommendations": suggested_fixes()}
    with open("auth_findings.json", "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, ensure_ascii=False)

def suggested_fixes():
    """Remediation suggestions included in final output."""
    return {
        "use_https": "Serve auth pages and cookies over HTTPS (TLS).",
        "secure_cookie_flags": "Set Secure; HttpOnly; SameSite=strict or Lax on session cookies.",
        "session_regeneration": "Regenerate session identifier after login (prevent fixation).",
        "rate_limit": "Apply rate limiting and exponential backoff on failed auth attempts.",
        "account_lockout": "Implement progressive lockouts or CAPTCHA after repeated failures.",
        "mfa": "Provide multi-factor authentication for sensitive accounts.",
        "bind_session": "Consider binding sessions to additional attributes (IP/UA) cautiously."
    }

# ---------- Helpers ----------
def get_login_form_tokens(session, login_url):
    """
    GET the login page and return:
      - any hidden fields (dict)
      - a dict of cookies returned (session cookies)
    """
    try:
        r = session.get(login_url, timeout=REQUEST_TIMEOUT)
    except Exception as e:
        print("[!] Cannot fetch login page:", e)
        return {}, {}
    soup = BeautifulSoup(r.text or "", "html.parser")
    hidden = {}
    form = soup.find("form")
    if form:
        for hid in form.find_all("input", {"type": "hidden"}):
            name = hid.get("name")
            if name:
                hidden[name] = hid.get("value", "")
    return hidden, r.cookies.get_dict()

def attempt_login(session, login_url, user, pwd, extra_data=None):
    """
    Attempt login by POSTing form data. Returns the response object or None on error.
    Uses session (so cookies persist).
    """
    data = {}
    if extra_data:
        data.update(extra_data)
    data[username_field] = user
    data[password_field] = pwd
    # include submit name if present
    data[submit_name] = submit_name
    try:
        r = session.post(login_url, data=data, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        return r
    except Exception as e:
        print("[!] Login POST failed:", e)
        return None

def is_logged_in(resp_text):
    """
    Heuristic for DVWA: look for 'Logout' or 'dvwa' in page to consider login success.
    Adjust for other apps if needed.
    """
    if not resp_text:
        return False
    return ("Logout" in resp_text or "logout.php" in resp_text or "DVWA" in resp_text or "Welcome" in resp_text)

# ---------- Tests ----------

def test_default_credentials():
    """Check a short list of common/weak credentials (non-exhaustive)."""
    session = requests.Session()
    login_url = base_host + login_path
    hidden, cookies_before = get_login_form_tokens(session, login_url)

    for user, pwd in CHECK_CREDS:
        print(f"[+] Testing default credential: {user}/{pwd}")
        r = attempt_login(session, login_url, user, pwd, extra_data=hidden)
        logged = r is not None and is_logged_in(r.text)
        findings.append({
            "test": "default_credentials",
            "username": user,
            "password": pwd,
            "success": bool(logged),
            "status_code": r.status_code if r is not None else None
        })
        if logged:
            print(f"    -> SUCCESS: {user}/{pwd}")
            # logout to reset state if needed (best-effort)
            try:
                session.get(base_host + "/logout.php", timeout=3)
            except Exception:
                pass
        time.sleep(0.3)  # small delay

def test_bruteforce_simulation(target_user="admin"):
    """
    Simulate a small, safe brute-force attempt against a single username using BRUTEFORCE_WORDLIST.
    Honours BRUTEFORCE_MAX_TRIES and BRUTEFORCE_DELAY to be non-aggressive.
    """
    session = requests.Session()
    login_url = base_host + login_path
    hidden, _ = get_login_form_tokens(session, login_url)

    tries = 0
    for pwd in BRUTEFORCE_WORDLIST:
        if tries >= BRUTEFORCE_MAX_TRIES:
            print("[*] Reached brute-force max tries; stopping to be safe.")
            break
        print(f"[+] Brute force attempt: {target_user} / {pwd}")
        r = attempt_login(session, login_url, target_user, pwd, extra_data=hidden)
        success = r is not None and is_logged_in(r.text)
        findings.append({
            "test": "brute_force_simulation",
            "username": target_user,
            "password_tried": pwd,
            "success": bool(success),
            "status_code": r.status_code if r is not None else None
        })
        tries += 1
        if success:
            print("    -> LOGIN SUCCESS during brute-force simulation (stop further attempts).")
            # logout and stop further attempts
            try:
                session.get(base_host + "/logout.php", timeout=3)
            except Exception:
                pass
            break
        time.sleep(BRUTEFORCE_DELAY)

def inspect_cookie_flags():
    """
    GET the login page (or any page) and inspect Set-Cookie headers for security flags.
    We'll look for Secure, HttpOnly, and SameSite.
    """
    session = requests.Session()
    try:
        r = session.get(base_host, timeout=REQUEST_TIMEOUT)
    except Exception as e:
        print("[!] Cannot fetch base host for cookie inspection:", e)
        findings.append({"test": "cookie_flags", "error": str(e)})
        return

    # requests exposes cookies as a dict (values only), but we need raw headers to inspect flags
    raw_set_cookie = r.headers.get("Set-Cookie")
    # In many setups multiple Set-Cookie headers exist; requests combines them in one string occasionally.
    # So fetch from raw headers via r.raw if necessary (best-effort).
    set_cookie_headers = []
    if raw_set_cookie:
        set_cookie_headers = [raw_set_cookie]
    else:
        # try to extract multiple headers via r.raw (not always available)
        try:
            # r.raw._original_response is a http.client.HTTPResponse; headers there can be fetched
            headers = r.raw._original_response.getheaders()
            set_cookie_headers = [v for (k, v) in headers if k.lower() == "set-cookie"]
        except Exception:
            pass

    # parse each Set-Cookie header for flags
    cookies_info = []
    for sc in set_cookie_headers:
        sc_lower = sc.lower()
        cookie_name = sc.split("=", 1)[0]
        cookies_info.append({
            "header": sc,
            "name": cookie_name,
            "has_secure": "secure" in sc_lower,
            "has_httponly": "httponly" in sc_lower,
            "same_site": None if "samesite" not in sc_lower else (
                # crude parse
                "lax" if "samesite=lax" in sc_lower else ("strict" if "samesite=strict" in sc_lower else "none")
            )
        })
    findings.append({"test": "cookie_flags", "cookies": cookies_info})
    print("[+] Cookie flag inspection complete.")

def test_session_fixation():
    """
    Session fixation test (non-destructive):
     - Create a session and set a custom session id cookie BEFORE login.
     - Login using that session and check whether the server accepted/kept our cookie value.
     - If the session id is the same after login, that's a session-fixation weakness.
    """
    session = requests.Session()
    login_url = base_host + login_path

    # Step 1: GET login to learn cookie names
    hidden, cookies_before = get_login_form_tokens(session, login_url)
    if not cookies_before:
        sess_name = "PHPSESSID"
    else:
        sess_name = next(iter(cookies_before.keys()))

    # Step 2: Set a fixation value intentionally
    fixation_value = "FIXATION_TEST_12345"
    session.cookies.set(sess_name, fixation_value)
    print(f"[+] Set cookie {sess_name}={fixation_value} before login (fixation test).")

    # Step 3: Attempt login
    r = attempt_login(session, login_url, "admin", "password", extra_data=hidden)

    # Step 4: Safely get post-login session cookie(s)
    post_cookies = session.cookies.get_dict()
    post_value = post_cookies.get(sess_name, None)

    # If multiple cookies exist with same name, merge/inspect manually
    if post_value is None:
        # fallback: extract from cookie jar manually
        post_value = None
        for c in session.cookies:
            if c.name == sess_name:
                post_value = c.value
                break

    fixation_ok = (post_value == fixation_value)
    findings.append({
        "test": "session_fixation",
        "cookie_name": sess_name,
        "pre_login_value": fixation_value,
        "post_login_value": post_value,
        "vulnerable": fixation_ok
    })
    if fixation_ok:
        print("    -> POSSIBLE session fixation: server preserved our session id across login.")
    else:
        print("    -> Session id changed after login (good).")

    # logout to clear session
    try:
        session.get(base_host + "/logout.php", timeout=3)
    except Exception:
        pass

def test_session_hijack():
    """
    Session hijack simulation:
      - Log in normally and capture the session cookie value.
      - Create a new session object (simulating attacker) and set the captured cookie.
      - Access a protected page with the attacker's session; if it gets access, session can be reused.
    This is a basic check: in real environments, session binding to IP/UA may be used.
    """
    # Step 1: login and capture cookie
    victim = requests.Session()
    login_url = base_host + login_path
    hidden, _ = get_login_form_tokens(victim, login_url)
    r = attempt_login(victim, login_url, "admin", "password", extra_data=hidden)
    if r is None or not is_logged_in(r.text):
        findings.append({"test": "session_hijack", "error": "Could not log in as victim to obtain session cookie."})
        print("[!] Could not login as victim to obtain session cookie; skipping hijack test.")
        return

    # get first session cookie name & value
    cookies = victim.cookies.get_dict()
    if not cookies:
        findings.append({"test": "session_hijack", "error": "No session cookie found after login."})
        print("[!] No session cookie found after login; skipping hijack test.")
        return
    sess_name, sess_value = next(iter(cookies.items()))
    print(f"[+] Captured session cookie: {sess_name}={sess_value}")

    # Step 2: simulate attacker using the same cookie value in a new session
    attacker = requests.Session()
    attacker.cookies.set(sess_name, sess_value)
    # optionally set a different User-Agent to test binding
    attacker.headers.update({"User-Agent": "HijackTestAgent/1.0"})
    # Access protected resource
    try:
        protected = attacker.get(base_host + protected_path, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        got_access = protected is not None and protected.status_code == 200 and ("Logout" in protected.text or "DVWA" in protected.text or "vulnerabilities" in protected.text)
    except Exception as e:
        got_access = False
        protected = None
    findings.append({
        "test": "session_hijack",
        "cookie_name": sess_name,
        "cookie_value": sess_value,
        "attacker_access_success": bool(got_access),
        "status_code": protected.status_code if protected is not None else None
    })
    if got_access:
        print("    -> Attacker session reuse allowed access to protected resource (possible hijack).")
    else:
        print("    -> Attacker could not access protected resource with captured cookie (good).")

    # cleanup: logout victim
    try:
        victim.get(base_host + "/logout.php", timeout=3)
    except Exception:
        pass

# ----------------- MAIN -----------------
if __name__ == "__main__":
    print("[*] Starting Auth & Session Testing module")
    # Safety check - quick ping to base host
    try:
        r = requests.get(base_host, timeout=REQUEST_TIMEOUT)
    except Exception as e:
        print("[!] Cannot reach base_host:", e)
        sys.exit(1)

    # 1) Default credentials check
    print("[*] Checking default/weak credentials")
    test_default_credentials()

    # 2) Brute-force simulation (safe)
    print("[*] Simulating throttled brute-force")
    test_bruteforce_simulation(target_user="admin")

    # 3) Inspect cookie flags
    print("[*] Inspecting cookie flags (Secure/HttpOnly/SameSite)")
    inspect_cookie_flags()

    # 4) Session fixation test
    print("[*] Testing session fixation")
    test_session_fixation()

    # 5) Session hijack simulation
    print("[*] Testing session hijack (cookie reuse)")
    test_session_hijack()

    # Save results
    save_findings()
    print("[+] Tests complete. Findings written to auth_findings.json")
    # Summarize results
    for f in findings:
        print(" -", f.get("test"), "->", ("VULNERABLE" if f.get("vulnerable") or f.get("success") or f.get("attacker_access_success") else f.get("error", f.get("success", False))))

    print("\nRecommendations (short):")
    for k, v in suggested_fixes().items():
        print(f" - {k}: {v}")

