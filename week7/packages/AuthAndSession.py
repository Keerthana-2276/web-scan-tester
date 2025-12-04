"""
Auth & Session Testing Module (Package Version)

Converted to be safely imported into main.py:
    from scanners import AuthAndSession
    AuthAndSession.run()
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import json
import time
import sys

# ---------------- CONFIG ----------------
base_host = "http://localhost:8080"
login_path = "/login.php"
protected_path = "/vulnerabilities/sqli/"
username_field = "username"
password_field = "password"
submit_name = "Login"

CHECK_CREDS = [("admin", "password"), ("admin", "admin"), ("root", "root"), ("test", "test")]
BRUTEFORCE_WORDLIST = ["password", "123456", "admin", "letmein", "dvwa", "qwerty"]
BRUTEFORCE_MAX_TRIES = 5
BRUTEFORCE_DELAY = 1.0
REQUEST_TIMEOUT = 8
# ----------------------------------------

findings = []


def save_findings():
    out = {"findings": findings, "recommendations": suggested_fixes()}
    with open("auth_findings.json", "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2, ensure_ascii=False)


def suggested_fixes():
    return {
        "use_https": "Serve auth pages and cookies over HTTPS.",
        "secure_cookie_flags": "Set Secure; HttpOnly; SameSite=strict or Lax on session cookies.",
        "session_regeneration": "Regenerate session ID after login.",
        "rate_limit": "Apply rate limiting/backoff on failed authentication attempts.",
        "account_lockout": "Enable progressive lockouts or CAPTCHA.",
        "mfa": "Enable multi-factor authentication.",
        "bind_session": "Bind session to additional factors (IP/UA) carefully."
    }


# ---------------- HELPER FUNCTIONS ----------------

def get_login_form_tokens(session, login_url):
    try:
        r = session.get(login_url, timeout=REQUEST_TIMEOUT)
    except Exception:
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
    data = {}
    if extra_data:
        data.update(extra_data)
    data[username_field] = user
    data[password_field] = pwd
    data[submit_name] = submit_name
    try:
        return session.post(login_url, data=data, timeout=REQUEST_TIMEOUT, allow_redirects=True)
    except Exception:
        return None


def is_logged_in(resp_text):
    if not resp_text:
        return False
    return ("Logout" in resp_text or "DVWA" in resp_text or "logout.php" in resp_text)


# ---------------- TEST MODULES ----------------

def test_default_credentials():
    session = requests.Session()
    login_url = base_host + login_path
    hidden, _ = get_login_form_tokens(session, login_url)

    for user, pwd in CHECK_CREDS:
        r = attempt_login(session, login_url, user, pwd, extra_data=hidden)
        logged = r is not None and is_logged_in(r.text)
        
        findings.append({
            "test": "default_credentials",
            "url": login_url,
            "username": user,
            "password": pwd,
            "success": bool(logged),
            "status_code": r.status_code if r else None
        })


        # findings.append({
        #     "test": "default_credentials",
        #     "username": user,
        #     "password": pwd,
        #     "success": bool(logged),
        #     "status_code": r.status_code if r else None
        # })
        if logged:
            try:
                session.get(base_host + "/logout.php", timeout=3)
            except Exception:
                pass
        time.sleep(0.3)


def test_bruteforce_simulation(target_user="admin"):
    session = requests.Session()
    login_url = base_host + login_path
    hidden, _ = get_login_form_tokens(session, login_url)

    tries = 0
    for pwd in BRUTEFORCE_WORDLIST:
        if tries >= BRUTEFORCE_MAX_TRIES:
            break
        r = attempt_login(session, login_url, target_user, pwd, extra_data=hidden)
        success = r is not None and is_logged_in(r.text)
        
        findings.append({
            "test": "brute_force_simulation",
            "url": login_url,
            "username": target_user,
            "password_tried": pwd,
            "success": bool(success),
            "status_code": r.status_code if r else None
        })

        # findings.append({
        #     "test": "brute_force_simulation",
        #     "username": target_user,
        #     "password_tried": pwd,
        #     "success": bool(success),
        #     "status_code": r.status_code if r else None
        # })
        tries += 1
        if success:
            try:
                session.get(base_host + "/logout.php", timeout=3)
            except Exception:
                pass
            break
        time.sleep(BRUTEFORCE_DELAY)


def inspect_cookie_flags():
    session = requests.Session()
    try:
        r = session.get(base_host, timeout=REQUEST_TIMEOUT)
    except Exception as e:
        findings.append({"test": "cookie_flags", "error": str(e)})
        return

    raw = r.headers.get("Set-Cookie", "")
    cookies = [{
        "header": raw,
        "name": raw.split("=")[0],
        "has_secure": "secure" in raw.lower(),
        "has_httponly": "httponly" in raw.lower(),
        "same_site": (
            "lax" if "samesite=lax" in raw.lower()
            else "strict" if "samesite=strict" in raw.lower()
            else None
        )
    }]

    findings.append({
        "test": "cookie_flags",
        "url": base_host,
        "cookies": cookies
    })

    # findings.append({"test": "cookie_flags", "cookies": cookies})


def test_session_fixation():
    session = requests.Session()
    login_url = base_host + login_path
    hidden, cookies_before = get_login_form_tokens(session, login_url)
    sess_name = next(iter(cookies_before)) if cookies_before else "PHPSESSID"

    fixation_value = "FIXATION_TEST_12345"
    session.cookies.set(sess_name, fixation_value)

    r = attempt_login(session, login_url, "admin", "password", extra_data=hidden)
    post_cookies = session.cookies.get_dict()
    post_value = post_cookies.get(sess_name)

    vulnerable = (post_value == fixation_value)

    findings.append({
        "test": "session_fixation",
        "url": login_url,
        "cookie_name": sess_name,
        "pre_login_value": fixation_value,
        "post_login_value": post_value,
        "vulnerable": vulnerable
    })

    # findings.append({
    #     "test": "session_fixation",
    #     "cookie_name": sess_name,
    #     "pre_login_value": fixation_value,
    #     "post_login_value": post_value,
    #     "vulnerable": vulnerable
    # })

    try:
        session.get(base_host + "/logout.php", timeout=3)
    except Exception:
        pass


def test_session_hijack():
    victim = requests.Session()
    login_url = base_host + login_path
    hidden, _ = get_login_form_tokens(victim, login_url)
    r = attempt_login(victim, login_url, "admin", "password", extra_data=hidden)
    if r is None or not is_logged_in(r.text):
        findings.append({"test": "session_hijack", "error": "Victim login failed."})
        return

    cookies = victim.cookies.get_dict()
    sess_name, sess_value = next(iter(cookies.items()))

    attacker = requests.Session()
    attacker.cookies.set(sess_name, sess_value)

    try:
        protected = attacker.get(base_host + protected_path, timeout=REQUEST_TIMEOUT)
        success = protected.status_code == 200 and is_logged_in(protected.text)
    except Exception:
        success = False
        protected = None

    findings.append({
        "test": "session_hijack",
        "url": base_host + protected_path,
        "cookie_name": sess_name,
        "cookie_value": sess_value,
        "attacker_access_success": bool(success),
        "status_code": protected.status_code if protected else None
    })

    # findings.append({
    #     "test": "session_hijack",
    #     "cookie_name": sess_name,
    #     "cookie_value": sess_value,
    #     "attacker_access_success": bool(success),
    #     "status_code": protected.status_code if protected else None
    # })

    try:
        victim.get(base_host + "/logout.php", timeout=3)
    except Exception:
        pass


# ---------------- MAIN WRAPPER ----------------

def run():
    findings.clear()

    # Quick reachability check
    try:
        requests.get(base_host, timeout=REQUEST_TIMEOUT)
    except Exception as e:
        print("[!] Cannot reach base_host:", e)
        return

    test_default_credentials()
    test_bruteforce_simulation()
    inspect_cookie_flags()
    test_session_fixation()
    test_session_hijack()
    save_findings()

    print("[+] Auth & Session testing completed. Output: auth_findings.json")
