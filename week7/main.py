import json
import os
from datetime import datetime

# Import scanners
from packages.sqlinject import run as run_sql_injection

from packages.xss import run as run_xss_scanner
from packages.AccessControl import run as run_access_control
from packages.AccessControlIDOR import run as run_idor_test
from packages.AuthAndSession import run as run_auth_session


def load_json(filename):
    if not os.path.exists(filename):
        return []


    try:
        with open(filename, "r", encoding="utf-8") as fh:
            data = json.load(fh)
            return data.get("findings", [])
    except:
        return []

def run_all_scanners():
    print("\n===== Running All Security Scanners =====\n")

    print("[1] SQL Injection Scanner...")
    run_sql_injection()

    print("[2] XSS Scanner...")
    run_xss_scanner()

    print("[3] Access Control Scanner...")
    run_access_control()

    print("[4] IDOR Scanner...")
    run_idor_test()

    print("[5] Authentication & Session Scanner...")
    run_auth_session()

    print("\n===== All Scanners Completed =====\n")

def generate_security_report():
    print("[+] Generating Week-7 Security Report...")

    all_findings = (
        load_json("sql_findings.json")
        + load_json("xss_findings.json")
        + load_json("access_findings.json")
        + load_json("idor_findings.json")
        + load_json("auth_findings.json")
    )

    if not all_findings:
        print("[!] No findings found. Run scanners first.")
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""
<html>
<head>
<title>Week 7 Security Report</title>
<style>
body {{
    font-family: Arial;
    margin: 20px;
}}
h1 {{
    color: #333;
}}
.finding {{
    border: 1px solid #ccc;
    padding: 12px;
    margin-bottom: 10px;
    border-radius: 6px;
}}
.high {{ background-color: #ffcccc; }}
.medium {{ background-color: #fff0b3; }}
.low {{ background-color: #ccffcc; }}
pre {{
    background: #f5f5f5;
    padding: 10px;
    overflow-x: auto;
}}
</style>
</head>
<body>
<h1>Week 7 Automated Security Report</h1>
<p><strong>Generated:</strong> {timestamp}</p>
<hr>
"""

    for f in all_findings:
        vuln_type = f.get("test", "Unknown")
       # endpoint = f.get("url", "N/A")
        
        endpoint = (
    f.get("url")
    or f.get("target")
    or f.get("endpoint")
    or f.get("action_url")
    or f.get("links_scanned")
    or f.get("scanned_links")
    or "N/A"
)


        # Severity logic
        if f.get("success") or f.get("vulnerable") or f.get("attacker_access_success"):
            sev = "high"
        elif f.get("error"):
            sev = "low"
        else:
            sev = "medium"

        html += f"""
<div class="finding {sev}">
    <h3>Vulnerability: {vuln_type}</h3>
    <p><strong>Endpoint:</strong> {endpoint}</p>
    <p><strong>Severity:</strong> {sev.upper()}</p>
    <pre>{json.dumps(f, indent=2)}</pre>
</div>
"""

    html += "</body></html>"

    with open("Security_Report.html", "w", encoding="utf-8") as fh:
        fh.write(html)

    print("[+] HTML saved: Security_Report.html")


def generate_pdf():
   
    exit_code = os.system("wkhtmltopdf Security_Report.html Security_Report.pdf")

    if exit_code == 0:
        print("[+] PDF generated: Security_Report.pdf")
    else:
        print("[!] wkhtmltopdf not installed → PDF skipped.")


if __name__ == "__main__":
    run_all_scanners()
    generate_security_report()
    generate_pdf()
    print("\n[✓] Week-7 automation complete!\n")
