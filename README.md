# Web Scan Tester

A multi‑module security testing toolkit for learning and automating
basic web vulnerability scanning, including **SQL Injection**, **XSS**,
**Authentication & Session Testing**, **Access Control/IDOR**, and **Web
Crawling**.

This repository contains your work for different milestones of your
security project.

------------------------------------------------------------------------

## 📁 Project Structure

    .
    │   LICENSE
    │   style.css
    │
    ├── milestone1
    │   ├── Docker
    │   │   └── docker-compose.yml
    │   └── webcrawler
    │       ├── metadata.json
    │       ├── milestone2_webcrawler.py
    │       └── sql_findings.json
    │
    ├── milestone2
    │   ├── sql_injection
    │   │   ├── crawler.py
    │   │   ├── docker-compose.yml
    │   │   ├── findings_report.html
    │   │   ├── findings_summary.csv
    │   │   ├── json_parser.py
    │   │   ├── metadata.json
    │   │   ├── sql_findings.json
    │   │   └── Screenshots
    │   │       └── (SQL Injection screenshots)
    │   └── xss
    │       ├── xss.py
    │       └── xss_findings.json
    │
    ├── milestone3
    │   ├── Access Control and IDOR Testing
    │   │   ├── AccessControl.py
    │   │   └── access_findings.json
    │   ├── AccessControl
    │   │   ├── AccessControl.py
    │   │   └── access_findings.json
    │   └── Authentication and Session Testing
    │       ├── AuthAndSession.py
    │       └── auth_findings.json
    │
    └── week7
        ├── access_findings.json
        ├── auth_findings.json
        ├── idor_findings.json
        ├── main.py
        ├── Security_Report.html
        ├── Security_Report.pdf
        ├── sql_findings.json
        └── xss_findings.json
        └── packages
            ├── AccessControl.py
            ├── AccessControlIDOR.py
            ├── AuthAndSession.py
            ├── sqlinject.py
            ├── xss.py
            └── __init__.py

------------------------------------------------------------------------

## 🚀 What This Project Does

### ✔ **Web Crawler**

-   Crawls pages and collects forms, links, and input fields.
-   Stores metadata for later vulnerability testing.

### ✔ **SQL Injection Scanner**

-   Sends payloads to fields.
-   Detects whether database errors, union results, or bypass conditions
    occur.
-   Saves findings in JSON, CSV, and HTML.

### ✔ **XSS Scanner**

-   Tests pages with XSS payloads.
-   Checks reflection of input in responses.
-   Stores findings in `xss_findings.json`.

### ✔ **Access Control & IDOR Scanner**

-   Checks unauthorized access to pages and parameters.
-   Tries ID-based URL manipulation.
-   Writes results to `access_findings.json`.

### ✔ **Authentication & Session Testing**

-   Checks login strength, session cookies, CSRF tokens, logout
    behavior, etc.

### ✔ **Week 7 Integrated Runner (`main.py`)**

-   Runs all scanners.
-   Generates final reports (HTML + PDF).

------------------------------------------------------------------------

## 🛠 How to Run

### 1️⃣ Install Dependencies

    pip install -r requirements.txt

### 2️⃣ Start DVWA (if using)

    docker-compose up --build

### 3️⃣ Run the Main Script

    python week7/main.py

------------------------------------------------------------------------

## 📄 Output Reports

You will get: - `Security_Report.html` - `Security_Report.pdf` - JSON
outputs for each scan

------------------------------------------------------------------------

## 🙌 Contribution

Pull requests are welcome --- this repo is designed for learning and
improving web security automation.
