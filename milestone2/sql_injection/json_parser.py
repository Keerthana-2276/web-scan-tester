# summarize_findings.py
import json
import csv
import os
from collections import defaultdict
from html import escape

INFILE = "sql_findings.json"
CSV_OUT = "findings_summary.csv"
HTML_OUT = "findings_report.html"

def load_findings(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    # Accept multiple possible shapes:
    # 1) {"sql_findings": [...], ...}
    # 2) {"crawled_pages": [...], "sql_findings": [...], ...}
    # 3) [...] (just a list)
    if isinstance(data, dict):
        if "sql_findings" in data and isinstance(data["sql_findings"], list):
            return data["sql_findings"]
        # sometimes nested under top-level 'output' or similar
        for k, v in data.items():
            if isinstance(v, list) and v and isinstance(v[0], dict):
                # guess it's the correct list if items look like findings
                # but prefer keys that contain 'sql' or 'finding'
                if "sql" in k.lower() or "finding" in k.lower():
                    return v
        # fallback: collect any lists of dicts
        list_candidates = []
        for v in data.values():
            if isinstance(v, list) and v and isinstance(v[0], dict):
                list_candidates.append(v)
        if list_candidates:
            return list_candidates[0]
        return []
    elif isinstance(data, list):
        return data
    else:
        return []

def normalize_finding(f):
    # produce canonical fields for report
    f2 = {}
    f2['source_page'] = f.get("source_page") or f.get("url") or f.get("tested_url") or f.get("action_url") or ""
    f2['tested_url'] = f.get("tested_url") or f.get("action_url") or f2['source_page']
    f2['param_or_field'] = f.get("param") or f.get("injected_field") or ""
    f2['payload'] = f.get("payload") or ""
    f2['status_code'] = f.get("status_code") or ""
    f2['error_found'] = bool(f.get("error_found"))
    f2['reflected'] = bool(f.get("reflected"))
    # numeric relative change (if present), else 0.0
    try:
        f2['rel_length_change'] = float(f.get("rel_length_change") or f.get("rel_change") or 0.0)
    except Exception:
        f2['rel_length_change'] = 0.0
    return f2

def score(f):
    # heuristic scoring: higher = more likely exploitable
    s = 0
    if f['error_found']:
        s += 50
    if f['reflected']:
        s += 20
    # relative length change contributes up to 30 points
    rl = f['rel_length_change']
    if rl >= 1.0:
        s += 30
    else:
        s += int(rl * 30)
    return s

def dedupe_and_aggregate(findings):
    # dedupe by tested_url + param + payload
    d = {}
    for f in findings:
        key = (f['tested_url'], f['param_or_field'], f['payload'])
        if key not in d:
            d[key] = dict(f)
            d[key]['count'] = 1
        else:
            d[key]['count'] += 1
            # keep the highest severity flags (OR them)
            d[key]['error_found'] = d[key]['error_found'] or f['error_found']
            d[key]['reflected'] = d[key]['reflected'] or f['reflected']
            d[key]['rel_length_change'] = max(d[key]['rel_length_change'], f['rel_length_change'])
    # produce sorted list by score desc
    out = []
    for k, v in d.items():
        v['score'] = score(v)
        out.append(v)
    out.sort(key=lambda x: x['score'], reverse=True)
    return out

def write_csv(rows, path):
    keys = ['score','count','tested_url','param_or_field','payload','status_code','error_found','reflected','rel_length_change']
    with open(path, "w", newline='', encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(keys)
        for r in rows:
            writer.writerow([r.get(k,"") for k in keys])

def write_html(rows, path, top_n=100):
    html_parts = []
    html_parts.append("<!doctype html><html><head><meta charset='utf-8'><title>SQL Findings Report</title></head><body>")
    html_parts.append("<h1>SQL Findings Report</h1>")
    html_parts.append(f"<p>Total distinct findings: {len(rows)}</p>")
    html_parts.append("<table border='1' cellpadding='6' cellspacing='0'>")
    html_parts.append("<tr><th>Score</th><th>Count</th><th>URL</th><th>Param/Field</th><th>Payload</th><th>Status</th><th>Error</th><th>Reflected</th><th>RelChange</th></tr>")
    for r in rows[:top_n]:
        html_parts.append("<tr>")
        html_parts.append(f"<td>{r['score']}</td>")
        html_parts.append(f"<td>{r['count']}</td>")
        html_parts.append(f"<td><a href='{escape(r['tested_url'])}' target='_blank'>{escape(r['tested_url'])}</a></td>")
        html_parts.append(f"<td>{escape(str(r['param_or_field']))}</td>")
        html_parts.append(f"<td><code>{escape(r['payload'])}</code></td>")
        html_parts.append(f"<td>{escape(str(r.get('status_code','')))}</td>")
        html_parts.append(f"<td>{'Yes' if r['error_found'] else 'No'}</td>")
        html_parts.append(f"<td>{'Yes' if r['reflected'] else 'No'}</td>")
        html_parts.append(f"<td>{r['rel_length_change']:.2f}</td>")
        html_parts.append("</tr>")
    html_parts.append("</table>")
    html_parts.append("<hr><h3>Suggested Fixes</h3><ul>")
    html_parts.append("<li>Use parameterized queries / prepared statements.</li>")
    html_parts.append("<li>Validate and sanitize input; enforce allow-lists and lengths.</li>")
    html_parts.append("<li>Apply least-privilege DB accounts (no DROP/ALTER for web app user).</li>")
    html_parts.append("<li>Never show raw DB errors to users; log them server-side.</li>")
    html_parts.append("</ul></body></html>")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(html_parts))

def main():
    if not os.path.exists(INFILE):
        print(f"File not found: {INFILE}")
        return
    raw = load_findings(INFILE)
    if not raw:
        print("No findings found in file (or file format unknown).")
        return
    normalized = [normalize_finding(r) for r in raw]
    aggregated = dedupe_and_aggregate(normalized)
    write_csv(aggregated, CSV_OUT)
    write_html(aggregated, HTML_OUT)
    print(f"Parsed {len(raw)} raw entries -> {len(aggregated)} unique findings.")
    print(f"CSV written: {CSV_OUT}")
    print(f"HTML written: {HTML_OUT}")
    # print top 10 to console
    print("\nTop 10 findings (score, url, param, payload):")
    for r in aggregated[:10]:
        print(f"{r['score']:3d} | {r['tested_url']} | {r['param_or_field']} | {r['payload']} (count={r['count']})")

if __name__ == "__main__":
    main()
