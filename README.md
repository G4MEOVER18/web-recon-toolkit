# web-recon-toolkit

> **Comprehensive Web Application Reconnaissance Toolkit for Penetration Testers**

A modular, zero-dependency Python 3 tool for the initial reconnaissance phase of a web application pentest. Each module can be run independently or all together with `--all`. Results can be exported as JSON for integration into larger toolchains.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)]()

---

## Rechtlicher Hinweis / Legal Disclaimer

**This tool is intended for authorized security assessments only.**  
Running reconnaissance scans against targets you do not own or have explicit written permission to test is **illegal** in most jurisdictions. The author assumes no liability for misuse. Always obtain proper authorization before using this tool.

---

## Inhaltsverzeichnis / Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Module Reference](#module-reference)
   - [--tech — Technology Fingerprinting](#--tech--technology-fingerprinting)
   - [--dirs — Directory Brute-force](#--dirs--directory-brute-force)
   - [--emails — Email Harvesting](#--emails--email-harvesting)
   - [--dns — DNS Enumeration](#--dns--dns-enumeration)
   - [--wayback — Wayback Machine](#--wayback--wayback-machine)
4. [CLI Reference](#cli-reference)
5. [Pentest Workflow](#pentest-workflow)
6. [Output Formats](#output-formats)
7. [Related Tools](#related-tools)
8. [Donations](#donations)

---

## Installation

```bash
git clone https://github.com/G4MEOVER18/web-recon-toolkit.git
cd web-recon-toolkit
# No pip install needed — zero external dependencies
python recon.py --help
```

Requirements: **Python 3.8+**, standard library only.  
On Windows, `nslookup` is available by default for DNS queries. On Linux/macOS, `dig` or `nslookup` is used.

---

## Quick Start

```bash
# Run all modules against a target
python recon.py example.com --all

# Only fingerprint the technology stack
python recon.py https://example.com --tech

# Directory brute-force with 20 threads and 5s timeout
python recon.py example.com --dirs --threads 20 --timeout 5

# Full scan, save JSON output
python recon.py example.com --all --json --out results.json

# Use a custom wordlist for directory scanning
python recon.py example.com --dirs --wordlist /path/to/wordlist.txt
```

---

## Module Reference

### `--tech` — Technology Fingerprinting

Fetches the target page and HTTP headers, then identifies:

| Category | Detection Method |
|---|---|
| Web Server | `Server:` HTTP header |
| Backend | `X-Powered-By:` header |
| CMS | Body patterns (wp-content, Joomla!, sites/all/modules, etc.) |
| Generator | `<meta name="generator">` tag |
| JS Frameworks | Script `src` attributes (React, Vue, Angular, jQuery, Next.js, etc.) |
| CDN | Headers: `cf-ray`, `x-akamai-*`, `x-amz-cf-id`, `x-varnish`, etc. |
| WAF | Headers: `x-sucuri-id`, `cf-ray`, `x-fw-*`, `x-iinfo`, etc. |
| Security Headers | Checks for HSTS, CSP, X-Frame-Options, etc. |

**Example output:**

```
[*] Technology Fingerprinting — https://example.com
  Key                        Value
  -------------------------- ----------------------------------------
  Server                     nginx/1.24.0
  X-Powered-By               PHP/8.2.1
  CMS                        WordPress
  JS Frameworks              jQuery, React
  CDN                        Cloudflare
  WAF                        Cloudflare WAF
  Security Headers:
    strict-transport-security  max-age=31536000; includeSubDomains
    content-security-policy    MISSING
    x-frame-options            SAMEORIGIN
```

---

### `--dirs` — Directory Brute-force

Sends concurrent HEAD requests to a built-in list of **100+ common paths** and reports anything other than 404. Uses `ThreadPoolExecutor` with configurable thread count (`--threads`).

**Built-in paths include:**
- Admin panels: `/admin`, `/wp-admin`, `/phpmyadmin`, `/console`, `/manager`
- API endpoints: `/api`, `/api/v1`, `/swagger`, `/openapi.json`, `/graphql`
- Sensitive files: `/.env`, `/.git/HEAD`, `/backup.zip`, `/db.sql`, `/web.config`
- Config files: `/config.yml`, `/config.json`, `/.htaccess`, `/.htpasswd`
- Info endpoints: `/server-status`, `/actuator/env`, `/phpinfo.php`
- Security files: `/robots.txt`, `/security.txt`, `/.well-known/security.txt`

Reported HTTP codes: `200` (found), `301/302/307/308` (redirect), `403/401` (forbidden/auth required — indicates presence).

**Example output:**

```
[*] Directory Brute-force — https://example.com
  200  https://example.com/robots.txt
  403  https://example.com/.git/HEAD
  301  https://example.com/admin → https://example.com/admin/
  200  https://example.com/wp-login.php

  Found 4 interesting path(s).
```

Provide an additional wordlist with `--wordlist /path/to/list.txt` (one path per line, `#` for comments).

---

### `--emails` — Email Harvesting

Fetches multiple pages from the target (homepage, `/robots.txt`, `/sitemap.xml`, `/contact`, `/about`, `/impressum`) and extracts email addresses using a regex pattern. Also searches inside **HTML comments**, which sometimes contain developer or admin addresses.

**Example output:**

```
[*] Email Harvesting — https://example.com
  Found 3 email(s):
    admin@example.com
    support@example.com
    webmaster@example.com
```

---

### `--dns` — DNS Enumeration

Resolves all common DNS record types for the target domain and checks email security configuration:

| Check | Details |
|---|---|
| A / AAAA | IPv4 and IPv6 addresses |
| MX | Mail server records |
| NS | Nameserver records |
| TXT | All TXT records |
| CNAME | Canonical name records |
| SPF | Extracted from TXT records (`v=spf1`) |
| DMARC | Queries `_dmarc.<domain>` |
| DKIM | Queries `default._domainkey.<domain>` |

**Example output:**

```
[*] DNS Enumeration — https://example.com
  A         93.184.216.34
  AAAA      2606:2800:220:1:248:1893:25c8:1946
  MX        10 mail.example.com.
  NS        a.iana-servers.net.
  TXT       "v=spf1 include:_spf.google.com ~all"

  SPF:   v=spf1 include:_spf.google.com ~all
  DMARC: v=DMARC1; p=reject; rua=mailto:dmarc@example.com
  DKIM:  default._domainkey not found (selector unknown)
```

---

### `--wayback` — Wayback Machine

Queries the Internet Archive for historical snapshots:

1. **Availability check** — finds the most recent snapshot timestamp and URL via `archive.org/wayback/available`
2. **CDX index query** — fetches up to 20 recent archived URLs via the CDX API, showing timestamps and HTTP status codes at time of archival

Useful for finding:
- Old admin panels or hidden endpoints that no longer exist
- Previously exposed sensitive files (`.env`, backups, etc.)
- Historical API versions

**Example output:**

```
[*] Wayback Machine — https://example.com
  Snapshot available: 2024-11-01 14:22  →  https://web.archive.org/web/20241101142201/https://example.com/

  Timestamp          Code   URL
  ----------------- ------ --------------------------------------------------
  2024-11-01        200    https://example.com/
  2024-10-15        200    https://example.com/admin-old/
  2024-09-22        200    https://example.com/backup-2024.zip
```

---

## CLI Reference

| Flag | Type | Default | Description |
|---|---|---|---|
| `target` | positional | — | Target URL or hostname |
| `--tech` | flag | — | Run technology fingerprinting module |
| `--dirs` | flag | — | Run directory brute-force module |
| `--emails` | flag | — | Run email harvesting module |
| `--dns` | flag | — | Run DNS enumeration module |
| `--wayback` | flag | — | Run Wayback Machine module |
| `--all` | flag | — | Run all modules |
| `--threads N` | int | `10` | Number of concurrent threads (for `--dirs`) |
| `--timeout N` | int | `8` | HTTP request timeout in seconds |
| `--user-agent STR` | str | Chrome UA | Custom User-Agent string |
| `--wordlist FILE` | path | — | Extra directory wordlist (used with `--dirs`) |
| `--json` | flag | — | Output results in JSON format |
| `--out FILE` | path | — | Save results to file |

---

## Pentest Workflow

A typical recon phase for a web application pentest:

```bash
# Step 1 — Initial passive recon: DNS + Wayback before touching the server
python recon.py target.com --dns --wayback --json --out step1-passive.json

# Step 2 — Active fingerprinting
python recon.py target.com --tech --out step2-tech.txt

# Step 3 — Directory discovery with a larger wordlist
python recon.py target.com --dirs --threads 25 --wordlist ~/wordlists/raft-medium-directories.txt --out step3-dirs.txt

# Step 4 — Email harvesting for OSINT / phishing sim
python recon.py target.com --emails

# Step 5 — Full combined scan for report
python recon.py target.com --all --json --out final-report.json
```

**Combine with related tools for deeper coverage:**

```bash
# Enumerate subdomains first
python ~/tools/subdomain-takeover-scanner/scanner.py target.com

# Then run web-recon-toolkit on each live subdomain
for sub in $(cat live-subs.txt); do
    python recon.py $sub --tech --dirs --out "$sub.txt"
done

# Check JWT tokens found in responses
python ~/tools/jwt-pwn/jwt_pwn.py --token <token>

# Audit HTTP security headers in detail
python ~/tools/http-header-auditor/auditor.py target.com

# Test for CORS misconfigurations
python ~/tools/cors-scanner/cors_scan.py target.com
```

---

## Output Formats

### Console (default)
Coloured, human-readable output with ANSI colour codes.

### JSON (`--json`)
Structured output suitable for scripting and reporting pipelines:

```json
{
  "meta": [{"target": "https://example.com", "scan_time": "2026-05-22T10:00:00Z", "modules": ["tech", "dns"]}],
  "tech": [{"Server": "nginx/1.24.0", "CMS": "WordPress", ...}],
  "dns":  [{"A": ["93.184.216.34"], "MX": ["mail.example.com"], ...}],
  "dirs": [{"path": "/wp-login.php", "code": 200, "url": "https://example.com/wp-login.php"}]
}
```

### File output (`--out`)
Save any format to a file. Combine with `--json` for machine-readable output:

```bash
python recon.py target.com --all --json --out report.json
python recon.py target.com --all --out report.txt   # plain text
```

---

## Related Tools

All tools by [G4MEOVER18](https://github.com/G4MEOVER18):

| Tool | Description |
|---|---|
| [subdomain-takeover-scanner](https://github.com/G4MEOVER18/subdomain-takeover-scanner) | Detect dangling DNS records and subdomain takeover vulnerabilities |
| [jwt-pwn](https://github.com/G4MEOVER18/jwt-pwn) | JWT security testing: alg:none, RS256→HS256, weak secret brute-force |
| [cors-scanner](https://github.com/G4MEOVER18/cors-scanner) | CORS misconfiguration detection |
| [http-header-auditor](https://github.com/G4MEOVER18/http-header-auditor) | Comprehensive HTTP security header analysis |
| [stm32-usb-fuzzer](https://github.com/G4MEOVER18/stm32-usb-fuzzer) | USB protocol fuzzing via STM32 microcontrollers |

---

## Donations

If this tool saved you time on a pentest, consider buying me a coffee:

**Bitcoin:** `39vZWmnUwDReQ15BwqQXzyqVQ6U8LardEf`
**PayPal:** [paypal.me/Freakbank1](https://paypal.me/Freakbank1)

---

*Built with Python 3 stdlib only — no pip required.*
