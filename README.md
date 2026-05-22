# web-recon-toolkit

> **Umfassendes Web-Application-Reconnaissance-Toolkit für Penetrationstester**

Ein modulares Python-3-Tool ohne externe Abhängigkeiten für die initiale Recon-Phase eines Web-App-Pentests. Jedes Modul lässt sich einzeln oder mit `--all` zusammen ausführen. Ergebnisse können als JSON exportiert werden, um sie in größere Toolchains einzubinden.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)]()

---

## Rechtlicher Hinweis / Legal Disclaimer

**This tool is intended for authorized security assessments only.**  
Running reconnaissance scans against targets you do not own or have explicit written permission to test is **illegal** in most jurisdictions. The author assumes no liability for misuse. Always obtain proper authorization before using this tool.

---

## Inhaltsverzeichnis

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Modulreferenz](#modulreferenz)
   - [--tech — Technologie-Fingerprinting](#--tech--technologie-fingerprinting)
   - [--dirs — Directory Brute-force](#--dirs--directory-brute-force)
   - [--emails — E-Mail-Harvesting](#--emails--e-mail-harvesting)
   - [--dns — DNS-Enumeration](#--dns--dns-enumeration)
   - [--wayback — Wayback Machine](#--wayback--wayback-machine)
4. [CLI-Referenz](#cli-referenz)
5. [Pentest-Workflow](#pentest-workflow)
6. [Ausgabeformate](#ausgabeformate)
7. [Verwandte Tools](#verwandte-tools)
8. [Spenden](#spenden)

---

## Installation

```bash
git clone https://github.com/G4MEOVER18/web-recon-toolkit.git
cd web-recon-toolkit
# No pip install needed — zero external dependencies
python recon.py --help
```

Voraussetzungen: **Python 3.8+**, nur die Standardbibliothek.  
Unter Windows steht `nslookup` für DNS-Abfragen standardmäßig zur Verfügung. Unter Linux/macOS wird `dig` oder `nslookup` verwendet.

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

## Modulreferenz

### `--tech` — Technologie-Fingerprinting

Ruft die Zielseite und HTTP-Header ab und erkennt dabei:

| Kategorie | Erkennungsmethode |
|---|---|
| Webserver | HTTP-Header `Server:` |
| Backend | Header `X-Powered-By:` |
| CMS | Body-Patterns (wp-content, Joomla!, sites/all/modules, etc.) |
| Generator | `<meta name="generator">`-Tag |
| JS Frameworks | Script-`src`-Attribute (React, Vue, Angular, jQuery, Next.js, etc.) |
| CDN | Header: `cf-ray`, `x-akamai-*`, `x-amz-cf-id`, `x-varnish`, etc. |
| WAF | Header: `x-sucuri-id`, `cf-ray`, `x-fw-*`, `x-iinfo`, etc. |
| Security Headers | Prüft auf HSTS, CSP, X-Frame-Options, etc. |

**Beispielausgabe:**

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

Schickt parallele HEAD-Requests an eine eingebaute Liste mit **über 100 gängigen Pfaden** und meldet alles, was nicht 404 zurückgibt. Verwendet `ThreadPoolExecutor` mit konfigurierbarer Thread-Anzahl (`--threads`).

**Enthaltene Pfade (Auswahl):**
- Admin-Panels: `/admin`, `/wp-admin`, `/phpmyadmin`, `/console`, `/manager`
- API-Endpunkte: `/api`, `/api/v1`, `/swagger`, `/openapi.json`, `/graphql`
- Sensible Dateien: `/.env`, `/.git/HEAD`, `/backup.zip`, `/db.sql`, `/web.config`
- Konfigurationsdateien: `/config.yml`, `/config.json`, `/.htaccess`, `/.htpasswd`
- Info-Endpunkte: `/server-status`, `/actuator/env`, `/phpinfo.php`
- Security-Dateien: `/robots.txt`, `/security.txt`, `/.well-known/security.txt`

Gemeldete HTTP-Codes: `200` (gefunden), `301/302/307/308` (Redirect), `403/401` (verboten/Authentifizierung nötig — deutet auf Vorhandensein hin).

**Beispielausgabe:**

```
[*] Directory Brute-force — https://example.com
  200  https://example.com/robots.txt
  403  https://example.com/.git/HEAD
  301  https://example.com/admin → https://example.com/admin/
  200  https://example.com/wp-login.php

  Found 4 interesting path(s).
```

Eigene Wordlist mit `--wordlist /pfad/zur/liste.txt` hinzufügen (ein Pfad pro Zeile, `#` für Kommentare).

---

### `--emails` — E-Mail-Harvesting

Ruft mehrere Seiten des Ziels ab (Startseite, `/robots.txt`, `/sitemap.xml`, `/contact`, `/about`, `/impressum`) und extrahiert E-Mail-Adressen per Regex. Durchsucht auch **HTML-Kommentare**, die manchmal Entwickler- oder Admin-Adressen enthalten.

**Beispielausgabe:**

```
[*] Email Harvesting — https://example.com
  Found 3 email(s):
    admin@example.com
    support@example.com
    webmaster@example.com
```

---

### `--dns` — DNS-Enumeration

Löst alle gängigen DNS-Record-Typen für die Zieldomain auf und prüft die E-Mail-Sicherheitskonfiguration:

| Prüfung | Details |
|---|---|
| A / AAAA | IPv4- und IPv6-Adressen |
| MX | Mailserver-Records |
| NS | Nameserver-Records |
| TXT | Alle TXT-Records |
| CNAME | Canonical Name Records |
| SPF | Aus TXT-Records extrahiert (`v=spf1`) |
| DMARC | Abfrage von `_dmarc.<domain>` |
| DKIM | Abfrage von `default._domainkey.<domain>` |

**Beispielausgabe:**

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

Fragt das Internet Archive nach historischen Snapshots ab:

1. **Verfügbarkeitscheck** — findet den aktuellsten Snapshot-Zeitstempel und die URL über `archive.org/wayback/available`
2. **CDX-Index-Abfrage** — holt bis zu 20 kürzlich archivierte URLs über die CDX API, inklusive Zeitstempel und HTTP-Statuscodes zum Zeitpunkt der Archivierung

Nützlich, um zu finden:
- Alte Admin-Panels oder versteckte Endpunkte, die nicht mehr existieren
- Früher öffentlich zugängliche sensible Dateien (`.env`, Backups, etc.)
- Ältere API-Versionen

**Beispielausgabe:**

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

## CLI-Referenz

| Flag | Typ | Standard | Beschreibung |
|---|---|---|---|
| `target` | positional | — | Ziel-URL oder Hostname |
| `--tech` | Flag | — | Technologie-Fingerprinting ausführen |
| `--dirs` | Flag | — | Directory-Brute-force ausführen |
| `--emails` | Flag | — | E-Mail-Harvesting ausführen |
| `--dns` | Flag | — | DNS-Enumeration ausführen |
| `--wayback` | Flag | — | Wayback-Machine-Modul ausführen |
| `--all` | Flag | — | Alle Module ausführen |
| `--threads N` | int | `10` | Anzahl paralleler Threads (für `--dirs`) |
| `--timeout N` | int | `8` | HTTP-Request-Timeout in Sekunden |
| `--user-agent STR` | str | Chrome UA | Eigener User-Agent-String |
| `--wordlist FILE` | Pfad | — | Zusätzliche Wordlist für Directory-Scanning (mit `--dirs`) |
| `--json` | Flag | — | Ausgabe im JSON-Format |
| `--out FILE` | Pfad | — | Ergebnisse in Datei speichern |

---

## Pentest-Workflow

Ein typischer Recon-Ablauf für einen Web-App-Pentest:

```bash
# Schritt 1 — Passiver Recon: DNS + Wayback, bevor der Server berührt wird
python recon.py target.com --dns --wayback --json --out step1-passive.json

# Schritt 2 — Aktives Fingerprinting
python recon.py target.com --tech --out step2-tech.txt

# Schritt 3 — Directory Discovery mit größerer Wordlist
python recon.py target.com --dirs --threads 25 --wordlist ~/wordlists/raft-medium-directories.txt --out step3-dirs.txt

# Schritt 4 — E-Mail-Harvesting für OSINT / Phishing-Simulation
python recon.py target.com --emails

# Schritt 5 — Vollständiger kombinierter Scan für den Report
python recon.py target.com --all --json --out final-report.json
```

**Mit verwandten Tools kombinieren für tiefere Abdeckung:**

```bash
# Erst Subdomains enumerieren
python ~/tools/subdomain-takeover-scanner/scanner.py target.com

# Dann web-recon-toolkit auf jede aktive Subdomain anwenden
for sub in $(cat live-subs.txt); do
    python recon.py $sub --tech --dirs --out "$sub.txt"
done

# JWT-Tokens aus Responses prüfen
python ~/tools/jwt-pwn/jwt_pwn.py --token <token>

# HTTP-Security-Header im Detail auditieren
python ~/tools/http-header-auditor/auditor.py target.com

# Auf CORS-Fehlkonfigurationen testen
python ~/tools/cors-scanner/cors_scan.py target.com
```

---

## Ausgabeformate

### Konsole (Standard)
Farbige, menschenlesbare Ausgabe mit ANSI-Farbcodes.

### JSON (`--json`)
Strukturierte Ausgabe für Scripting und Reporting-Pipelines:

```json
{
  "meta": [{"target": "https://example.com", "scan_time": "2026-05-22T10:00:00Z", "modules": ["tech", "dns"]}],
  "tech": [{"Server": "nginx/1.24.0", "CMS": "WordPress", ...}],
  "dns":  [{"A": ["93.184.216.34"], "MX": ["mail.example.com"], ...}],
  "dirs": [{"path": "/wp-login.php", "code": 200, "url": "https://example.com/wp-login.php"}]
}
```

### Dateiausgabe (`--out`)
Jedes Format lässt sich in eine Datei speichern. Mit `--json` kombinieren für maschinenlesbare Ausgabe:

```bash
python recon.py target.com --all --json --out report.json
python recon.py target.com --all --out report.txt   # plain text
```

---

## Verwandte Tools

Alle Tools von [G4MEOVER18](https://github.com/G4MEOVER18):

| Tool | Beschreibung |
|---|---|
| [subdomain-takeover-scanner](https://github.com/G4MEOVER18/subdomain-takeover-scanner) | Erkennt verwaiste DNS-Records und Subdomain-Takeover-Schwachstellen |
| [jwt-pwn](https://github.com/G4MEOVER18/jwt-pwn) | JWT-Sicherheitstests: alg:none, RS256→HS256, Brute-force schwacher Secrets |
| [cors-scanner](https://github.com/G4MEOVER18/cors-scanner) | Erkennung von CORS-Fehlkonfigurationen |
| [http-header-auditor](https://github.com/G4MEOVER18/http-header-auditor) | Umfassende Analyse von HTTP-Security-Headern |
| [stm32-usb-fuzzer](https://github.com/G4MEOVER18/stm32-usb-fuzzer) | USB-Protokoll-Fuzzing über STM32-Mikrocontroller |

---

## Spenden

Falls dieses Tool dir bei einem Pentest Zeit gespart hat, freue ich mich über einen Kaffee:

**Bitcoin:** `39vZWmnUwDReQ15BwqQXzyqVQ6U8LardEf`
**PayPal:** [paypal.me/Freakbank1](https://paypal.me/Freakbank1)

---

*Nur mit Python-3-Standardbibliothek — kein pip nötig.*
