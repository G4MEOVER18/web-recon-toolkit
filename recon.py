#!/usr/bin/env python3
"""
web-recon-toolkit — Comprehensive Web Application Reconnaissance Tool
For penetration testers and security researchers.

Usage:
    python recon.py <target> [--tech] [--dirs] [--emails] [--dns] [--wayback]
                             [--ssl] [--secrets] [--subdomains]
                             [--all] [--modules M1,M2,...]
                             [--threads N] [--timeout N] [--user-agent STR]
                             [--delay FLOAT] [--retry INT] [--proxy URL]
                             [--json] [--out FILE] [--wordlist FILE]

Author  : G4MEOVER18
License : MIT
"""

import sys
import re
import ssl
import json
import socket
import struct
import argparse
import threading
import time
import urllib.request
import urllib.error
import urllib.parse
from html.parser import HTMLParser
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Colour helpers (no deps, pure ANSI)
# ---------------------------------------------------------------------------

RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
GREY   = "\033[90m"
WHITE  = "\033[97m"

def c(text, colour):
    return f"{colour}{text}{RESET}"

def banner():
    print(f"""
{CYAN}{BOLD}
  ██╗    ██╗███████╗██████╗       ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██║    ██║██╔════╝██╔══██╗      ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██║ █╗ ██║█████╗  ██████╔╝█████╗██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██║███╗██║██╔══╝  ██╔══██╗╚════╝██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ╚███╔███╔╝███████╗██████╔╝      ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
   ╚══╝╚══╝ ╚══════╝╚═════╝       ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{RESET}{GREY}  Web Application Reconnaissance Toolkit  |  github.com/G4MEOVER18/web-recon-toolkit{RESET}
""")

# ---------------------------------------------------------------------------
# Shared HTTP helpers
# ---------------------------------------------------------------------------

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# Global proxy opener — replaced by setup_proxy() if --proxy is given
_OPENER = urllib.request.build_opener()

def setup_proxy(proxy_url):
    """Install a proxy for all subsequent http_get / http_head calls."""
    global _OPENER
    proxy_handler = urllib.request.ProxyHandler({
        "http":  proxy_url,
        "https": proxy_url,
    })
    _OPENER = urllib.request.build_opener(proxy_handler)

def http_get(url, timeout=8, ua=DEFAULT_UA, allow_redirects=True, retry=1):
    """Perform a GET request. Returns (status_code, headers_dict, body_str) or raises."""
    req = urllib.request.Request(url, headers={"User-Agent": ua})
    last_exc = None
    for attempt in range(max(1, retry)):
        try:
            with _OPENER.open(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                headers = dict(resp.headers)
                return resp.status, headers, body
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace") if e.fp else ""
            return e.code, dict(e.headers) if e.headers else {}, body
        except Exception as e:
            last_exc = e
            if attempt < retry - 1:
                time.sleep(0.5)
    raise last_exc

def http_head(url, timeout=8, ua=DEFAULT_UA, retry=1):
    """Perform a HEAD request. Returns (status_code, headers_dict) or (None, {})."""
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": ua})
    for attempt in range(max(1, retry)):
        try:
            with _OPENER.open(req, timeout=timeout) as resp:
                return resp.status, dict(resp.headers)
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers) if e.headers else {}
        except Exception:
            if attempt < retry - 1:
                time.sleep(0.5)
    return None, {}

def normalise_target(target):
    """Ensure target has a scheme."""
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target.rstrip("/")

def extract_hostname(target):
    return urllib.parse.urlparse(target).hostname or target

# ---------------------------------------------------------------------------
# Output accumulator
# ---------------------------------------------------------------------------

class Report:
    def __init__(self):
        self.sections = {}

    def add(self, section, data):
        self.sections.setdefault(section, [])
        if isinstance(data, list):
            self.sections[section].extend(data)
        else:
            self.sections[section].append(data)

    def to_json(self):
        return json.dumps(self.sections, indent=2)

# ---------------------------------------------------------------------------
# Module 1 — Technology Fingerprinting
# ---------------------------------------------------------------------------

_JS_FRAMEWORKS = {
    "React":   ["react", "react-dom", "reactjs"],
    "Vue.js":  ["vue.js", "vue.min.js", "vuejs"],
    "Angular": ["angular.js", "angular.min.js", "ng-version"],
    "jQuery":  ["jquery", "jquery.min.js", "jquery-"],
    "Next.js": ["_next/static", "__next"],
    "Nuxt.js": ["_nuxt/", "__nuxt"],
    "Svelte":  ["svelte"],
    "Ember":   ["ember.js", "ember.min.js"],
    "Backbone":["backbone.js", "backbone-min.js"],
}

_CMS_SIGNATURES = {
    "WordPress":  ["wp-content", "wp-includes", "wp-json"],
    "Joomla":     ["Joomla!", "/components/com_", "/modules/mod_"],
    "Drupal":     ["sites/all/modules", "Drupal.settings", "/core/misc/drupal"],
    "Magento":    ["Mage.Cookies", "skin/frontend", "/mage/"],
    "Shopify":    ["cdn.shopify.com", "Shopify.theme"],
    "PrestaShop": ["prestashop", "/themes/default-bootstrap/"],
    "TYPO3":      ["typo3", "TYPO3 CMS"],
    "Ghost":      ["ghost/api", "/content/themes/"],
    "Wix":        ["wix.com", "_wix_"],
    "Squarespace":["squarespace.com", "sqsp"],
}

_CDN_HEADERS = {
    "Cloudflare": ["cf-ray", "cf-cache-status", "server: cloudflare"],
    "Akamai":     ["x-check-cacheable", "x-akamai-", "akamai-origin-hop"],
    "Fastly":     ["x-served-by", "x-cache: HIT, HIT", "fastly-"],
    "Varnish":    ["x-varnish", "via: varnish"],
    "Sucuri":     ["x-sucuri-id", "x-sucuri-cache"],
    "AWS CloudFront": ["x-amz-cf-id", "x-amz-cf-pop"],
    "Azure CDN":  ["x-azure-ref", "x-msedge-ref"],
    "BunnyCDN":   ["cdn-pullzone", "cdn-uid"],
}

_WAF_SIGNATURES = {
    "Cloudflare WAF":   ["cf-ray", "server: cloudflare"],
    "Sucuri WAF":       ["x-sucuri-id"],
    "Incapsula":        ["x-iinfo", "incap_ses"],
    "ModSecurity":      ["mod_security", "modsecurity"],
    "F5 BIG-IP":        ["x-wa-info", "bigipserver"],
    "Barracuda":        ["bni-persistence"],
    "Fortinet":         ["x-fw-", "fortigate"],
    "AWS WAF":          ["x-amzn-requestid", "awswaf"],
    "Wordfence":        ["x-wordfence-", "wordfence"],
}

class MetaParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.generator = None
        self.scripts = []

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == "meta" and attrs_dict.get("name", "").lower() == "generator":
            self.generator = attrs_dict.get("content", "")
        if tag == "script":
            src = attrs_dict.get("src", "")
            if src:
                self.scripts.append(src.lower())


def module_tech(target, timeout, ua, report, verbose=True):
    print(f"\n{BOLD}{CYAN}[*] Technology Fingerprinting — {target}{RESET}")
    results = {}

    try:
        status, headers, body = http_get(target, timeout=timeout, ua=ua)
    except Exception as e:
        print(f"  {RED}[!] Request failed: {e}{RESET}")
        report.add("tech", {"error": str(e)})
        return

    headers_lower = {k.lower(): v for k, v in headers.items()}
    body_lower = body.lower()

    # --- Web server
    server = headers_lower.get("server", "")
    powered = headers_lower.get("x-powered-by", "")
    results["Server"]     = server or "(not disclosed)"
    results["X-Powered-By"] = powered or "(not disclosed)"

    # --- CMS via meta generator
    parser = MetaParser()
    parser.feed(body)
    if parser.generator:
        results["Generator (meta)"] = parser.generator

    # --- CMS via body patterns
    detected_cms = []
    for cms, sigs in _CMS_SIGNATURES.items():
        if any(s.lower() in body_lower for s in sigs):
            detected_cms.append(cms)
    results["CMS"] = ", ".join(detected_cms) if detected_cms else "Unknown"

    # --- JS Frameworks
    detected_js = []
    scripts_concat = " ".join(parser.scripts)
    for fw, sigs in _JS_FRAMEWORKS.items():
        if any(s in body_lower or s in scripts_concat for s in sigs):
            detected_js.append(fw)
    results["JS Frameworks"] = ", ".join(detected_js) if detected_js else "None detected"

    # --- CDN
    detected_cdn = []
    for cdn, sigs in _CDN_HEADERS.items():
        if any(s.lower() in body_lower or s.lower() in " ".join(f"{k}: {v}".lower() for k, v in headers.items()) for s in sigs):
            detected_cdn.append(cdn)
    results["CDN"] = ", ".join(detected_cdn) if detected_cdn else "None detected"

    # --- WAF
    detected_waf = []
    header_str = " ".join(f"{k}: {v}".lower() for k, v in headers.items())
    for waf, sigs in _WAF_SIGNATURES.items():
        if any(s.lower() in header_str or s.lower() in body_lower for s in sigs):
            detected_waf.append(waf)
    results["WAF"] = ", ".join(detected_waf) if detected_waf else "None detected"

    # --- Interesting security headers
    sec_hdrs = {}
    for h in ["strict-transport-security", "content-security-policy",
              "x-frame-options", "x-content-type-options",
              "referrer-policy", "permissions-policy"]:
        sec_hdrs[h] = headers_lower.get(h, c("MISSING", RED))
    results["Security Headers"] = sec_hdrs

    # --- Print table
    col = 26
    print(f"  {'Key':<{col}} Value")
    print(f"  {'-'*col} {'-'*40}")
    for k, v in results.items():
        if k == "Security Headers":
            print(f"  {c('Security Headers:', YELLOW)}")
            for hk, hv in v.items():
                status_col = GREEN if hv and "MISSING" not in hv else RED
                print(f"    {hk:<40} {c(hv, status_col)}")
        else:
            val_col = GREEN if v not in ("Unknown", "None detected", "(not disclosed)") else GREY
            print(f"  {BOLD}{k:<{col}}{RESET} {c(v, val_col)}")

    report.add("tech", results)


# ---------------------------------------------------------------------------
# Module 2 — Directory / Path Brute-force
# ---------------------------------------------------------------------------

BUILTIN_PATHS = [
    "/admin", "/admin/", "/login", "/login.php", "/wp-admin", "/wp-admin/",
    "/wp-login.php", "/phpmyadmin", "/phpmyadmin/", "/pma/",
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/swagger", "/swagger-ui.html", "/swagger-ui/", "/api-docs", "/openapi.json",
    "/.env", "/.env.backup", "/.env.local", "/.env.production",
    "/.git/HEAD", "/.git/config", "/.svn/entries",
    "/backup", "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/db.sql", "/dump.sql", "/database.sql",
    "/config", "/config.yml", "/config.json", "/config.php", "/configuration.php",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/security.txt", "/.well-known/security.txt",
    "/server-status", "/server-info", "/.htaccess", "/.htpasswd",
    "/index.php", "/info.php", "/phpinfo.php", "/test.php",
    "/console", "/manager", "/manager/html",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/mappings",
    "/metrics", "/health", "/status", "/version",
    "/upload", "/uploads", "/files", "/static", "/assets", "/media",
    "/cgi-bin/", "/cgi-bin/admin.cgi",
    "/admin.php", "/admin.html", "/admin/login",
    "/user", "/users", "/register", "/signup", "/forgot-password",
    "/shell", "/shell.php", "/cmd.php",
    "/debug", "/trace", "/test", "/demo",
    "/old", "/bak", "/bak/", "/old/", "/archive",
    "/logs", "/log", "/error.log", "/access.log",
    "/readme.txt", "/README.md", "/CHANGELOG.md", "/INSTALL.txt",
    "/license.txt", "/LICENSE",
    "/wp-content/debug.log", "/wp-json/wp/v2/users",
    "/xmlrpc.php", "/feed", "/rss", "/atom",
    "/.DS_Store", "/Thumbs.db", "/web.config",
    "/graphql", "/graphiql", "/playground",
    "/jenkins", "/jenkins/login",
    "/.well-known/openid-configuration",
]

INTERESTING_CODES = {200, 301, 302, 307, 308, 403, 401}


def _probe_path(base, path, timeout, ua, delay=0.0, retry=1):
    if delay > 0:
        time.sleep(delay)
    url = base + path
    code, headers = http_head(url, timeout=timeout, ua=ua, retry=retry)
    return path, code, headers, url


def module_dirs(target, timeout, ua, report, threads=10, extra_wordlist=None,
                delay=0.0, retry=1):
    print(f"\n{BOLD}{CYAN}[*] Directory Brute-force — {target}{RESET}")

    paths = list(BUILTIN_PATHS)
    if extra_wordlist:
        try:
            with open(extra_wordlist, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    p = line.strip()
                    if p and not p.startswith("#"):
                        paths.append("/" + p.lstrip("/"))
            print(f"  {GREY}[+] Loaded extra wordlist: {extra_wordlist} ({len(paths)} total paths){RESET}")
        except Exception as e:
            print(f"  {YELLOW}[!] Could not load wordlist: {e}{RESET}")

    found = []
    lock = threading.Lock()

    code_colours = {
        200: GREEN, 201: GREEN, 204: GREEN,
        301: CYAN,  302: CYAN,  307: CYAN,  308: CYAN,
        401: YELLOW, 403: YELLOW,
    }

    def worker(path):
        p, code, hdrs, url = _probe_path(target, path, timeout, ua,
                                          delay=delay, retry=retry)
        if code and code in INTERESTING_CODES:
            colour = code_colours.get(code, WHITE)
            redirect = hdrs.get("Location", "") if code in (301, 302, 307, 308) else ""
            with lock:
                found.append({"path": p, "code": code, "url": url, "redirect": redirect})
                redirect_str = f" → {redirect}" if redirect else ""
                print(f"  {c(str(code), colour)}  {url}{c(redirect_str, GREY)}")

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = [ex.submit(worker, p) for p in paths]
        for f in as_completed(futures):
            pass  # results printed in worker

    if not found:
        print(f"  {GREY}No interesting paths found.{RESET}")
    else:
        print(f"\n  {GREEN}Found {len(found)} interesting path(s).{RESET}")

    report.add("dirs", found)


# ---------------------------------------------------------------------------
# Module 3 — Email Harvesting
# ---------------------------------------------------------------------------

EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
)
COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)


def _harvest_from(url, timeout, ua):
    emails = set()
    try:
        _, _, body = http_get(url, timeout=timeout, ua=ua)
        emails.update(EMAIL_RE.findall(body))
        # Also search inside HTML comments
        for comment in COMMENT_RE.findall(body):
            emails.update(EMAIL_RE.findall(comment))
    except Exception:
        pass
    return emails


def module_emails(target, timeout, ua, report):
    print(f"\n{BOLD}{CYAN}[*] Email Harvesting — {target}{RESET}")
    hostname = extract_hostname(target)

    urls = [
        target,
        target + "/robots.txt",
        target + "/sitemap.xml",
        target + "/contact",
        target + "/about",
        target + "/impressum",
    ]

    all_emails = set()
    for url in urls:
        found = _harvest_from(url, timeout, ua)
        all_emails.update(found)

    # Filter obvious false positives (e.g. example@schematics)
    filtered = sorted(e for e in all_emails if "." in e.split("@")[1])

    if filtered:
        print(f"  {GREEN}Found {len(filtered)} email(s):{RESET}")
        for em in filtered:
            print(f"    {CYAN}{em}{RESET}")
    else:
        print(f"  {GREY}No email addresses found.{RESET}")

    report.add("emails", filtered)


# ---------------------------------------------------------------------------
# Module 4 — DNS Enumeration
# ---------------------------------------------------------------------------

def _dns_query(hostname, qtype):
    """
    Lightweight DNS resolver using standard library socket where possible,
    falls back to calling `nslookup` for record types Python does not expose.
    """
    import subprocess
    results = []
    try:
        if qtype == "A":
            for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
                ip = info[4][0]
                if ip not in results:
                    results.append(ip)
        elif qtype == "AAAA":
            for info in socket.getaddrinfo(hostname, None, socket.AF_INET6):
                ip = info[4][0]
                if ip not in results:
                    results.append(ip)
        else:
            # Use nslookup / dig where available
            for cmd in [["nslookup", f"-type={qtype}", hostname],
                        ["dig", "+short", qtype, hostname]]:
                try:
                    out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL,
                                                   timeout=8).decode(errors="replace")
                    if out.strip():
                        results = [line.strip() for line in out.splitlines() if line.strip()]
                        break
                except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
                    continue
    except Exception:
        pass
    return results


def module_dns(target, timeout, ua, report):
    print(f"\n{BOLD}{CYAN}[*] DNS Enumeration — {target}{RESET}")
    hostname = extract_hostname(target)

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    dns_results = {}

    for rtype in record_types:
        records = _dns_query(hostname, rtype)
        dns_results[rtype] = records
        if records:
            print(f"  {BOLD}{rtype:<8}{RESET}", end="")
            for i, r in enumerate(records):
                if i == 0:
                    print(f"  {GREEN}{r}{RESET}")
                else:
                    print(f"  {' '*8}  {GREEN}{r}{RESET}")
        else:
            print(f"  {BOLD}{rtype:<8}{RESET}  {GREY}(none){RESET}")

    # SPF check
    txt_records = dns_results.get("TXT", [])
    spf = [r for r in txt_records if "v=spf1" in r.lower()]
    print(f"\n  {BOLD}SPF:{RESET}   {GREEN + spf[0] + RESET if spf else c('Not configured', YELLOW)}")

    # DMARC
    dmarc_host = f"_dmarc.{hostname}"
    dmarc_recs = _dns_query(dmarc_host, "TXT")
    dmarc_val = next((r for r in dmarc_recs if "v=dmarc1" in r.lower()), None)
    print(f"  {BOLD}DMARC:{RESET} {GREEN + dmarc_val + RESET if dmarc_val else c('Not configured (_dmarc not found)', YELLOW)}")

    # DKIM (default selector)
    dkim_host = f"default._domainkey.{hostname}"
    dkim_recs = _dns_query(dkim_host, "TXT")
    dkim_val = next((r for r in dkim_recs if "v=dkim1" in r.lower()), None)
    if dkim_val:
        print(f"  {BOLD}DKIM:{RESET}  {GREEN}{dkim_val[:80]}...{RESET}")
    else:
        print(f"  {BOLD}DKIM:{RESET}  {GREY}default._domainkey not found (selector unknown){RESET}")

    dns_results["SPF"] = spf
    dns_results["DMARC"] = dmarc_val or ""
    dns_results["DKIM_default"] = dkim_val or ""
    report.add("dns", dns_results)


# ---------------------------------------------------------------------------
# Module 5 — Wayback Machine
# ---------------------------------------------------------------------------

WAYBACK_AVAIL  = "http://archive.org/wayback/available?url={}"
WAYBACK_CDX    = "http://web.archive.org/cdx/search/cdx?url={}/*&output=text&limit=20&fl=timestamp,statuscode,original&filter=statuscode:200"


def module_wayback(target, timeout, ua, report):
    print(f"\n{BOLD}{CYAN}[*] Wayback Machine — {target}{RESET}")
    clean = target.lstrip("https://").lstrip("http://")

    # Snapshot availability
    avail_url = WAYBACK_AVAIL.format(urllib.parse.quote(clean))
    try:
        _, _, body = http_get(avail_url, timeout=timeout, ua=ua)
        data = json.loads(body)
        snap = data.get("archived_snapshots", {}).get("closest", {})
        if snap:
            ts   = snap.get("timestamp", "")
            surl = snap.get("url", "")
            avail = snap.get("available", False)
            dt = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]} {ts[8:10]}:{ts[10:12]}" if len(ts) >= 12 else ts
            print(f"  {GREEN}Snapshot available: {dt}  →  {surl}{RESET}")
            report.add("wayback", {"latest_snapshot": surl, "timestamp": ts})
        else:
            print(f"  {YELLOW}No snapshot found for {clean}{RESET}")
            report.add("wayback", {"latest_snapshot": None})
    except Exception as e:
        print(f"  {RED}[!] Availability check failed: {e}{RESET}")

    # CDX — historical URLs
    cdx_url = WAYBACK_CDX.format(urllib.parse.quote(clean))
    print(f"\n  {GREY}Fetching CDX index (up to 20 URLs)...{RESET}")
    try:
        _, _, body = http_get(cdx_url, timeout=timeout, ua=ua)
        lines = [l.strip() for l in body.splitlines() if l.strip()]
        if lines:
            print(f"  {BOLD}{'Timestamp':<18} {'Code':<6} URL{RESET}")
            print(f"  {'-'*17} {'-'*5} {'-'*50}")
            urls_found = []
            for line in lines[:20]:
                parts = line.split(" ", 2)
                if len(parts) == 3:
                    ts, code, orig = parts
                    dt = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
                    col = GREEN if code == "200" else YELLOW
                    print(f"  {GREY}{dt:<18}{RESET} {c(code, col):<6} {orig}")
                    urls_found.append({"timestamp": ts, "code": code, "url": orig})
            report.add("wayback", {"historical_urls": urls_found})
        else:
            print(f"  {GREY}No archived URLs found in CDX.{RESET}")
    except Exception as e:
        print(f"  {RED}[!] CDX query failed: {e}{RESET}")


# ---------------------------------------------------------------------------
# Module 6 — SSL/TLS Certificate Analysis
# ---------------------------------------------------------------------------

def _parse_x509_name(name_dict):
    """Return a dict of RDN components from ssl peer cert name tuple-of-tuples."""
    result = {}
    for rdn in name_dict:
        for key, value in rdn:
            result[key] = value
    return result

def _get_cert_sans(cert):
    """Extract Subject Alternative Names from ssl peer cert dict."""
    sans = []
    for ext_type, ext_values in cert.get("subjectAltName", []):
        if ext_type == "DNS":
            sans.append(ext_values)
    return sans

def _cert_date_to_dt(date_str):
    """Convert ssl module's certificate date string to datetime (UTC)."""
    # Format: 'May 15 12:00:00 2025 GMT'
    try:
        return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except Exception:
        return None

def module_ssl(target, timeout, ua, report):
    print(f"\n{BOLD}{CYAN}[*] SSL/TLS Certificate Analysis — {target}{RESET}")
    hostname = extract_hostname(target)
    findings = []
    result = {"hostname": hostname}

    try:
        ctx = ssl.create_default_context()
        # We want to inspect even if something is wrong → wrap with check_hostname=False
        # but first try the proper way
        conn = ctx.wrap_socket(
            socket.create_connection((hostname, 443), timeout=timeout),
            server_hostname=hostname,
        )
    except ssl.SSLCertVerificationError as e:
        # Still try to get cert info with verification disabled
        print(f"  {YELLOW}[!] SSL verification failed ({e.reason}), retrying without verification for inspection...{RESET}")
        ctx_noverify = ssl.create_default_context()
        ctx_noverify.check_hostname = False
        ctx_noverify.verify_mode = ssl.CERT_NONE
        try:
            conn = ctx_noverify.wrap_socket(
                socket.create_connection((hostname, 443), timeout=timeout),
                server_hostname=hostname,
            )
            findings.append({"severity": "HIGH", "issue": f"SSL verification failed: {e.reason}"})
        except Exception as e2:
            print(f"  {RED}[!] Could not connect to port 443: {e2}{RESET}")
            report.add("ssl", {"error": str(e2)})
            return
    except Exception as e:
        print(f"  {RED}[!] Could not connect to port 443: {e}{RESET}")
        report.add("ssl", {"error": str(e)})
        return

    try:
        cert = conn.getpeercert()
        tls_version = conn.version()
        cipher_name, tls_proto, key_bits = conn.cipher()
    finally:
        conn.close()

    # --- Subject
    subject = _parse_x509_name(cert.get("subject", ()))
    cn = subject.get("commonName", "(none)")
    result["subject_cn"] = cn

    # --- Issuer
    issuer = _parse_x509_name(cert.get("issuer", ()))
    issuer_cn = issuer.get("commonName", "(none)")
    issuer_org = issuer.get("organizationName", "")
    result["issuer_cn"] = issuer_cn
    result["issuer_org"] = issuer_org

    # --- SANs
    sans = _get_cert_sans(cert)
    result["sans"] = sans

    # --- Validity
    not_before_str = cert.get("notBefore", "")
    not_after_str  = cert.get("notAfter", "")
    not_before = _cert_date_to_dt(not_before_str)
    not_after  = _cert_date_to_dt(not_after_str)
    result["not_before"] = not_before_str
    result["not_after"]  = not_after_str

    now = datetime.now(timezone.utc)
    if not_after:
        days_left = (not_after - now).days
        result["days_until_expiry"] = days_left
        if days_left < 0:
            findings.append({"severity": "HIGH",
                             "issue": f"Certificate EXPIRED {abs(days_left)} day(s) ago"})
        elif days_left <= 30:
            findings.append({"severity": "MEDIUM",
                             "issue": f"Certificate expires in {days_left} day(s)"})

    # --- Self-signed check
    is_self_signed = (subject == issuer)
    result["self_signed"] = is_self_signed
    if is_self_signed:
        findings.append({"severity": "HIGH", "issue": "Self-signed certificate"})

    # --- TLS version and cipher
    result["tls_version"] = tls_version
    result["cipher"] = cipher_name
    result["cipher_bits"] = key_bits

    # Weak TLS
    if tls_version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        findings.append({"severity": "HIGH",
                         "issue": f"Weak TLS version in use: {tls_version}"})

    result["findings"] = findings

    # --- Print
    col = 24
    print(f"  {BOLD}{'TLS Version':<{col}}{RESET} {GREEN if tls_version in ('TLSv1.2','TLSv1.3') else YELLOW}{tls_version}{RESET}")
    print(f"  {BOLD}{'Cipher':<{col}}{RESET} {cipher_name} ({key_bits} bit)")
    print(f"  {BOLD}{'Subject CN':<{col}}{RESET} {cn}")
    print(f"  {BOLD}{'Issuer':<{col}}{RESET} {issuer_cn}{f' / {issuer_org}' if issuer_org else ''}")
    print(f"  {BOLD}{'Valid From':<{col}}{RESET} {not_before_str}")

    days_col = RED if not_after and days_left < 0 else (YELLOW if not_after and days_left <= 30 else GREEN)
    print(f"  {BOLD}{'Valid Until':<{col}}{RESET} {c(not_after_str, days_col)}{f'  ({days_left}d left)' if not_after else ''}")

    if is_self_signed:
        print(f"  {BOLD}{'Self-Signed':<{col}}{RESET} {c('YES', RED)}")

    if sans:
        print(f"  {BOLD}SANs ({len(sans)}):{RESET}")
        for san in sans:
            print(f"    {CYAN}{san}{RESET}")
    else:
        print(f"  {BOLD}{'SANs':<{col}}{RESET} {GREY}(none){RESET}")

    if findings:
        print(f"\n  {BOLD}{YELLOW}Findings:{RESET}")
        for f in findings:
            sev_col = RED if f["severity"] == "HIGH" else YELLOW
            print(f"    [{c(f['severity'], sev_col)}] {f['issue']}")
    else:
        print(f"\n  {GREEN}No certificate issues detected.{RESET}")

    report.add("ssl", result)


# ---------------------------------------------------------------------------
# Module 7 — Secret / Credential Detection
# ---------------------------------------------------------------------------

# (key_label, compiled_regex, description)
_SECRET_PATTERNS = [
    ("AWS Access Key",
     re.compile(r"AKIA[0-9A-Z]{16}"),
     "AWS IAM access key"),
    ("GitHub Token (ghp_)",
     re.compile(r"ghp_[a-zA-Z0-9]{36}"),
     "GitHub personal access token"),
    ("GitHub Token (github_pat_)",
     re.compile(r"github_pat_[a-zA-Z0-9_]{82}"),
     "GitHub fine-grained PAT"),
    ("API Key / Token",
     re.compile(r"(?:api[_\-]?key|apikey|token|secret)\s*[=:\"'`]\s*([a-zA-Z0-9_\-]{32,})",
                re.IGNORECASE),
     "Generic API key or token"),
    ("Private Key Header",
     re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
     "PEM private key block"),
    ("DB Connection String",
     re.compile(r"(?:mysql|postgresql|mongodb)://[^:@\s]+:[^@\s]+@[^\s\"'<>]+",
                re.IGNORECASE),
     "Database connection string with credentials"),
    ("Basic Auth in URL",
     re.compile(r"https?://[^:@\s/]+:[^@\s/]+@[^\s\"'<>]+"),
     "HTTP Basic auth credentials embedded in URL"),
]

class _ScriptSrcParser(HTMLParser):
    """Collect absolute and relative script src URLs from HTML."""
    def __init__(self):
        super().__init__()
        self.srcs = []

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            for name, val in attrs:
                if name == "src" and val:
                    self.srcs.append(val)

def _absolute_url(base, href):
    return urllib.parse.urljoin(base, href)

def _scan_for_secrets(content, source_label):
    """Scan text content for secrets. Returns list of finding dicts."""
    found = []
    for name, pattern, desc in _SECRET_PATTERNS:
        for m in pattern.finditer(content):
            snippet = m.group(0)[:60].replace("\n", " ")
            found.append({
                "type": name,
                "description": desc,
                "source": source_label,
                "snippet": snippet,
            })
    return found

def module_secrets(target, timeout, ua, report):
    print(f"\n{BOLD}{CYAN}[*] Secret / Credential Detection — {target}{RESET}")
    all_findings = []

    # --- Pages to always check
    urls_to_scan = [
        (target,              "homepage"),
        (target + "/robots.txt", "robots.txt"),
        (target + "/api",     "/api"),
        (target + "/config",  "/config"),
    ]

    # --- Fetch homepage to find JS files
    js_urls_found = []
    try:
        _, _, homepage_body = http_get(target, timeout=timeout, ua=ua)
        parser = _ScriptSrcParser()
        parser.feed(homepage_body)
        js_srcs = []
        for src in parser.srcs:
            abs_src = _absolute_url(target, src)
            # Only include JS on the same host or relative paths
            parsed_src = urllib.parse.urlparse(abs_src)
            parsed_tgt = urllib.parse.urlparse(target)
            if parsed_src.hostname == parsed_tgt.hostname and abs_src.endswith(".js"):
                js_srcs.append(abs_src)
        js_urls_found = js_srcs[:3]  # max 3
    except Exception:
        pass

    for js_url in js_urls_found:
        urls_to_scan.append((js_url, f"JS:{js_url.split('/')[-1]}"))

    # --- Scan each URL
    for url, label in urls_to_scan:
        try:
            status, _, body = http_get(url, timeout=timeout, ua=ua)
            if status and status < 400 and body:
                hits = _scan_for_secrets(body, label)
                all_findings.extend(hits)
                if hits:
                    print(f"  {YELLOW}[{label}] {len(hits)} finding(s){RESET}")
                else:
                    print(f"  {GREY}[{label}] {status} — clean{RESET}")
            else:
                print(f"  {GREY}[{label}] {status} — skipped{RESET}")
        except Exception as e:
            print(f"  {GREY}[{label}] error: {e}{RESET}")

    # --- Print findings
    if all_findings:
        print(f"\n  {RED}{BOLD}[!] {len(all_findings)} potential secret(s) found:{RESET}")
        for finding in all_findings:
            sev_col = RED
            print(f"    {c('[' + finding['type'] + ']', sev_col)}")
            print(f"      Source  : {finding['source']}")
            print(f"      Snippet : {finding['snippet']}")
    else:
        print(f"\n  {GREEN}No secrets detected in scanned resources.{RESET}")

    report.add("secrets", all_findings)


# ---------------------------------------------------------------------------
# Module 8 — Subdomain Enumeration
# ---------------------------------------------------------------------------

_COMMON_SUBDOMAINS = [
    "www", "api", "mail", "smtp", "ftp", "admin", "dev", "staging", "test",
    "beta", "app", "mobile", "cdn", "static", "assets", "media", "img",
    "login", "auth", "sso", "vpn", "remote", "gateway", "proxy", "backend",
    "dashboard", "panel", "portal", "status", "monitor", "metrics", "docs",
    "wiki", "git", "gitlab", "jenkins", "jira", "confluence", "pop3", "imap",
    "ns1", "ns2", "ns3", "mx", "webmail", "shop", "store", "blog", "forum",
    "support", "help", "cdn2", "s3", "files", "download", "smtp2",
]

def _dns_axfr(ns_host, domain, timeout=5):
    """
    Attempt a DNS zone transfer (AXFR) against ns_host for domain.
    Uses raw socket to send a minimal AXFR query (RFC 5936).
    Returns list of discovered names (may be empty on refusal).
    """
    results = []
    try:
        # Build minimal DNS AXFR request
        # Header: ID=0x1337, QR=0, OPCODE=0, QDCOUNT=1
        tid = 0x1337
        flags = 0x0000
        qdcount = 1
        ancount = arcount = nscount = 0
        header = struct.pack(">HHHHHH", tid, flags, qdcount, ancount, nscount, arcount)

        # Question: <domain> QTYPE=252 (AXFR) QCLASS=1 (IN)
        qname = b""
        for label in domain.split("."):
            enc = label.encode()
            qname += bytes([len(enc)]) + enc
        qname += b"\x00"
        question = qname + struct.pack(">HH", 252, 1)  # AXFR, IN

        payload = header + question
        # DNS over TCP: 2-byte length prefix
        tcp_msg = struct.pack(">H", len(payload)) + payload

        with socket.create_connection((ns_host, 53), timeout=timeout) as sock:
            sock.sendall(tcp_msg)
            # Read responses (may come in multiple messages)
            raw = b""
            for _ in range(20):  # read up to 20 chunks
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    raw += chunk
                except Exception:
                    break

        # Parse names from the raw response — look for label sequences
        # We scan for printable ASCII domain name patterns rather than
        # full DNS parsing to stay stdlib-only.
        name_re = re.compile(rb"[\x01-\x3f]([\w\-]+)")
        for m in name_re.finditer(raw):
            label = m.group(1).decode("ascii", errors="ignore")
            if label and len(label) > 1:
                candidate = f"{label}.{domain}"
                if candidate not in results:
                    results.append(candidate)
    except Exception:
        pass
    return results

def module_subdomains(target, timeout, ua, report):
    print(f"\n{BOLD}{CYAN}[*] Subdomain Enumeration — {target}{RESET}")
    hostname = extract_hostname(target)

    # Strip leading www. to get base domain
    base_domain = hostname
    if base_domain.startswith("www."):
        base_domain = base_domain[4:]

    # Resolve main domain IP for comparison
    main_ips = set()
    try:
        main_ips = {info[4][0] for info in socket.getaddrinfo(hostname, None, socket.AF_INET)}
    except Exception:
        pass

    found_subs = []
    lock = threading.Lock()

    def check_subdomain(sub):
        fqdn = f"{sub}.{base_domain}"
        try:
            _, _, ips_info = socket.gethostbyname_ex(fqdn)
            resolved_ips = set(ips_info) if ips_info else set()
            # gethostbyname_ex returns (hostname, aliases, ipaddrlist)
            # but signature is (name, aliaslist, addresslist)
        except Exception:
            return

        if not resolved_ips:
            return

        is_different_ip = bool(resolved_ips - main_ips) if main_ips else False
        entry = {
            "subdomain": fqdn,
            "ips": list(resolved_ips),
            "different_ip": is_different_ip,
        }
        with lock:
            found_subs.append(entry)
            diff_tag = c(" [different IP]", YELLOW) if is_different_ip else ""
            ips_str = ", ".join(sorted(resolved_ips))
            print(f"  {GREEN}{fqdn:<45}{RESET} {GREY}{ips_str}{RESET}{diff_tag}")

    # Fix: gethostbyname_ex returns (hostname, aliaslist, addresslist)
    def check_subdomain_fixed(sub):
        fqdn = f"{sub}.{base_domain}"
        try:
            name, aliases, addresslist = socket.gethostbyname_ex(fqdn)
            resolved_ips = set(addresslist)
        except Exception:
            return

        if not resolved_ips:
            return

        is_different_ip = bool(resolved_ips - main_ips) if main_ips else False
        entry = {
            "subdomain": fqdn,
            "ips": list(resolved_ips),
            "different_ip": is_different_ip,
        }
        with lock:
            found_subs.append(entry)
            diff_tag = c(" [different IP]", YELLOW) if is_different_ip else ""
            ips_str = ", ".join(sorted(resolved_ips))
            print(f"  {GREEN}{fqdn:<45}{RESET} {GREY}{ips_str}{RESET}{diff_tag}")

    print(f"  {GREY}Testing {len(_COMMON_SUBDOMAINS)} common subdomains...{RESET}")
    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = [ex.submit(check_subdomain_fixed, sub) for sub in _COMMON_SUBDOMAINS]
        for f in as_completed(futures):
            pass

    # --- DNS Zone Transfer attempt
    print(f"\n  {GREY}Attempting DNS zone transfer (AXFR) on NS servers...{RESET}")
    ns_records = _dns_query(base_domain, "NS")
    axfr_results = []
    for ns in ns_records:
        ns_clean = ns.rstrip(".").strip()
        # Strip nslookup noise like "nameserver = " prefixes
        if "=" in ns_clean:
            ns_clean = ns_clean.split("=")[-1].strip()
        if not ns_clean or " " in ns_clean:
            continue
        print(f"  {GREY}  AXFR → {ns_clean} ...{RESET}", end=" ", flush=True)
        axfr_names = _dns_axfr(ns_clean, base_domain, timeout=timeout)
        if axfr_names:
            print(f"{RED}POSSIBLE LEAK ({len(axfr_names)} names){RESET}")
            for name in axfr_names[:20]:
                print(f"    {CYAN}{name}{RESET}")
            axfr_results.extend(axfr_names)
        else:
            print(f"{GREEN}refused/empty{RESET}")

    if found_subs:
        print(f"\n  {GREEN}Found {len(found_subs)} live subdomain(s).{RESET}")
    else:
        print(f"\n  {GREY}No subdomains resolved.{RESET}")

    report.add("subdomains", {
        "base_domain": base_domain,
        "found": found_subs,
        "axfr_names": axfr_results,
    })


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        prog="recon.py",
        description="Web Application Reconnaissance Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python recon.py example.com --all
  python recon.py https://example.com --tech --dns --ssl
  python recon.py example.com --dirs --threads 20 --timeout 5
  python recon.py example.com --all --json --out results.json
  python recon.py example.com --dirs --wordlist /path/to/wordlist.txt
  python recon.py example.com --modules ssl,secrets,subdomains
  python recon.py example.com --all --proxy http://127.0.0.1:8080
  python recon.py example.com --dirs --delay 0.5 --retry 3
        """,
    )
    p.add_argument("target", help="Target URL or hostname")
    p.add_argument("--tech",       action="store_true", help="Technology fingerprinting")
    p.add_argument("--dirs",       action="store_true", help="Directory brute-force")
    p.add_argument("--emails",     action="store_true", help="Email harvesting")
    p.add_argument("--dns",        action="store_true", help="DNS enumeration")
    p.add_argument("--wayback",    action="store_true", help="Wayback Machine lookup")
    p.add_argument("--ssl",        action="store_true", help="SSL/TLS certificate analysis")
    p.add_argument("--secrets",    action="store_true", help="Secret/credential detection")
    p.add_argument("--subdomains", action="store_true", help="Subdomain enumeration")
    p.add_argument("--all",        action="store_true", help="Run all modules")
    p.add_argument("--modules",    metavar="M1,M2,...",
                   help="Comma-separated module list: tech,dirs,emails,dns,wayback,ssl,secrets,subdomains")
    p.add_argument("--threads",    type=int, default=10, metavar="N",  help="Concurrent threads (default: 10)")
    p.add_argument("--timeout",    type=int, default=8,  metavar="N",  help="HTTP timeout seconds (default: 8)")
    p.add_argument("--user-agent", default=DEFAULT_UA, metavar="STR", help="Custom User-Agent string")
    p.add_argument("--delay",      type=float, default=0.0, metavar="FLOAT",
                   help="Delay in seconds between requests in --dirs (default: 0)")
    p.add_argument("--retry",      type=int, default=1, metavar="INT",
                   help="Number of retries on timeout (default: 1)")
    p.add_argument("--proxy",      metavar="URL",
                   help="Proxy URL, e.g. http://127.0.0.1:8080")
    p.add_argument("--json",       action="store_true", help="Output results as JSON")
    p.add_argument("--out",        metavar="FILE",  help="Save output to file")
    p.add_argument("--wordlist",   metavar="FILE",  help="Extra directory wordlist")
    return p.parse_args()


def main():
    banner()
    args = parse_args()

    # --- Proxy setup (must happen before any requests)
    if args.proxy:
        setup_proxy(args.proxy)
        print(f"  {YELLOW}[*] Proxy: {args.proxy}{RESET}")

    target = normalise_target(args.target)
    report = Report()

    # Meta
    report.add("meta", {
        "target": target,
        "scan_time": datetime.utcnow().isoformat() + "Z",
        "modules": [],
    })

    run_all = args.all
    ua = args.user_agent

    # --- Resolve --modules flag into individual booleans
    selected_modules = set()
    if args.modules:
        for m in args.modules.split(","):
            selected_modules.add(m.strip().lower())

    def want(name):
        return run_all or getattr(args, name, False) or name in selected_modules

    print(f"  {BOLD}Target  :{RESET} {CYAN}{target}{RESET}")
    print(f"  {BOLD}Threads :{RESET} {args.threads}")
    print(f"  {BOLD}Timeout :{RESET} {args.timeout}s")
    if args.delay > 0:
        print(f"  {BOLD}Delay   :{RESET} {args.delay}s between requests")
    if args.retry > 1:
        print(f"  {BOLD}Retry   :{RESET} {args.retry} attempts on timeout")
    print(f"  {BOLD}Started :{RESET} {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")

    if want("tech"):
        module_tech(target, args.timeout, ua, report)
        report.sections["meta"][0]["modules"].append("tech")

    if want("dns"):
        module_dns(target, args.timeout, ua, report)
        report.sections["meta"][0]["modules"].append("dns")

    if want("ssl"):
        module_ssl(target, args.timeout, ua, report)
        report.sections["meta"][0]["modules"].append("ssl")

    if want("emails"):
        module_emails(target, args.timeout, ua, report)
        report.sections["meta"][0]["modules"].append("emails")

    if want("secrets"):
        module_secrets(target, args.timeout, ua, report)
        report.sections["meta"][0]["modules"].append("secrets")

    if want("subdomains"):
        module_subdomains(target, args.timeout, ua, report)
        report.sections["meta"][0]["modules"].append("subdomains")

    if want("dirs"):
        module_dirs(target, args.timeout, ua, report,
                    threads=args.threads, extra_wordlist=args.wordlist,
                    delay=args.delay, retry=args.retry)
        report.sections["meta"][0]["modules"].append("dirs")

    if want("wayback"):
        module_wayback(target, args.timeout, ua, report)
        report.sections["meta"][0]["modules"].append("wayback")

    if not report.sections["meta"][0]["modules"]:
        print(f"\n  {YELLOW}[!] No module selected. Use --all or specify a module.{RESET}")
        print(f"  {GREY}    Run `python recon.py --help` for usage.{RESET}\n")
        sys.exit(0)

    print(f"\n{BOLD}{CYAN}[*] Scan complete.{RESET}\n")

    if args.json:
        output = report.to_json()
        print(output)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(output)
            print(f"\n  {GREEN}Results saved to {args.out}{RESET}")
    elif args.out:
        # Save plain summary
        lines = [f"# web-recon-toolkit — {target}",
                 f"# Scan: {datetime.utcnow().isoformat()}Z", ""]
        for section, items in report.sections.items():
            lines.append(f"[{section.upper()}]")
            for item in items:
                lines.append(f"  {json.dumps(item)}")
            lines.append("")
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        print(f"\n  {GREEN}Results saved to {args.out}{RESET}")


if __name__ == "__main__":
    main()
