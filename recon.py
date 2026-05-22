#!/usr/bin/env python3
"""
web-recon-toolkit — Comprehensive Web Application Reconnaissance Tool
For penetration testers and security researchers.

Usage:
    python recon.py <target> [--tech] [--dirs] [--emails] [--dns] [--wayback] [--all]
                             [--threads N] [--timeout N] [--user-agent STR]
                             [--json] [--out FILE] [--wordlist FILE]

Author  : G4MEOVER18
License : MIT
"""

import sys
import re
import json
import socket
import argparse
import threading
import urllib.request
import urllib.error
import urllib.parse
from html.parser import HTMLParser
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

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

def http_get(url, timeout=8, ua=DEFAULT_UA, allow_redirects=True):
    """Perform a GET request. Returns (status_code, headers_dict, body_str) or raises."""
    req = urllib.request.Request(url, headers={"User-Agent": ua})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            headers = dict(resp.headers)
            return resp.status, headers, body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return e.code, dict(e.headers) if e.headers else {}, body

def http_head(url, timeout=8, ua=DEFAULT_UA):
    """Perform a HEAD request. Returns status_code or None on error."""
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": ua})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers) if e.headers else {}
    except Exception:
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


def _probe_path(base, path, timeout, ua):
    url = base + path
    code, headers = http_head(url, timeout=timeout, ua=ua)
    return path, code, headers, url


def module_dirs(target, timeout, ua, report, threads=10, extra_wordlist=None):
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
        p, code, hdrs, url = _probe_path(target, path, timeout, ua)
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
  python recon.py https://example.com --tech --dns
  python recon.py example.com --dirs --threads 20 --timeout 5
  python recon.py example.com --all --json --out results.json
  python recon.py example.com --dirs --wordlist /path/to/wordlist.txt
        """,
    )
    p.add_argument("target", help="Target URL or hostname")
    p.add_argument("--tech",     action="store_true", help="Technology fingerprinting")
    p.add_argument("--dirs",     action="store_true", help="Directory brute-force")
    p.add_argument("--emails",   action="store_true", help="Email harvesting")
    p.add_argument("--dns",      action="store_true", help="DNS enumeration")
    p.add_argument("--wayback",  action="store_true", help="Wayback Machine lookup")
    p.add_argument("--all",      action="store_true", help="Run all modules")
    p.add_argument("--threads",  type=int, default=10, metavar="N",  help="Concurrent threads (default: 10)")
    p.add_argument("--timeout",  type=int, default=8,  metavar="N",  help="HTTP timeout seconds (default: 8)")
    p.add_argument("--user-agent", default=DEFAULT_UA, metavar="STR", help="Custom User-Agent string")
    p.add_argument("--json",     action="store_true", help="Output results as JSON")
    p.add_argument("--out",      metavar="FILE",  help="Save output to file")
    p.add_argument("--wordlist", metavar="FILE",  help="Extra directory wordlist")
    return p.parse_args()


def main():
    banner()
    args = parse_args()

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

    print(f"  {BOLD}Target  :{RESET} {CYAN}{target}{RESET}")
    print(f"  {BOLD}Threads :{RESET} {args.threads}")
    print(f"  {BOLD}Timeout :{RESET} {args.timeout}s")
    print(f"  {BOLD}Started :{RESET} {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")

    if run_all or args.tech:
        module_tech(target, args.timeout, ua, report)
        report.sections["meta"][0]["modules"].append("tech")

    if run_all or args.dns:
        module_dns(target, args.timeout, ua, report)
        report.sections["meta"][0]["modules"].append("dns")

    if run_all or args.emails:
        module_emails(target, args.timeout, ua, report)
        report.sections["meta"][0]["modules"].append("emails")

    if run_all or args.dirs:
        module_dirs(target, args.timeout, ua, report,
                    threads=args.threads, extra_wordlist=args.wordlist)
        report.sections["meta"][0]["modules"].append("dirs")

    if run_all or args.wayback:
        module_wayback(target, args.timeout, ua, report)
        report.sections["meta"][0]["modules"].append("wayback")

    if not any([run_all, args.tech, args.dirs, args.emails, args.dns, args.wayback]):
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
