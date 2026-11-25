#!/usr/bin/env python3
"""Passive web fingerprinting for bug bounty recon.

Usage:
    python fingerprint.py https://example.com [--json] [--output FILE]

Default (passive) checks:
  - response headers of the main page and of a random 404 path
  - sitemap status (/sitemap.xml, /sitemap_index.xml, /sitemap-index.xml)
  - source inspection of the main page: meta generator, WP plugins/themes,
    library versions from CDN links, favicon MD5 hash, generic tech signatures
  - WAF / reverse-proxy fingerprinting (headers + cookies)
  - security headers audit (present and absent)
  - error page signatures (403/500/etc.)
  - passive discovery endpoints (.git/HEAD, configs, env files)

With --active (opt-in):
  - HEAD, OPTIONS, PUT, DELETE probes against the target root
"""

import argparse
import hashlib
import json
import random
import re
import string
import sys
import urllib.parse

try:
    import requests
except ImportError:
    requests = None

from urllib.error import HTTPError
from urllib.request import Request, urlopen

TIMEOUT = 10
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
      "AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/120.0.0.0 Safari/537.36 BB-Fingerprint/1.0")


def fetch(url, timeout=TIMEOUT, method="GET"):
    """GET/HEAD/etc url -> {url, status, headers, body} or None on failure."""
    try:
        if requests is not None:
            r = requests.request(method, url, timeout=timeout,
                                 allow_redirects=True,
                                 headers={"User-Agent": UA})
            return {
                "url": str(r.url),
                "status": r.status_code,
                "headers": {k.lower(): v for k, v in r.headers.items()},
                "body": r.content or b"",
            }
        req = Request(url, headers={"User-Agent": UA}, method=method)
        try:
            with urlopen(req, timeout=timeout) as resp:
                return {
                    "url": resp.geturl(),
                    "status": resp.status,
                    "headers": {k.lower(): v for k, v in resp.headers.items()},
                    "body": resp.read() or b"",
                }
        except HTTPError as e:
            headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
            body = e.read() if e.fp is not None else b""
            return {"url": url, "status": e.code, "headers": headers, "body": body or b""}
    except Exception:
        return None


def body_text(resp):
    if not resp or not resp["body"]:
        return ""
    for enc in ("utf-8", "latin-1"):
        try:
            return resp["body"].decode(enc, errors="replace")
        except Exception:
            continue
    return ""


def header_report(resp):
    """The interesting response headers for fingerprinting."""
    out = {}
    if not resp:
        return out
    h = resp["headers"]
    for k in ("server", "x-powered-by", "x-aspnet-version", "x-generator", "via",
              "x-cache", "x-server", "set-cookie", "server-timing"):
        if k in h:
            v = h[k]
            out[k] = [c.split("=")[0] for c in v.split(",")] if k == "set-cookie" else v
    return out


def header_value(resp, name):
    if not resp:
        return ""
    return resp["headers"].get(name, "")


def meta_generator(text):
    m = re.search(r'<meta[^>]+(?:name|property)\s*=\s*["\']generator["\'][^>]+content\s*=\s*["\']([^"\']+)', text, re.I)
    if not m:
        m = re.search(r'<meta[^>]+content\s*=\s*["\']([^"\']+)["\'][^>]+(?:name|property)\s*=\s*["\']generator["\']', text, re.I)
    if not m:
        m = re.search(r'<meta[^>]+generator="([^"]+)"', text, re.I)
    return m.group(1) if m else None


def wp_assets(text):
    """WordPress plugin/theme names pulled from /wp-content/plugins/<name>/ and /wp-content/themes/<name>/."""
    return sorted({m.group(1) for m in re.finditer(r'/wp-content/(?:plugins|themes)/([a-z0-9_-]+)/', text, re.I)})


def library_versions(text):
    """library@version tokens (e.g. /npm/bootstrap@5.3.2/ on a CDN link)."""
    out, seen = [], set()
    for m in re.finditer(r'([a-z0-9][\w.-]*)@(\d+(?:\.\d+){0,3})(?![\d.])', text, re.I):
        key = "%s@%s" % (m.group(1), m.group(2))
        # filter font-variation tokens like "wght@400"
        if key not in seen and not key.split("@")[0].lower().startswith("wght"):
            seen.add(key)
            out.append(key)
    for m in re.finditer(r'([\w.-]*?)(\d+\.\d+\.\d+)[\w.-]*\.min\.js', text):
        name = m.group(1).rstrip(".-_") or m.group(0).split("/")[-1].rsplit(".min.js", 1)[0]
        key = "%s %s" % (name, m.group(2))
        if key not in seen:
            seen.add(key)
            out.append(key)
    return sorted(out)[:20]


BODY_SIGNATURES = [
    ("WordPress", r'wp-content/[a-z0-9-]+/|wp-login\.php|wp-admin/|wp-json/'),
    ("Drupal", r'Drupal|generator" content="Drupal'),
    ("Joomla", r'com_[a-z0-9_-]+|Joomla'),
    ("Laravel", r'laravel'),
    ("Rails", r'[Rr]ails'),
    ("Django", r'Django|csrfmiddlewaretoken'),
    ("Symfony", r'Symfony'),
    ("ASP.NET", r'ASP\.NET|__VIEWSTATE'),
    ("Flask/Werkzeug", r'Werkzeug|flask'),
    ("Ghost", r'ghost'),
    ("phpBB", r'phpBB'),
    ("vBulletin", r'vBulletin'),
    ("Next.js", r'/_next/'),
    ("React", r'react-dom|React\.version'),
    ("Vue.js", r'vue\.js|Vue\.version'),
    ("Angular", r'ng-app|angular-root'),
    ("jQuery", r'jQuery|jquery/'),
    ("jQuery UI", r'jquery-ui'),
    ("Font Awesome", r'font-awesome|FontAwesome'),
    ("Bootstrap", r'bootstrap'),
]


def body_signatures(text):
    return [name for name, pat in BODY_SIGNATURES if re.search(pat, text, re.I)]


# --- WAF / reverse-proxy fingerprinting (passive, header + cookie based) ---

def _all_header_text(resp):
    """Concatenate lowercase header names+values for matching."""
    if not resp:
        return ""
    return " ".join("%s: %s" % (k, v) for k, v in resp["headers"].items()).lower()


WAF_SIGNATURES = [
    ("Cloudflare", [r"server: cloudflare", r"set-cookie.*__cf_", r"set-cookie.*cf_clearance", r"server: github\s+cloudflare"]),
    ("Sucuri", [r"server: sucuri", r"set-cookie.*sucuri"]),
    ("Cloudbric", [r"server: cloudbric"]),
    ("Incapsula", [r"server: incapsula", r"set-cookie.*incapsula_"]),
    ("ModSecurity", [r"modsecurity"]),
    ("Akamai", [r"server: akamai", r"via: akamaigh", r"via: akamai"]),
    ("Distil", [r"server: distil"]),
    ("Azure Front Door", [r"server: azurefrontdoor"]),
    ("AWS WAF (CloudFront)", [r"server: amazon cloudfront", r"set-cookie.*aws-waf"]),
]


def waf_detect(resp):
    """Passive WAF detection from response headers/cookies."""
    out = []
    if not resp:
        return out
    text = _all_header_text(resp)
    for name, pats in WAF_SIGNATURES:
        if any(re.search(p, text) for p in pats):
            out.append(name)
    return sorted(set(out))


PROXY_SIGNATURES = [
    ("Cloudflare", [r"server: cloudflare"]),
    ("CloudFront", [r"server: cloudfront"]),
    ("Fastly", [r"server: fastly", r"via: fastly", r"x-fastly-request-id",
                r"x-fastly-host", r"x-fastly-origin-request-id", r"x-served-by: cache-"]),
    ("Akamai", [r"server: akamaigh", r"via: akamaigh", r"server: akamai"]),
    ("Google Frontend", [r"server: google frontend", r"via: google frontend"]),
    ("Vercel", [r"server: vercel", r"x-vercel-id"]),
    ("Netlify", [r"server: netlify", r"x-nf-"]),
    ("Heroku", [r"server: heroku"]),
    ("GitHub Pages", [r"server: github pages", r"server: github\.com",
                      r"x-github-request-id", r"x-github-edge-region"]),
    ("Azure Front Door", [r"server: azurefrontdoor"]),
    ("Cloudflare Workers", [r"server: cloudflare", r"x-worker"]),
]


def proxy_detect(resp):
    out = []
    if not resp:
        return out
    text = _all_header_text(resp)
    for name, pats in PROXY_SIGNATURES:
        if any(re.search(p, text) for p in pats):
            out.append(name)
    return sorted(set(out))


SECURITY_HEADERS = [
    ("Strict-Transport-Security", True),
    ("Content-Security-Policy", True),
    ("X-Content-Type-Options", True),
    ("X-Frame-Options", True),
    ("Referrer-Policy", True),
    ("Permissions-Policy", True),
    ("X-XSS-Protection", True),
    ("Expect-CT", True),
    ("Cross-Origin-Opener-Policy", True),
    ("Cross-Origin-Embedder-Policy", True),
    ("Cross-Origin-Resource-Policy", True),
    ("X-Permitted-Cross-Domain-Policies", True),
]


def security_headers(resp):
    """Returns (present, absent): present = {name: value(truncated)}, absent = [names]."""
    present, absent = {}, []
    if not resp:
        return {"present": present, "absent": [n for n, _ in SECURITY_HEADERS]}
    for name, _ in SECURITY_HEADERS:
        v = header_value(resp, name.lower())
        if v:
            present[name] = v[:80]
        else:
            absent.append(name)
    return {"present": present, "absent": absent}


ERROR_BODY_PATTERNS = [
    ("PHP stack trace", [r"uncaught error|php fatal error|call to a member function|call to undefined function"]),
    ("Python traceback", [r"traceback \(most recent call last\)"]),
    ("Django debug page", [r"using the urlconf defined|page not found at"]),
    ("ASP.NET error", [r"server error in [a-z]+ application|\.net error page|enable verbose"]),
    ("Rails error", [r"activesupport|couldn't find an appropriate"]),
    ("Laravel error", [r"whoops|invalidargumentexception"]),
    ("Java stack trace", [r"java\.lang\.|noclassdeffounderror|nosuchmethodexception"]),
    ("Apache default error", [r"apache/[0-9.]+ \(unix\)"]),
    ("IIS error", [r"iis|\.net error page"]),
    ("Generic stack trace", [r"^\s*#[0-9]+ "]),
]

ERROR_PATHS = ["/500", "/error", "/404"]


def error_page_signatures(base):
    """Fetch common error paths (GET) and detect stack traces / default pages."""
    out = []
    for path in ERROR_PATHS:
        r = fetch(base + path)
        if not r:
            continue
        text = body_text(r)[:4000]
        found = [name for name, pats in ERROR_BODY_PATTERNS if any(re.search(p, text, re.I | re.M) for p in pats)]
        if found:
            out.append({"path": path, "status": r["status"], "signatures": found})
    return out


DISCOVERY_PATHS = [
    "/.git/HEAD", "/.git/config", "/.git/packed-refs",
    "/config.php", "/configuration.php", "/wp-config.php",
    "/application.ini", "/.env", "/.htaccess",
    "/server-status", "/status", "/health",
]


def discovery_probes(base):
    """Passive GETs of common config/env/vcs endpoints; returns notable statuses."""
    out = []
    for path in DISCOVERY_PATHS:
        r = fetch(base + path)
        if r and r["status"] not in (404, 405, 400):
            out.append({"path": path, "status": r["status"]})
    return out


def host_hints(base):
    """Loose hostname-based hints (e.g. *.github.io)."""
    hints = []
    host = (urllib.parse.urlparse(base).hostname or "").lower()
    if host.endswith(".github.io"):
        hints.append("GitHub Pages (host *.github.io)")
    elif host.endswith(".cloudfront.net"):
        hints.append("CloudFront (host *.cloudfront.net)")
    elif host.endswith(".cloudflare.com"):
        hints.append("Cloudflare (host *.cloudflare.com)")
    return hints


def method_probe(base):
    """Actively probe HEAD/OPTIONS/PUT/DELETE (opt-in --active)."""
    out = {}
    for method in ("HEAD", "OPTIONS"):
        r = fetch(base, method=method)
        if r:
            out[method] = {"status": r["status"]}
    for method in ("PUT", "DELETE"):
        r = fetch(base, method=method)
        if r:
            out[method] = {"status": r["status"]}
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Passive web fingerprinting (main page, 404 page, sitemap, source inspection, WAF/proxy, security headers, errors, discovery).")
    ap.add_argument("target", help="Target URL, e.g. https://example.com")
    ap.add_argument("--json", action="store_true", help="Print JSON instead of text")
    ap.add_argument("--output", help="Write report to this file (text or JSON)")
    ap.add_argument("--quiet", action="store_true", help="Suppress console output (report still printed unless --output is given)")
    ap.add_argument("--timeout", type=int, default=TIMEOUT, help="Request timeout in seconds (default 10)")
    ap.add_argument("--active", action="store_true", help="Also probe HEAD/OPTIONS/PUT/DELETE on the target root")
    args = ap.parse_args(argv)

    base = args.target.strip().rstrip("/")
    main_resp = fetch(base, timeout=args.timeout)
    text = body_text(main_resp)

    notfound_token = "fp-" + "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(12))
    notfound_resp = fetch(base + "/" + notfound_token, timeout=args.timeout)

    sitemap_status = {}
    for sm in ("/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml"):
        r = fetch(base + sm, timeout=args.timeout)
        if r:
            sitemap_status[sm] = r["status"]

    favicon_resp = fetch(base + "/favicon.ico", timeout=args.timeout)
    favicon_md5 = hashlib.md5(favicon_resp["body"]).hexdigest() if (favicon_resp and favicon_resp["body"]) else None

    main_report = {
        "url": main_resp["url"] if main_resp else None,
        "status": main_resp["status"] if main_resp else None,
        "headers": header_report(main_resp),
        "meta_generator": meta_generator(text),
        "wp_assets": wp_assets(text),
        "library_versions": library_versions(text),
        "body_signatures": body_signatures(text),
        "waf": waf_detect(main_resp),
        "proxy": proxy_detect(main_resp),
        "security_headers": security_headers(main_resp),
    }
    notfound_report = {
        "url_probe": base + "/" + notfound_token,
        "status": notfound_resp["status"] if notfound_resp else None,
        "headers": header_report(notfound_resp),
        "waf": waf_detect(notfound_resp),
        "note": ("random path returned %s (not 404)" % notfound_resp["status"])
                if (notfound_resp and notfound_resp["status"] != 404) else None,
    }

    error_pages = error_page_signatures(base)
    discovery = discovery_probes(base)
    active = method_probe(base) if args.active else {}

    report = {
        "target": base,
        "main": main_report,
        "notfound": notfound_report,
        "sitemap": sitemap_status,
        "favicon_md5": favicon_md5,
        "waf": main_report["waf"] or notfound_report["waf"],
        "proxy": main_report["proxy"],
        "security_headers": main_report["security_headers"],
        "error_pages": error_pages,
        "discovery": discovery,
        "host_hints": host_hints(base),
    }
    if active:
        report["active_probes"] = active

    if args.json or (args.output and args.output.endswith(".json")):
        payload = json.dumps(report, indent=2)
    else:
        payload = render_text(report)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(payload + "\n")
    if not args.quiet:
        print(payload)
    return 0


def render_text(report):
    lines = []
    m = report["main"]
    nf = report["notfound"]
    lines.append("=== Fingerprint: %s ===" % report["target"])
    lines.append("[main] GET %s -> %s" % (m["url"], m["status"]))
    for k, v in sorted(m["headers"].items()):
        lines.append("         %s: %s" % (k, v))
    if m["meta_generator"]:
        lines.append("         meta generator: %s" % m["meta_generator"])
    if m["wp_assets"]:
        lines.append("         wp assets: %s" % ", ".join(m["wp_assets"]))
    if m["library_versions"]:
        lines.append("         libs: %s" % ", ".join(m["library_versions"]))
    if m["body_signatures"]:
        lines.append("         tech: %s" % ", ".join(m["body_signatures"]))
    if m["waf"]:
        lines.append("         WAF: %s" % ", ".join(m["waf"]))
    if m["proxy"]:
        lines.append("         proxy/CDN: %s" % ", ".join(m["proxy"]))
    sh = m["security_headers"]
    if sh["present"]:
        lines.append("         sec-headers (present): %s" % ", ".join(
            "%s=%s" % (k, v) for k, v in sorted(sh["present"].items())))
    if sh["absent"]:
        lines.append("         sec-headers (ABSENT): %s" % ", ".join(sorted(sh["absent"])))

    lines.append("[404]  GET %s -> %s" % (nf["url_probe"], nf["status"]))
    for k, v in sorted(nf["headers"].items()):
        lines.append("         %s: %s" % (k, v))
    if nf.get("waf"):
        lines.append("         WAF: %s" % ", ".join(nf["waf"]))
    if nf["note"]:
        lines.append("         NOTE: %s" % nf["note"])

    lines.append("[sitemap] %s" % (", ".join("%s=%s" % kv for kv in sorted(report["sitemap"].items())) or "none found"))
    if report["favicon_md5"]:
        lines.append("[favicon] md5=%s" % report["favicon_md5"])
    if report["host_hints"]:
        lines.append("[host] %s" % ", ".join(report["host_hints"]))
    if report["error_pages"]:
        for e in report["error_pages"]:
            lines.append("[error] %s -> %s (signatures: %s)" % (e["path"], e["status"], ", ".join(e["signatures"])))
    if report["discovery"]:
        lines.append("[discovery] %s" % ", ".join("%s=%s" % (d["path"], d["status"]) for d in report["discovery"]))
    if report.get("active_probes"):
        lines.append("[active] %s" % ", ".join("%s=%s" % (m, d["status"]) for m, d in sorted(report["active_probes"].items())))
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
