# fingerprint.py — Passive Web Fingerprinting (Bug Bounty Recon, First Step)

Passive web fingerprinting tool for a bug bounty hunter. Run it on a target as the
first step of recon: it reports the web stack, proxies, security posture, discovery
exposure and (optionally) HTTP method behavior. By default all checks are passive
(plain GETs) — nothing is sent to change the target.

## Usage

```bash
python fingerprint.py https://example.com              # text output
python fingerprint.py https://example.com --json       # JSON output
python fingerprint.py https://example.com --output fp.json
python fingerprint.py https://example.com --quiet --output fp.json
python fingerprint.py https://example.com --active     # adds HEAD/OPTIONS/PUT/DELETE probes
python fingerprint.py https://example.com --timeout 15
```

## What it checks

**Default (passive)**

- Response headers of the main page and of a random 404 path
- Sitemap status: `/sitemap.xml`, `/sitemap_index.xml`, `/sitemap-index.xml`
- Favicon MD5 hash
- Source inspection of the main page:
  - meta generator, `/wp-content/plugins/<name>/`, `/wp-content/themes/<name>/`
  - CDN library versions from `name@version` tokens (e.g. `bootstrap@5.3.2`)
  - Generic framework signatures (Django, Rails, Laravel, Vue, React, …)
- WAF / reverse-proxy fingerprinting from headers/cookies (Cloudflare, Sucuri,
  Cloudbric, Incapsula, ModSecurity, Akamai, Distil, AWS WAF, Azure Front Door…)
- Reverse proxy / CDN fingerprinting (Cloudflare, CloudFront, Fastly, Google
  Frontend, Vercel, Netlify, Heroku, GitHub Pages…)
- Security-headers audit: present (with values) + absent lists
  (HSTS, CSP, X-Frame-Options, Expect-CT, …)
- Error-page signatures: GET `/500`, `/error`, `/404` — bodies matched against
  PHP/Python/Django/ASP.NET/Rails/Laravel/Java/Apache/IIS/generic stack traces
- Passive discovery endpoints (notable statuses only): `/.git/HEAD`, `/.git/config`,
  `/.git/packed-refs`, `/config.php`, `/configuration.php`, `/wp-config.php`,
  `/application.ini`, `/.env`, `/.htaccess`, `/server-status`, `/status`, `/health`
- Host hints: `*.github.io` → "GitHub Pages"

**With `--active`**

- `HEAD`, `OPTIONS` on the target root
- `PUT`, `DELETE` on the target root

## Output (text)

```
=== Fingerprint: https://example.com ===
[main] GET https://example.com/ -> 200
         server: nginx
         tech: Bootstrap
         sec-headers (ABSENT): Content-Security-Policy, ...
[404]  GET https://example.com/fp-xk3j9z2qwak -> 404
         server: nginx
[sitemap] /sitemap-index.xml=200, /sitemap.xml=200, /sitemap_index.xml=200
[favicon] md5=1b04361150c55167a11994310a1c612a
[discovery] /.git/HEAD=200, /config.php=200, ...
[active] DELETE=200, HEAD=200, OPTIONS=200, PUT=200
```

## Output (JSON)

Top-level keys:

- `target`, `main` (`url`, `status`, `headers`, `meta_generator`, `wp_assets`,
  `library_versions`, `body_signatures`, `waf`, `proxy`, `security_headers`),
  `notfound`, `sitemap`, `favicon_md5`, `waf`, `proxy`, `security_headers`,
  `error_pages` (`[{path, status, signatures}]`), `discovery` (`[{path, status}]`),
  `host_hints`, `active_probes` (only with `--active`)

## Notes for hunters

- Start with the tool output: anything it flags (stack traces, `.env`, git metadata,
  absent security headers) is a candidate for further checks.
- `security_headers.absent` often hints at the stack vintage (e.g., no HSTS on a modern stack).
- Random 404 token (`fp-xxxx`) lets you spot a WAF: main 200 but random 404 blocked.
