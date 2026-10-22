# HeaderHawk — Project Report

**Course:** Web Application Security / Cyber Security  
**Year:** B.Tech, Third Year  
**Project Title:** HeaderHawk — Automated Website Security Header & CORS Scanner  
**Language & Framework:** Python 3.10+, Flask  
**Dependencies:** Flask ≥ 3.0, Requests ≥ 2.31  

---

## Abstract

HeaderHawk is a single-file Flask web application that performs automated,
read-only audits of HTTP security response headers and Cross-Origin Resource
Sharing (CORS) configurations on publicly accessible websites. The tool
accepts a URL, validates it against a multi-layer SSRF-prevention policy,
issues two HTTP requests (one standard, one with a controlled `Origin`
header), inspects the response headers, classifies each finding by severity,
and presents a colour-coded dashboard with per-finding explanations and
remediation guidance. A heuristic A–F grade and 0–100 score give an
at-a-glance indication of a site's header hygiene. The project demonstrates
practical knowledge of secure HTTP design, OWASP Secure Headers guidelines,
SSRF mitigations, safe HTTP client usage, Flask development, and Python unit
testing using `unittest.mock`.

---

## 1. Introduction

Modern web browsers honour a set of HTTP response headers that restrict what
a web page may load, where it may be framed, how much referrer information
it may leak, and which device features it may access. When these headers are
absent or misconfigured, the attack surface of an application is meaningfully
wider — even when the underlying code contains no bugs.

Despite being simple one-line server configurations, security headers are
routinely missing in production deployments. The OWASP Secure Headers Project
catalogues these headers and their recommended values; independent surveys
consistently show that a large fraction of publicly accessible websites do not
set them.

HeaderHawk was designed to make this class of misconfiguration visible,
explainable, and actionable for a developer or student audience, while
demonstrating responsible scanning practices.

---

## 2. Problem Statement

Developers and students often need to quickly assess whether a web server has
been configured with basic HTTP security hardening. Existing tools (browser
extensions, online scanners) either require a network round-trip to a
third-party service, provide no explanation of findings, or are too complex
for a learning context.

Simultaneously, any tool that makes outbound HTTP requests on behalf of a
user must be careful not to introduce Server-Side Request Forgery (SSRF)
vulnerabilities — where an attacker tricks the server into issuing requests
to internal infrastructure.

The problem is therefore two-sided:

1. Build an accessible, educational scanner that explains HTTP security
   headers and CORS misconfigurations.
2. Do so without introducing SSRF, proxy bypass, or other security weaknesses
   in the scanner itself.

---

## 3. Objectives

1. Accept a URL from the user and perform a preliminary security-header audit.
2. Implement a multi-layer SSRF prevention policy covering scheme, hostname,
   IP address (including IPv4-mapped IPv6), and per-hop redirect validation.
3. Probe CORS configuration using a controlled, clearly documented probe origin.
4. Classify findings by severity (HIGH / MEDIUM / LOW / INFO) with context-aware
   adjustment (e.g. HSTS severity is downgraded when scanned over plain HTTP).
5. Derive a heuristic 0–100 score using the *effective* finding severity so that
   the displayed badge and the numeric score always agree.
6. Present results in a responsive, dark-themed cybersecurity dashboard with
   expandable per-finding detail panels.
7. Provide a `POST /api/scan` JSON endpoint with strict input validation.
8. Offer a Demo Mode that produces illustrative sample results without making
   any network request.
9. Embed a fully deterministic 73-test unit suite in the same file using only
   Python's standard library (`unittest`, `unittest.mock`).
10. Keep the entire application — logic, routes, HTML/CSS/JS, and tests — in
    a single file (`app.py`) for ease of review and submission.

---

## 4. Methodology

### 4.1 Security Headers Inspected

| Header | Catalog Severity | Attack Mitigated |
|--------|-----------------|-----------------|
| `Strict-Transport-Security` | HIGH (HTTPS) / MEDIUM (HTTP) | Protocol-downgrade, MITM |
| `Content-Security-Policy` | HIGH | Cross-site scripting (XSS) |
| `X-Content-Type-Options` | MEDIUM | MIME-sniffing attacks |
| `X-Frame-Options` | MEDIUM | Clickjacking |
| `Referrer-Policy` | LOW | Referrer information leakage |
| `Permissions-Policy` | LOW | Unrestricted browser feature access |

HSTS is only enforceable by browsers over HTTPS. When a scan is performed
over plain HTTP, the absence of HSTS is reported as MEDIUM rather than HIGH,
and the score deducts accordingly — so the displayed severity badge and the
numeric deduction always agree.

### 4.2 CORS Testing Approach

A second GET request is issued with the `Origin` request header set to
`https://cors-probe.headerhawk.test` — a syntactically valid but non-routable
domain that clearly signals test intent. The response is examined for:

- `Access-Control-Allow-Origin: *` — wildcard, acceptable for public APIs only
- Verbatim origin reflection — indicates dynamic allowlisting
- `Access-Control-Allow-Credentials: true` combined with reflection — HIGH risk
- `Access-Control-Allow-Credentials: true` combined with wildcard — broken config
- Missing `Vary: Origin` when ACAO is present — CDN cache-poisoning risk

Every finding includes the disclaimer: *"These observations indicate a possible
misconfiguration. They are NOT proof of exploitability."*

### 4.3 SSRF Prevention

SSRF is prevented across five layers:

| Layer | Mechanism |
|-------|-----------|
| Scheme | Only `http://` and `https://` are accepted |
| URL credentials | Embedded `user:pass@host` rejected in initial URL and every redirect |
| Hostname blocklist | `localhost`, `broadcasthost`, `*.local`, `*.internal` rejected before DNS |
| IP check | All resolved addresses checked with `addr.is_global`; BLOCKED_NETWORKS as defence-in-depth; IPv4-mapped IPv6 unwrapped first |
| Per-hop redirect | Every redirect destination re-validated through the full policy |

The `requests.Session` is created with `trust_env=False` to prevent
environment-derived proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`, `~/.netrc`)
from routing scanner traffic through an uncontrolled proxy.

**Documented limitation:** DNS-rebinding attacks cannot be prevented by
application-layer DNS-time checks alone. A hostname that resolves to a global
IP at validation time could resolve to a private IP at connection time.
Network-level egress controls are required in production.

### 4.4 Bounded Response Reading

Responses are opened with `stream=True`. The `_drain_response()` function
iterates `resp.iter_content(chunk_size=8192)`, counts bytes, and stops at
`MAX_RESPONSE_BYTES` (512 KB). Every response object is closed in a
`try/finally` block regardless of success, redirect, or exception. The body
is never parsed — only headers are examined.

### 4.5 Scoring Algorithm

The heuristic score starts at 100 and applies weighted deductions:

| Condition | Deduction |
|-----------|-----------|
| Missing HIGH header | 20 pts |
| Missing MEDIUM header | 12 pts |
| Missing LOW header | 6 pts |
| Header present but quality issue | 5 pts |
| CORS severity HIGH | 20 pts |
| CORS severity MEDIUM | 10 pts |
| CORS severity LOW | 4 pts |

Deductions use `f["severity"]` (the effective, context-adjusted severity) not
the catalog default — ensuring HSTS over HTTP deducts 12 pts (MEDIUM) rather
than 20 pts (HIGH).

Grade thresholds: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F < 40.

---

## 5. System Architecture

```
┌─────────────────────────────────── app.py ──────────────────────────────────┐
│                                                                              │
│  ┌──────────────────┐    ┌──────────────────────────────────────────────┐   │
│  │   Flask Routes   │    │             Validation Layer                  │   │
│  │  GET  /          │───▶│  validate_url()  — scheme, credentials,      │   │
│  │  POST /scan      │    │                    blocklist, DNS             │   │
│  │  GET  /demo      │    │  _check_hostname() — DNS + is_global          │   │
│  │  POST /api/scan  │    │  _is_blocked_ip()  — is_global + networks     │   │
│  └───────┬──────────┘    │  _validate_redirect_url() — per-hop policy   │   │
│          │               └────────────────────┬─────────────────────────┘   │
│          │                                    ▼                             │
│          │               ┌──────────────────────────────────────────────┐   │
│          │               │           _safe_fetch()                       │   │
│          │               │  Session(trust_env=False)                     │   │
│          │               │  Manual redirect loop (max 5 hops)            │   │
│          │               │  _drain_response() — bounded read + close     │   │
│          │               └────────────────────┬─────────────────────────┘   │
│          │                                    ▼                             │
│          │               ┌──────────────────────────────────────────────┐   │
│          │               │           Scanner Engine                      │   │
│          │               │  analyze_headers(scheme-aware)                │   │
│          │               │  _check_header_quality()                      │   │
│          │               │  analyze_cors()                               │   │
│          │               │  calculate_score() — effective severity       │   │
│          │               └────────────────────┬─────────────────────────┘   │
│          └────────────────────────────────────▼                             │
│                          ┌──────────────────────────────────────────────┐   │
│                          │  HTML_TEMPLATE  (Jinja2 + CSS + JS inline)   │   │
│                          └──────────────────────────────────────────────┘   │
│                                                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  TestHeaderHawk  (unittest — 73 deterministic tests, no network I/O) │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Implementation

### 6.1 Key Functions

| Function | Responsibility |
|----------|---------------|
| `validate_url()` | Scheme, credential, hostname, and IP validation for initial URL |
| `_check_hostname()` | DNS resolution; blocks any non-globally-routable address |
| `_is_blocked_ip()` | `is_global` primary check; `BLOCKED_NETWORKS` secondary check; IPv4-mapped IPv6 unwrap |
| `_validate_redirect_url()` | Full URL policy applied to each redirect destination |
| `_safe_fetch()` | Session with `trust_env=False`; manual redirect loop; re-validation per hop |
| `_drain_response()` | Bounded body consumption (≤ 512 KB); guaranteed close |
| `analyze_headers()` | Case-insensitive header detection; HSTS scheme-awareness |
| `_check_header_quality()` | Value-level checks for present headers |
| `analyze_cors()` | Five CORS checks; disclaimer on all findings |
| `calculate_score()` | Effective-severity deductions; heuristic grade |
| `build_scan_result()` | Assembles final result dict from two Response objects |
| `get_demo_result()` | Returns hardcoded illustrative data; zero network I/O |
| `api_scan()` | Strict JSON body and field-type validation before processing |

### 6.2 Flask Routes

| Route | Method | Description |
|-------|--------|-------------|
| `/` | GET | Renders main page (empty state) |
| `/scan` | POST | Validates URL, performs scan, renders results |
| `/demo` | GET | Returns labelled illustrative sample results |
| `/api/scan` | POST | JSON API; same scan logic; strict input validation |

### 6.3 Embedded Template

`HTML_TEMPLATE` is a raw string rendered with `render_template_string()`. All
CSS (dark theme, severity badges, responsive grid) and JavaScript (spinner,
expandable detail panels) are inline. No external resources are loaded.

### 6.4 Error Handling

All network errors are caught at the route level:
`ConnectionError`, `Timeout`, `TooManyRedirects`, `RequestException`, and
policy `ValueError`. Users receive plain-English messages; stack traces are
logged only to the server console.

---

## 7. Testing

### 7.1 Test Philosophy

All 73 tests are fully deterministic:
- DNS resolution is patched with `unittest.mock.patch("socket.getaddrinfo", ...)`.
- HTTP responses are replaced with `MagicMock(spec=requests.Response)` objects
  with stubbed `iter_content`, `close`, `status_code`, and `headers`.
- No real network connection is made at any point during the test run.

### 7.2 Test Suite Summary

| Category | Count | What Is Verified |
|----------|-------|-----------------|
| URL validation | 9 | Empty URL, non-HTTP scheme, `file://`, localhost, `.local`, `.internal`, bare hostname, mocked-DNS pass, DNS failure |
| IP restriction | 11 | Loopback, RFC-1918 ranges, link-local, IPv6 loopback, IPv4-mapped IPv6 loopback and private, public IP allowed, mocked DNS private and public |
| Redirect URL policy | 5 | Private IP, embedded credentials, FTP scheme, `.internal` TLD, public URL allowed |
| `_safe_fetch` | 5 | `iter_content` called (not `.content`), response closed after drain, redirect response closed, closure on exception, `_drain_response` byte-limit |
| Security header analysis | 12 | All missing (HTTPS), all passing, case-insensitive detection, HSTS short max-age, HSTS absent over HTTP (MEDIUM not HIGH), HSTS present over HTTP flagged, HSTS absent over HTTPS (HIGH), CSP `unsafe-inline`, `X-Content-Type-Options` wrong value, `X-Frame-Options` invalid, sort order |
| CORS analysis | 5 | Wildcard, reflection + credentials (HIGH), no headers (INFO), missing `Vary`, wildcard + credentials CRITICAL |
| Score / summary | 3 | Perfect score (A ≥ 90), all missing (F < 40), bounds [0, 100] |
| Demo mode | 2 | Structure check, zero network activity |
| API input validation | 6 | Empty body, invalid JSON, array body, missing `url`, non-string `url`, null `url` |
| `_is_blocked_ip` / `is_global` | 10 | Loopback, 10.x, link-local, public IPv4 allowed, IPv6 loopback, IPv4-mapped loopback, IPv4-mapped private, mixed DNS rejected, all-public DNS allowed, redirect via `is_global` |
| Scoring consistency | 2 | HTTP vs HTTPS HSTS deduction delta (8 pts), HTTPS HSTS HIGH = 20-pt deduction |
| Severity helper | 1 | `_upgrade_severity` all cases |
| **Total** | **73** | |

### 7.3 Running the Tests

```bash
python app.py test
```

Actual output from the final version of the file:

```
----------------------------------------------------------------------
Ran 73 tests in 0.036s
OK
```

---

## 8. Results

### 8.1 Scan Output Structure

A live scan produces:
- **Security grade** (A–F) and numeric **score** (0–100)
- **Headers present / missing** counts
- **CORS risk level** (HIGH / MEDIUM / LOW / INFO)
- Per-finding: header name, present/missing status, severity badge, observed
  value, quality note if applicable, expandable explanation and remediation
- CORS section: probe origin, all observed CORS headers, flagged issues,
  disclaimer

### 8.2 Demo Mode Scenario

The Demo Mode (`/demo`) illustrates a typical partially-hardened site:

| Header | Status | Note |
|--------|--------|------|
| `Content-Security-Policy` | Missing | HIGH |
| `Strict-Transport-Security` | Present | LOW — `max-age=3600` < 6 months |
| `X-Content-Type-Options` | Present | INFO — `nosniff` ✓ |
| `X-Frame-Options` | Missing | MEDIUM |
| `Referrer-Policy` | Missing | LOW |
| `Permissions-Policy` | Missing | LOW |
| CORS | — | HIGH — origin reflection + credentials |

---

## 9. Security Limitations

These limitations are explicitly documented in the application and communicated
to users on every page.

1. **Header-level audit only.** The tool does not assess authentication, input
   validation, injection vulnerabilities, TLS certificate quality, cookie
   configuration, or server-side logic of any kind.

2. **Single-endpoint snapshot.** Only the submitted URL is scanned. Other paths
   on the same server may have different header configurations.

3. **DNS rebinding.** Pre-request DNS validation reduces SSRF risk but cannot
   eliminate DNS-rebinding attacks. A hostname can legitimately resolve to a
   public IP at scan time and to a private IP at connection time. Production
   deployments require network-layer egress controls.

4. **CORS findings are indicative.** One probe origin is tested. Actual
   exploitability depends on authentication requirements, SameSite cookie
   attributes, and browser enforcement policies.

5. **Heuristic score.** The A–F grade is an educational indicator, not a
   certified security assessment.

6. **No active exploitation.** The tool never attempts to exploit any
   vulnerability, bypass authentication, or download site content.

---

## 10. Future Enhancements

| Enhancement | Rationale |
|-------------|-----------|
| TLS/certificate inspection | Cipher suites, certificate validity, HSTS preload status |
| Cookie attribute scanner | `Secure`, `HttpOnly`, `SameSite` flags |
| Subresource Integrity check | Detect `<script>` tags without SRI hashes |
| Multiple endpoints | Scan a list of paths or a sitemap |
| Historical comparison | SQLite-backed trend tracking |
| Export to PDF / CSV | For submission in security reports |
| Authenticated scanning | Accept session cookies for behind-login pages |
| CI/CD mode | Exit code 1 when findings exceed a severity threshold |
| Rate limiting | Prevent accidental hammering of a single target |

---

## 11. Conclusion

HeaderHawk demonstrates that a meaningful, well-structured security tool can be
built in a single Python file while adhering to responsible-disclosure principles
and SSRF-prevention best practices. The project provides students with hands-on
experience of:

- Why HTTP security headers exist and which attacks they mitigate.
- How CORS works, what misconfigurations look like, and why they are not
  automatically exploitable.
- How to prevent SSRF in server-side HTTP client code.
- How `ipaddress.is_global` provides a stricter and more maintainable IP-
  blocking gate than enumerating individual network ranges.
- How to write a deterministic unit-test suite using `unittest.mock` without
  an additional test framework.
- How to structure a Flask application cleanly in a single file.

The tool is deliberately modest in scope — a *configuration audit*, not a
penetration test — and communicates this boundary clearly to users. This honesty
about limitations is itself an important lesson in responsible security tooling.

---

## References

1. OWASP Secure Headers Project — https://owasp.org/www-project-secure-headers/
2. MDN Web Docs: HTTP Headers — https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
3. RFC 6454 — The Web Origin Concept
4. OWASP CORS Security Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/CORS_Security_Cheat_Sheet.html
5. OWASP SSRF Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
6. Python `ipaddress` module documentation — https://docs.python.org/3/library/ipaddress.html
7. Flask Documentation — https://flask.palletsprojects.com/
8. Requests Library Documentation — https://docs.python-requests.org/
