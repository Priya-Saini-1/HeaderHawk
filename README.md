# HeaderHawk 🦅

**Automated Website Security Header & CORS Scanner**  
*B.Tech Cybersecurity Course Project — Python / Flask*

---

## Overview

HeaderHawk is a single-file Flask web application that performs a
**preliminary HTTP security-header audit** and **CORS configuration probe**
on any publicly accessible website. It accepts a URL, validates it against
SSRF-prevention rules, sends two HTTP requests (one plain, one with a
controlled `Origin` header), inspects the response headers, classifies
findings by severity, and presents a colour-coded dashboard with explanations
and remediation guidance.

> **This is a configuration audit, not a penetration test.**  
> HeaderHawk inspects HTTP response headers only. It does not execute code,
> probe for injection vulnerabilities, attempt authentication bypass, or
> assess any server-side logic. A high score does not mean a site is secure.

---

## Features

| Feature | Detail |
|---------|--------|
| Security header audit | `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy` |
| CORS probe | Injects a controlled `Origin` and inspects `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`, `Vary`, etc. |
| Severity classification | HIGH / MEDIUM / LOW / INFO with per-finding explanations and remediation |
| Heuristic scoring | A–F letter grade and 0–100 score weighted by effective finding severity |
| HSTS scheme-awareness | Missing HSTS over plain HTTP is reported as MEDIUM (not HIGH), because the header is only enforceable over HTTPS |
| SSRF protection | All resolved IP addresses checked via `is_global`; private, loopback, link-local, and reserved ranges blocked; IPv4-mapped IPv6 unwrapped |
| Safe redirect handling | Redirects followed manually (max 5 hops); every destination re-validated; embedded credentials in redirect URLs rejected |
| Bounded response reading | At most 512 KB read per response; every response explicitly closed |
| Proxy isolation | `trust_env=False` prevents environment-derived proxy variables from bypassing SSRF controls |
| API input validation | `/api/scan` validates JSON body type, presence and type of the `url` field before any processing |
| Demo mode | Illustrative sample results with zero network activity |
| JSON API | `POST /api/scan` for programmatic use |
| Single-file design | All logic, routes, HTML/CSS/JS template, and tests in `app.py` |

---

## Project Structure

```
.
├── app.py            # Complete application (all logic + UI + tests)
├── requirements.txt  # Third-party dependencies only
├── README.md         # This file
├── PROJECT_REPORT.md # Academic course-project report
└── .gitignore
```

---

## Technologies Used

| Component | Library / Version |
|-----------|------------------|
| Web framework | Flask ≥ 3.0, < 4.0 |
| HTTP client | Requests ≥ 2.31, < 3.0 |
| IP validation | Python standard library — `ipaddress` |
| URL parsing | Python standard library — `urllib.parse` |
| Unit testing | Python standard library — `unittest` / `unittest.mock` |

No database, frontend build tool, or additional runtime dependency is required.

---

## Prerequisites

- Python **3.10 or later** (type-union syntax `X | Y` is used)
- `pip`

---

## Installation

```bash
# 1. Clone or download the repository
git clone https://github.com/<your-username>/headerhawk.git
cd headerhawk

# 2. Create and activate a virtual environment (recommended)
python -m venv .venv

# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## Running the Application

```bash
python app.py
```

The development server starts on **http://127.0.0.1:5000**.  
Open that address in your browser. The application does not bind to any
external interface by default.

---

## Usage

### Web Interface

1. Open **http://127.0.0.1:5000**.
2. Enter a publicly accessible URL, e.g. `https://example.com`.
3. Click **🔍 Scan**.
4. Review:
   - **Summary cards** — security grade, score, headers present/missing, CORS risk level.
   - **Security Header Findings table** — status, severity badge, header value, quality note.
   - Click **▶ Show** on any row to expand a full explanation and remediation steps.
   - **CORS Configuration Analysis** — probe origin used, headers observed, identified issues.

### Demo Mode

Click **🧪 Demo** (or navigate to `/demo`) to load illustrative sample results.
**No network request is made.** The demo shows a mixed scenario — some headers
missing, one with a weak value, and a HIGH-severity CORS misconfiguration — to
demonstrate what the output looks like.

---

## API Endpoint — `POST /api/scan`

Returns the full scan result as JSON. Useful for scripting or integration.

### Request

```
POST /api/scan
Content-Type: application/json

{
  "url": "https://example.com"
}
```

**Validation rules (400 is returned if any fails):**

| Condition | Error message |
|-----------|---------------|
| Empty body | `"Request body is empty..."` |
| Invalid JSON | `"Request body is not valid JSON."` |
| Body is not a JSON object | `"Request body must be a JSON object..."` |
| `url` field missing | `"Missing required field: 'url'."` |
| `url` is not a string | `"Field 'url' must be a string."` |
| URL fails validation | Specific validation error message |

### Example using curl

```bash
curl -s -X POST http://127.0.0.1:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}' | python -m json.tool
```

### Response structure (200 OK)

```json
{
  "url": "https://example.com",
  "timestamp": "2024-01-15T10:30:00+00:00",
  "status_code": 200,
  "server": "ECS (dcb/7F84)",
  "is_demo": false,
  "summary": {
    "score": 32,
    "grade": "F",
    "label": "Critical",
    "color": "#dc2626",
    "headers_checked": 6,
    "headers_missing": 5,
    "headers_present": 1,
    "quality_issues": 0,
    "cors_severity": "INFO"
  },
  "header_findings": [
    {
      "header": "Content-Security-Policy",
      "present": false,
      "value": "",
      "severity": "HIGH",
      "description": "...",
      "remediation": "...",
      "reference": "https://developer.mozilla.org/...",
      "quality_note": "",
      "category": "Security Header"
    }
  ],
  "cors_finding": {
    "category": "CORS",
    "probe_origin": "https://cors-probe.headerhawk.test",
    "headers_observed": {},
    "issues": ["Server did not return Access-Control-Allow-Origin..."],
    "severity": "INFO",
    "disclaimer": "These observations indicate a possible misconfiguration..."
  }
}
```

### Error response (400 Bad Request)

```json
{
  "error": "Only HTTP and HTTPS URLs are supported."
}
```

---

## Running the Tests

All 73 unit tests are embedded in `app.py` and use Python's built-in
`unittest` and `unittest.mock` frameworks. No additional test runner is needed.

```bash
python app.py test
```

Expected output:

```
test_all_headers_missing_over_https ... ok
test_all_headers_present_good_values ... ok
...
----------------------------------------------------------------------
Ran 73 tests in 0.0Xs
OK
```

**All tests are fully deterministic.** DNS resolution is patched via
`unittest.mock.patch`; HTTP responses are replaced with mock objects.
No real network connections are made during testing.

### Test categories

| Category | Tests |
|----------|-------|
| URL validation (scheme, credentials, blocklists) | 9 |
| IP restriction — raw IPs and mocked DNS | 11 |
| Redirect URL policy | 5 |
| `_safe_fetch` — bounded read, closure | 5 |
| Security header analysis | 12 |
| CORS analysis | 5 |
| Score / summary calculation | 3 |
| Demo mode | 2 |
| API input validation | 6 |
| `_is_blocked_ip` / `is_global` checks | 10 |
| Severity helper | 1 |
| Scoring consistency (HSTS HTTP vs HTTPS) | 2 |
| Redirect via `is_global` | 1 |
| **Total** | **73** |

---

## Security Limitations

HeaderHawk is designed for educational use. Be aware of these constraints:

1. **Headers only.** The tool does not assess authentication, session
   management, input validation, SQL injection, TLS certificate quality,
   server-side logic, or any other security dimension.

2. **Single-endpoint snapshot.** Only the root URL is scanned. Headers may
   differ across endpoints, authenticated pages, or user-agent strings.

3. **DNS rebinding.** The SSRF pre-check resolves DNS at validation time.
   A hostname that resolves to a global IP at validation time could
   theoretically resolve to a private IP at connection time. Network-level
   egress controls (firewall rules) are required to fully eliminate this risk
   in production; this tool cannot.

4. **CORS results are indicative, not conclusive.** A single probe origin is
   used. Actual exploitability depends on authentication mechanisms, SameSite
   cookie attributes, and browser security policies outside the scope of a
   header scan.

5. **Score is heuristic.** The A–F grade is an educational indicator, not a
   certified security rating.

6. **Authorised targets only.** Only scan websites you own or have explicit
   written permission to test. Unauthorised scanning may violate applicable
   computer misuse laws.

---

## Suggested Screenshots (for Report / Presentation)

> *Screenshots are not included in the repository. Capture them while running
> the app locally.*

- **Home page** — URL input form with disclaimer visible
- **Scan result — passing site** — summary cards showing grade A/B, all headers present
- **Scan result — failing site** — grade D/F, several HIGH findings, expanded detail panel
- **CORS misconfiguration** — HIGH-severity CORS card with reflected-origin issue
- **Demo mode** — banner clearly marked DEMO, mixed findings
- **Error state** — invalid URL or private-IP rejection message
- **Terminal** — `python app.py test` output showing 73 tests OK

---

## GitHub Setup

```bash
git init
git remote add origin https://github.com/<your-username>/headerhawk.git
git add app.py requirements.txt README.md PROJECT_REPORT.md .gitignore
git commit -m "Initial commit: HeaderHawk security header scanner"
git branch -M main
git push -u origin main
```

---

## License

MIT — for academic and educational use only.
