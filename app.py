"""
HeaderHawk — Automated Website Security Header & CORS Scanner
=============================================================
A single-file Flask application for a cybersecurity course project.
Scans a target URL for missing/misconfigured HTTP security headers
and common CORS misconfigurations, then presents findings with
severity ratings, explanations, and remediation guidance.

Layout of this file
-------------------
1.  Imports & constants
2.  URL validation & SSRF-safe fetcher
3.  Security-header analysis
4.  CORS analysis
5.  Score / summary calculation
6.  Demo-mode data
7.  Flask application & routes
8.  Embedded HTML/CSS/JS template
9.  Unit tests  (run with:  python app.py test)
10. __main__ entry-point
"""

# ---------------------------------------------------------------------------
# 1. Imports & constants
# ---------------------------------------------------------------------------
import ipaddress
import json
import re
import socket
import sys
import unittest
import unittest.mock
import urllib.parse
from datetime import datetime, timezone

import requests
import requests.structures
from flask import Flask, jsonify, render_template_string, request

# ---- Scanning constants -------------------------------------------------------

# Origin header value we inject for CORS probing.
# Using a clearly fake domain so the intent is unambiguous.
CORS_TEST_ORIGIN = "https://cors-probe.headerhawk.test"

# Maximum bytes we will read from a response body (we never parse the body,
# but requests needs a limit to avoid unlimited memory growth).
MAX_RESPONSE_BYTES = 512 * 1024  # 512 KB

# Network timeouts (connect, read) in seconds.
REQUEST_TIMEOUT = (5, 10)

# Maximum redirects we will follow manually (each hop is re-validated).
MAX_REDIRECTS = 5

# ---- Security-header catalog --------------------------------------------------
# Each entry: key (canonical header name), severity, short reason, remediation.
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "description": (
            "HSTS tells browsers to always use HTTPS for this domain. "
            "Without it, users may connect over plain HTTP and be vulnerable "
            "to protocol-downgrade and man-in-the-middle attacks."
        ),
        "remediation": (
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n"
            "Minimum recommended max-age is 6 months (15768000 seconds)."
        ),
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "description": (
            "CSP restricts which resources (scripts, styles, frames…) a page "
            "may load, dramatically reducing the impact of XSS attacks. "
            "Missing CSP allows injected scripts to run freely."
        ),
        "remediation": (
            "Start with a restrictive policy, e.g.:\n"
            "Content-Security-Policy: default-src 'self'; script-src 'self';\n"
            "Use a CSP evaluator to refine it for your application."
        ),
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "description": (
            "Without this header set to 'nosniff', browsers may interpret "
            "files as a different MIME type, enabling MIME-sniffing attacks "
            "that can turn uploaded text files into executable scripts."
        ),
        "remediation": "Add: X-Content-Type-Options: nosniff",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": (
            "Controls whether this page may be embedded in an iframe. "
            "Without it, attackers can frame the page to perform clickjacking — "
            "tricking users into clicking hidden UI elements."
        ),
        "remediation": (
            "Add: X-Frame-Options: DENY  (or SAMEORIGIN if self-framing is needed).\n"
            "Modern alternative: Content-Security-Policy: frame-ancestors 'none';"
        ),
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": (
            "Controls how much referrer information is included in requests. "
            "Without a policy the browser uses its default, which may leak "
            "full URLs (including query strings with tokens) to third parties."
        ),
        "remediation": (
            "Add: Referrer-Policy: strict-origin-when-cross-origin\n"
            "For high-privacy sites consider: no-referrer"
        ),
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "description": (
            "Allows a site to control which browser features (camera, "
            "microphone, geolocation…) are enabled. Without it, all features "
            "that the browser allows by default remain accessible to the page."
        ),
        "remediation": (
            "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()\n"
            "Disable every feature your site does not use."
        ),
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
    },
}

# Severity order for sorting (higher index = higher severity)
SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "INFO": -1}

# Private / reserved IP ranges that must not be scanned (SSRF guard).
# IPv4-mapped IPv6 addresses (::ffff:0:0/96) are unwrapped to their IPv4
# form before checking, so they are covered by the IPv4 ranges below.
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    # IPv6 reserved ranges
    ipaddress.ip_network("::1/128"),          # loopback
    ipaddress.ip_network("::/128"),           # unspecified
    ipaddress.ip_network("fc00::/7"),         # ULA (private)
    ipaddress.ip_network("fe80::/10"),        # link-local
    ipaddress.ip_network("::ffff:0:0/96"),    # IPv4-mapped (unwrapped separately too)
    ipaddress.ip_network("64:ff9b::/96"),     # IPv4/IPv6 translation
    ipaddress.ip_network("100::/64"),         # discard
]


# ---------------------------------------------------------------------------
# 2. URL validation & SSRF-safe fetcher
# ---------------------------------------------------------------------------

def validate_url(url: str) -> tuple[bool, str]:
    """
    Validate that *url* is a well-formed HTTP/HTTPS URL that does not point
    at a private, loopback, link-local or otherwise reserved address.

    Returns (True, canonical_url) on success or (False, error_message).

    Note: This check resolves DNS at validation time.  It does NOT fully
    eliminate DNS-rebinding risks (where a hostname resolves to a public IP
    at check time but to a private IP at request time).  For a production
    system, network-layer controls (e.g. firewall egress rules) are required.
    """
    url = url.strip()
    if not url:
        return False, "URL must not be empty."

    # Prepend https:// only when the user typed a bare hostname (no scheme at all).
    # URLs that already contain a scheme (ftp://, file://, etc.) must not be
    # modified — they will be caught by the scheme check below.
    if "://" not in url:
        url = "https://" + url

    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError as exc:
        return False, f"URL parse error: {exc}"

    if parsed.scheme not in ("http", "https"):
        return False, "Only HTTP and HTTPS URLs are supported."

    # Reject embedded credentials (e.g. https://user:pass@example.com/).
    # Accepting credentials in the URL would silently forward them with every
    # request and could mislead users about what is being scanned.
    if parsed.username or parsed.password:
        return False, "URLs containing embedded credentials (user:password@host) are not permitted."

    hostname = parsed.hostname
    if not hostname:
        return False, "URL contains no hostname."

    # Reject obvious private hostnames before DNS resolution
    lower_host = hostname.lower()
    if lower_host in ("localhost", "broadcasthost"):
        return False, "Scanning localhost is not permitted."
    if lower_host.endswith(".local") or lower_host.endswith(".internal"):
        return False, "Scanning .local / .internal hostnames is not permitted."

    # Resolve and check all addresses
    valid, msg = _check_hostname(hostname)
    if not valid:
        return False, msg

    return True, url


def _check_hostname(hostname: str) -> tuple[bool, str]:
    """
    Resolve *hostname* to IP addresses and reject any address that is not
    globally routable.

    Uses ipaddress.is_global (Python ≥ 3.11 on IPv4Address; always available
    on IPv6Address) as the primary gate, with IPv4-mapped IPv6 unwrapping so
    that ::ffff:10.0.0.1 is treated as 10.0.0.1.  The explicit BLOCKED_NETWORKS
    list is retained as a defence-in-depth secondary check.

    DNS-rebinding caveat: this check is performed at validation time.  A
    hostname that resolves to a public IP now could resolve to a private IP at
    connection time.  Network-layer egress controls are required for production.
    """
    # If the hostname is already a raw IP address, check it directly.
    try:
        addr = ipaddress.ip_address(hostname)
        blocked, reason = _is_blocked_ip(addr)
        if blocked:
            return False, f"Target IP {addr} is in a reserved range ({reason})."
        return True, ""
    except ValueError:
        pass  # not a raw IP — proceed to DNS resolution

    try:
        results = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        return False, f"DNS resolution failed for '{hostname}': {exc}"

    if not results:
        return False, f"No DNS records found for '{hostname}'."

    for _family, _type, _proto, _canonname, sockaddr in results:
        raw_ip = sockaddr[0]
        try:
            addr = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue
        blocked, reason = _is_blocked_ip(addr)
        if blocked:
            return False, (
                f"'{hostname}' resolves to {addr}, which is in a reserved "
                f"range ({reason}). Scanning internal addresses is not allowed."
            )

    return True, ""


def _is_blocked_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> tuple[bool, str]:
    """
    Return (True, reason) if *addr* must not be scanned.

    Primary check: addr.is_global must be True.  This covers all private,
    loopback, link-local, multicast, reserved, and unspecified addresses as
    defined by the ipaddress module — a stricter and more future-proof gate
    than enumerating individual networks.

    Secondary check (defence-in-depth): explicit membership in BLOCKED_NETWORKS.
    This catches any edge-case where is_global may not behave as expected (e.g.
    documentation ranges that some Python versions mark as global).

    IPv4-mapped IPv6 addresses (::ffff:<ipv4>) are unwrapped to their IPv4 form
    before either check so that ::ffff:127.0.0.1 is treated identically to
    127.0.0.1.

    Note: is_global alone is sufficient for correctness; BLOCKED_NETWORKS is
    retained as a belt-and-suspenders guard.
    """
    # Unwrap IPv4-mapped IPv6 addresses (::ffff:0:0/96)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped

    # Primary gate: reject any address that is not globally routable.
    if not addr.is_global:
        return True, f"address {addr} is not globally routable (is_global=False)"

    # Secondary gate (defence-in-depth): explicit network list.
    for net in BLOCKED_NETWORKS:
        try:
            if addr in net:
                return True, str(net)
        except TypeError:
            # Mismatched address families — skip silently.
            continue

    return False, ""


def _validate_redirect_url(next_url: str) -> tuple[bool, str]:
    """
    Apply the full URL policy to a redirect destination:
    - Must be http:// or https://
    - Must not carry userinfo (credentials in URL)
    - Hostname must pass _check_hostname (resolves to a non-private address)

    Returns (True, "") on success or (False, reason) on rejection.

    Note: no port restriction is applied.  Port numbers alone are not a
    reliable SSRF signal for public targets (many CDNs and APIs use non-80/443
    ports); the IP-address check via _check_hostname is the authoritative gate.
    """
    try:
        parsed = urllib.parse.urlparse(next_url)
    except ValueError as exc:
        return False, f"Unparseable redirect URL: {exc}"

    if parsed.scheme not in ("http", "https"):
        return False, f"Redirect to non-HTTP(S) scheme '{parsed.scheme}' rejected."

    # Reject embedded credentials (http://user:pass@host/)
    if parsed.username or parsed.password:
        return False, "Redirect URL contains embedded credentials — rejected."

    hostname = parsed.hostname or ""
    if not hostname:
        return False, "Redirect URL has no hostname."

    # Reject .local / .internal hostnames
    lower_host = hostname.lower()
    if lower_host in ("localhost", "broadcasthost"):
        return False, "Redirect to localhost is not permitted."
    if lower_host.endswith(".local") or lower_host.endswith(".internal"):
        return False, "Redirect to .local / .internal hostname is not permitted."

    valid, msg = _check_hostname(hostname)
    if not valid:
        return False, f"Redirect to blocked destination: {msg}"

    return True, ""


def _safe_fetch(url: str, extra_headers: dict | None = None) -> requests.Response:
    """
    Fetch *url* without following redirects automatically.  Each redirect
    destination is validated using the full URL policy before being followed.

    Key security properties:
    - Redirects are followed manually; each hop is fully re-validated.
    - Environment-derived proxy settings are disabled (trust_env=False) to
      prevent proxy bypass of SSRF controls.
    - Responses are opened with stream=True and only a bounded number of
      bytes are read to free the connection without loading arbitrary bodies.
    - Every response object is explicitly closed in all exit paths.

    DNS-rebinding caveat: DNS is resolved before each request.  A hostname
    that resolves to a public IP at validation time could theoretically
    resolve to a private IP at connection time (DNS rebinding).  This risk
    cannot be eliminated by application-layer checks alone; network-level
    egress controls are required for production deployments.

    Raises ValueError for policy violations, requests.RequestException for
    network errors.
    """
    req_headers = {
        "User-Agent": "HeaderHawk-Scanner/1.0 (educational security audit tool)",
        "Accept": "*/*",
    }
    if extra_headers:
        req_headers.update(extra_headers)

    # Use a Session so we can disable trust_env at the session level.
    # trust_env=False prevents requests from picking up HTTP_PROXY / HTTPS_PROXY
    # environment variables or ~/.netrc credentials, which could otherwise bypass
    # SSRF controls by routing scanner traffic through an attacker-controlled proxy.
    session = requests.Session()
    session.trust_env = False

    current_url = url
    for hop in range(MAX_REDIRECTS + 1):
        resp = session.get(
            current_url,
            headers=req_headers,
            allow_redirects=False,
            timeout=REQUEST_TIMEOUT,
            stream=True,
        )
        try:
            if resp.status_code in (301, 302, 303, 307, 308):
                if hop == MAX_REDIRECTS:
                    raise ValueError(
                        f"Too many redirects (>{MAX_REDIRECTS}) while fetching {url}."
                    )
                location = resp.headers.get("Location", "")
                if not location:
                    raise ValueError("Redirect response missing Location header.")

                # Resolve relative redirects against the current URL
                next_url = urllib.parse.urljoin(current_url, location)

                # Apply the full URL policy to the redirect destination
                ok, reason = _validate_redirect_url(next_url)
                if not ok:
                    raise ValueError(reason)

                current_url = next_url
                # Close this intermediate response before following the redirect
                resp.close()
                continue

            # Non-redirect: discard the body in a bounded way to free the
            # connection, then return the response (headers already received).
            # We deliberately do NOT read resp.content (which buffers everything).
            # iter_content with a single large chunk reads at most MAX_RESPONSE_BYTES.
            _drain_response(resp)
            return resp

        except Exception:
            resp.close()
            raise

    # Should be unreachable — the loop exits via return or raises ValueError
    # inside the loop when hop == MAX_REDIRECTS.
    raise ValueError("Redirect loop not resolved.")  # pragma: no cover


def _drain_response(resp: requests.Response) -> None:
    """
    Consume at most MAX_RESPONSE_BYTES from *resp* to allow the underlying
    TCP connection to be returned to the connection pool, then close the
    stream.  We never inspect the body content — only headers matter.
    """
    try:
        bytes_read = 0
        for chunk in resp.iter_content(chunk_size=8192):
            bytes_read += len(chunk)
            if bytes_read >= MAX_RESPONSE_BYTES:
                break
    finally:
        resp.close()


# ---------------------------------------------------------------------------
# 3. Security-header analysis
# ---------------------------------------------------------------------------

def analyze_headers(response_headers: dict, response_scheme: str = "https") -> list[dict]:
    """
    Compare *response_headers* against the catalog of expected security headers.

    response_scheme: the scheme of the actual response URL ('http' or 'https').
    HSTS is only meaningful over HTTPS; on plain HTTP it is both unenforceable
    and often absent by design, so its absence is not scored as a HIGH defect
    when the scan target itself uses HTTP.

    Returns a list of finding dicts sorted by descending severity.
    """
    # Normalize incoming header names to lower-case for case-insensitive lookup
    lower_headers = {k.lower(): v for k, v in response_headers.items()}
    is_https = response_scheme.lower() == "https"

    findings = []
    for header_name, meta in SECURITY_HEADERS.items():
        present = header_name.lower() in lower_headers
        value = lower_headers.get(header_name.lower(), "")

        # HSTS over plain HTTP: note the observation but lower the severity,
        # because HSTS is only enforced over HTTPS by browsers.
        if header_name == "Strict-Transport-Security" and not is_https and not present:
            finding = {
                "header": header_name,
                "present": False,
                "value": "",
                "severity": "MEDIUM",  # lowered from HIGH: HSTS inapplicable over HTTP
                "description": (
                    meta["description"] + "\n\nNote: This scan was performed over plain "
                    "HTTP. HSTS is only enforceable over HTTPS. Migrate to HTTPS first, "
                    "then add the HSTS header."
                ),
                "remediation": meta["remediation"],
                "reference": meta["reference"],
                "category": "Security Header",
                "quality_note": "",
            }
            findings.append(finding)
            continue

        finding = {
            "header": header_name,
            "present": present,
            "value": value,
            "severity": meta["severity"] if not present else "INFO",
            "description": meta["description"],
            "remediation": meta["remediation"],
            "reference": meta["reference"],
            "category": "Security Header",
        }

        # Extra quality checks when header IS present
        if present:
            note = _check_header_quality(header_name, value, is_https=is_https)
            if note:
                finding["severity"] = "LOW"
                finding["quality_note"] = note
            else:
                finding["quality_note"] = ""
        else:
            finding["quality_note"] = ""

        findings.append(finding)

    # Sort: missing/misconfigured first, then by severity descending
    findings.sort(
        key=lambda f: (
            0 if f["severity"] == "INFO" else 1,
            SEVERITY_ORDER.get(f["severity"], -1),
        ),
        reverse=True,
    )
    return findings


def _check_header_quality(header_name: str, value: str, *, is_https: bool = True) -> str:
    """
    Perform a basic quality check on a header value that IS present.
    Returns a non-empty string describing the issue, or '' if acceptable.

    is_https: True when the response arrived over HTTPS.  HSTS on an HTTP
    response is anomalous but checked leniently.
    """
    v = value.strip().lower()

    if header_name == "Strict-Transport-Security":
        if not is_https:
            # HSTS sent over plain HTTP is ignored by browsers; flag it.
            return (
                "HSTS header present on a plain HTTP response. "
                "Browsers only enforce HSTS headers received over HTTPS."
            )
        # Check for a reasonable max-age
        match = re.search(r"max-age\s*=\s*(\d+)", v)
        if not match:
            return "max-age directive is missing from HSTS value."
        max_age = int(match.group(1))
        if max_age < 15768000:  # 6 months
            return f"max-age={max_age} is less than the recommended 15768000 (6 months)."

    elif header_name == "X-Content-Type-Options":
        if v != "nosniff":
            return f"Expected 'nosniff', got '{value.strip()}'."

    elif header_name == "X-Frame-Options":
        if v not in ("deny", "sameorigin"):
            return f"Unexpected value '{value.strip()}'. Use DENY or SAMEORIGIN."

    elif header_name == "Content-Security-Policy":
        # Warn about obviously weak directives
        if "unsafe-inline" in v and "script-src" in v:
            return "CSP contains 'unsafe-inline' in script-src, weakening XSS protection."
        if "unsafe-eval" in v:
            return "CSP contains 'unsafe-eval', allowing dynamic code evaluation."
        if "*" in v and "default-src" in v:
            return "CSP default-src uses wildcard '*', which is overly permissive."

    return ""


# ---------------------------------------------------------------------------
# 4. CORS analysis
# ---------------------------------------------------------------------------

def analyze_cors(response_headers: dict, request_origin: str) -> dict:
    """
    Inspect the CORS-related response headers returned after injecting
    *request_origin* as the Origin request header.

    Returns a structured finding dict.

    IMPORTANT: These checks identify *possible* misconfigurations based on
    observable response headers.  They are NOT proof of exploitability.
    Actual exploitability depends on authentication requirements, SameSite
    cookie attributes, browser behavior, and other factors outside the scope
    of a header scan.
    """
    lower = {k.lower(): v for k, v in response_headers.items()}

    acao = lower.get("access-control-allow-origin", "")
    acac = lower.get("access-control-allow-credentials", "")
    acam = lower.get("access-control-allow-methods", "")
    acah = lower.get("access-control-allow-headers", "")
    vary = lower.get("vary", "")

    issues = []
    severity = "INFO"

    # --- Check 1: wildcard origin ---
    if acao == "*":
        issues.append(
            "Access-Control-Allow-Origin: * permits any origin to read "
            "responses. This is acceptable for fully public APIs but "
            "problematic for any endpoint that returns user-specific data."
        )
        severity = _upgrade_severity(severity, "MEDIUM")

    # --- Check 2: origin reflection ---
    elif acao and acao.strip() == request_origin:
        issues.append(
            f"Server reflects the requesting origin verbatim "
            f"({request_origin}). Combined with Allow-Credentials: true this "
            "allows arbitrary origins to make credentialed cross-origin requests."
        )
        severity = _upgrade_severity(severity, "MEDIUM")

    # --- Check 3: credentials + wildcard or reflection ---
    if acac.strip().lower() == "true":
        if acao == "*":
            issues.append(
                "CRITICAL combination: Access-Control-Allow-Credentials: true "
                "with Allow-Origin: * is rejected by browsers, but the server "
                "configuration is clearly broken and may behave differently with "
                "non-browser clients."
            )
            severity = _upgrade_severity(severity, "HIGH")
        elif acao.strip() == request_origin:
            issues.append(
                "Access-Control-Allow-Credentials: true combined with reflected "
                "origin allows a malicious site to make authenticated cross-origin "
                "requests using the victim's session cookies."
            )
            severity = _upgrade_severity(severity, "HIGH")

    # --- Check 4: Vary: Origin missing (cache poisoning risk) ---
    if acao and "origin" not in vary.lower() and acao != "*":
        issues.append(
            "The Vary header does not include 'Origin'. This may allow a "
            "CDN or proxy cache to serve a CORS-permissive response to a "
            "non-CORS request (cache-poisoning risk)."
        )
        severity = _upgrade_severity(severity, "LOW")

    # --- Check 5: no CORS headers at all ---
    if not acao:
        issues.append(
            "Server did not return Access-Control-Allow-Origin in response to "
            "the probe Origin header. CORS is either not configured or the "
            "request was not treated as cross-origin. No CORS misconfiguration "
            "was detected for this probe, though the absence of CORS headers "
            "does not rule out other configurations."
        )

    # Build the finding
    headers_observed = {}
    for h in (
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "access-control-allow-methods",
        "access-control-allow-headers",
        "access-control-expose-headers",
        "vary",
    ):
        if h in lower:
            headers_observed[h] = lower[h]

    return {
        "category": "CORS",
        "probe_origin": request_origin,
        "headers_observed": headers_observed,
        "issues": issues,
        "severity": severity,
        "disclaimer": (
            "These observations indicate a possible misconfiguration. "
            "They are NOT proof of exploitability. Actual risk depends on "
            "authentication mechanisms, cookie attributes, and browser policies "
            "outside the scope of this scan."
        ),
    }


def _upgrade_severity(current: str, candidate: str) -> str:
    """Return whichever of *current* / *candidate* is higher severity."""
    return current if SEVERITY_ORDER.get(current, -1) >= SEVERITY_ORDER.get(candidate, -1) else candidate


# ---------------------------------------------------------------------------
# 5. Score / summary calculation
# ---------------------------------------------------------------------------

def calculate_score(header_findings: list[dict], cors_finding: dict) -> dict:
    """
    Derive a simple A–F grade and numeric score from the findings.
    The score is heuristic and should be read as a rough indicator only.
    """
    total_headers = len(SECURITY_HEADERS)
    missing = sum(1 for f in header_findings if not f["present"])
    quality_issues = sum(
        1 for f in header_findings if f["present"] and f.get("quality_note")
    )

    # Deduct points using the *effective* finding severity — i.e. f["severity"]
    # as reported by analyze_headers().  This ensures that context-adjusted
    # severities (such as HSTS missing over HTTP being downgraded from HIGH to
    # MEDIUM) are reflected consistently in both the displayed badge and the
    # score.  Using the catalog's original severity here would create a
    # discrepancy where the UI shows MEDIUM but the score deducts as HIGH.
    deductions = 0
    for f in header_findings:
        if not f["present"]:
            sev = f["severity"]  # use effective severity, not catalog default
            deductions += {"HIGH": 20, "MEDIUM": 12, "LOW": 6}.get(sev, 0)
        elif f.get("quality_note"):
            deductions += 5

    cors_sev = cors_finding.get("severity", "INFO")
    deductions += {"HIGH": 20, "MEDIUM": 10, "LOW": 4, "INFO": 0}.get(cors_sev, 0)

    score = max(0, 100 - deductions)

    if score >= 90:
        grade, label, color = "A", "Excellent", "#16a34a"
    elif score >= 75:
        grade, label, color = "B", "Good", "#65a30d"
    elif score >= 60:
        grade, label, color = "C", "Fair", "#d97706"
    elif score >= 40:
        grade, label, color = "D", "Poor", "#ea580c"
    else:
        grade, label, color = "F", "Critical", "#dc2626"

    return {
        "score": score,
        "grade": grade,
        "label": label,
        "color": color,
        "headers_checked": total_headers,
        "headers_missing": missing,
        "headers_present": total_headers - missing,
        "quality_issues": quality_issues,
        "cors_severity": cors_sev,
    }


def build_scan_result(url: str, response: requests.Response, cors_response: requests.Response) -> dict:
    """Assemble the full scan result dict from two Response objects."""
    scheme = urllib.parse.urlparse(url).scheme.lower()
    header_findings = analyze_headers(dict(response.headers), response_scheme=scheme)
    cors_finding = analyze_cors(dict(cors_response.headers), CORS_TEST_ORIGIN)
    summary = calculate_score(header_findings, cors_finding)

    return {
        "url": url,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status_code": response.status_code,
        "server": response.headers.get("Server", ""),
        "header_findings": header_findings,
        "cors_finding": cors_finding,
        "summary": summary,
        "is_demo": False,
    }


# ---------------------------------------------------------------------------
# 6. Demo-mode data
# ---------------------------------------------------------------------------

def get_demo_result() -> dict:
    """
    Return clearly labelled illustrative sample results.
    NO network requests are made.
    """
    header_findings = [
        {
            "header": "Content-Security-Policy",
            "present": False,
            "value": "",
            "severity": "HIGH",
            "description": SECURITY_HEADERS["Content-Security-Policy"]["description"],
            "remediation": SECURITY_HEADERS["Content-Security-Policy"]["remediation"],
            "reference": SECURITY_HEADERS["Content-Security-Policy"]["reference"],
            "quality_note": "",
            "category": "Security Header",
        },
        {
            "header": "Strict-Transport-Security",
            "present": True,
            "value": "max-age=3600",
            "severity": "LOW",
            "description": SECURITY_HEADERS["Strict-Transport-Security"]["description"],
            "remediation": SECURITY_HEADERS["Strict-Transport-Security"]["remediation"],
            "reference": SECURITY_HEADERS["Strict-Transport-Security"]["reference"],
            "quality_note": "max-age=3600 is less than the recommended 15768000 (6 months).",
            "category": "Security Header",
        },
        {
            "header": "X-Content-Type-Options",
            "present": True,
            "value": "nosniff",
            "severity": "INFO",
            "description": SECURITY_HEADERS["X-Content-Type-Options"]["description"],
            "remediation": SECURITY_HEADERS["X-Content-Type-Options"]["remediation"],
            "reference": SECURITY_HEADERS["X-Content-Type-Options"]["reference"],
            "quality_note": "",
            "category": "Security Header",
        },
        {
            "header": "X-Frame-Options",
            "present": False,
            "value": "",
            "severity": "MEDIUM",
            "description": SECURITY_HEADERS["X-Frame-Options"]["description"],
            "remediation": SECURITY_HEADERS["X-Frame-Options"]["remediation"],
            "reference": SECURITY_HEADERS["X-Frame-Options"]["reference"],
            "quality_note": "",
            "category": "Security Header",
        },
        {
            "header": "Referrer-Policy",
            "present": False,
            "value": "",
            "severity": "LOW",
            "description": SECURITY_HEADERS["Referrer-Policy"]["description"],
            "remediation": SECURITY_HEADERS["Referrer-Policy"]["remediation"],
            "reference": SECURITY_HEADERS["Referrer-Policy"]["reference"],
            "quality_note": "",
            "category": "Security Header",
        },
        {
            "header": "Permissions-Policy",
            "present": False,
            "value": "",
            "severity": "LOW",
            "description": SECURITY_HEADERS["Permissions-Policy"]["description"],
            "remediation": SECURITY_HEADERS["Permissions-Policy"]["remediation"],
            "reference": SECURITY_HEADERS["Permissions-Policy"]["reference"],
            "quality_note": "",
            "category": "Security Header",
        },
    ]

    cors_finding = {
        "category": "CORS",
        "probe_origin": CORS_TEST_ORIGIN,
        "headers_observed": {
            "access-control-allow-origin": CORS_TEST_ORIGIN,
            "access-control-allow-credentials": "true",
            "access-control-allow-methods": "GET, POST, PUT, DELETE",
        },
        "issues": [
            (
                f"Server reflects the requesting origin verbatim "
                f"({CORS_TEST_ORIGIN}). Combined with Allow-Credentials: true this "
                "allows arbitrary origins to make credentialed cross-origin requests."
            ),
            (
                "Access-Control-Allow-Credentials: true combined with reflected "
                "origin allows a malicious site to make authenticated cross-origin "
                "requests using the victim's session cookies."
            ),
        ],
        "severity": "HIGH",
        "disclaimer": (
            "These observations indicate a possible misconfiguration. "
            "They are NOT proof of exploitability."
        ),
    }

    summary = calculate_score(header_findings, cors_finding)

    return {
        "url": "https://demo.example.com",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status_code": 200,
        "server": "nginx/1.18.0 (Demo)",
        "header_findings": header_findings,
        "cors_finding": cors_finding,
        "summary": summary,
        "is_demo": True,
    }


# ---------------------------------------------------------------------------
# 7. Flask application & routes
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.config["SECRET_KEY"] = "headerhawk-dev-only"  # not used for sessions in this app


@app.route("/", methods=["GET"])
def index():
    """Render the main page."""
    return render_template_string(HTML_TEMPLATE, result=None, error=None)


@app.route("/scan", methods=["POST"])
def scan():
    """Accept a URL, validate it, scan it, and return results."""
    url_input = request.form.get("url", "").strip()

    # --- Validate ---
    valid, result_or_error = validate_url(url_input)
    if not valid:
        return render_template_string(HTML_TEMPLATE, result=None, error=result_or_error)

    canonical_url = result_or_error

    try:
        # --- Fetch main response ---
        main_response = _safe_fetch(canonical_url)

        # --- Fetch CORS probe response ---
        cors_response = _safe_fetch(
            canonical_url,
            extra_headers={"Origin": CORS_TEST_ORIGIN},
        )

        # --- Assemble results ---
        result = build_scan_result(canonical_url, main_response, cors_response)
        return render_template_string(HTML_TEMPLATE, result=result, error=None)

    except ValueError as exc:
        return render_template_string(
            HTML_TEMPLATE, result=None, error=f"Policy violation: {exc}"
        )
    except requests.exceptions.ConnectionError:
        return render_template_string(
            HTML_TEMPLATE,
            result=None,
            error="Could not connect to the target. Check the URL and try again.",
        )
    except requests.exceptions.Timeout:
        return render_template_string(
            HTML_TEMPLATE,
            result=None,
            error="The request timed out. The target may be down or unreachable.",
        )
    except requests.exceptions.TooManyRedirects:
        return render_template_string(
            HTML_TEMPLATE,
            result=None,
            error="The target returned too many redirects.",
        )
    except requests.exceptions.RequestException as exc:
        # Log to server console but never expose details to the user.
        app.logger.error("Scan error for %s: %s", canonical_url, exc)
        return render_template_string(
            HTML_TEMPLATE,
            result=None,
            error="An unexpected network error occurred. Please try again.",
        )


@app.route("/demo", methods=["GET"])
def demo():
    """Return clearly labelled illustrative sample results without any network requests."""
    result = get_demo_result()
    return render_template_string(HTML_TEMPLATE, result=result, error=None)


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """JSON API endpoint — same logic as /scan but returns JSON.

    Input validation applied before any processing:
    - Request body must be valid JSON (not silently replaced with {}).
    - Body must be a JSON object (dict), not an array, string, or null.
    - The 'url' field must be present and must be a string.
    """
    # Force-parse JSON; on failure return a clear 400 rather than silently
    # falling through to a validate_url("") call.
    raw = request.get_data(cache=True)
    if not raw:
        return jsonify({"error": "Request body is empty. Provide a JSON object with a 'url' field."}), 400

    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return jsonify({"error": "Request body is not valid JSON."}), 400

    if not isinstance(data, dict):
        return jsonify({"error": "Request body must be a JSON object, not an array or scalar."}), 400

    if "url" not in data:
        return jsonify({"error": "Missing required field: 'url'."}), 400

    url_input = data["url"]
    if not isinstance(url_input, str):
        return jsonify({"error": "Field 'url' must be a string."}), 400

    url_input = url_input.strip()

    valid, result_or_error = validate_url(url_input)
    if not valid:
        return jsonify({"error": result_or_error}), 400

    canonical_url = result_or_error
    try:
        main_response = _safe_fetch(canonical_url)
        cors_response = _safe_fetch(canonical_url, extra_headers={"Origin": CORS_TEST_ORIGIN})
        result = build_scan_result(canonical_url, main_response, cors_response)
        return jsonify(result)
    except (ValueError, requests.exceptions.RequestException) as exc:
        app.logger.error("API scan error: %s", exc)
        return jsonify({"error": "Scan failed. Check URL and try again."}), 400


# ---------------------------------------------------------------------------
# 8. Embedded HTML / CSS / JavaScript template
# ---------------------------------------------------------------------------

HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HeaderHawk — Security Header Scanner</title>
<style>
  /* ---- Reset & base ---- */
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, "Segoe UI", system-ui, sans-serif;
    font-size: 15px;
    line-height: 1.6;
    background: #0f172a;
    color: #e2e8f0;
    min-height: 100vh;
  }
  a { color: #60a5fa; text-decoration: none; }
  a:hover { text-decoration: underline; }
  code { font-family: "Courier New", monospace; font-size: 0.88em; }

  /* ---- Nav ---- */
  nav {
    background: #1e293b;
    border-bottom: 1px solid #334155;
    padding: 0 1.5rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
    height: 56px;
    position: sticky;
    top: 0;
    z-index: 100;
  }
  .nav-brand {
    font-size: 1.2rem;
    font-weight: 700;
    color: #38bdf8;
    letter-spacing: 0.02em;
  }
  .nav-brand span { color: #f8fafc; }
  .nav-links { display: flex; gap: 1.5rem; font-size: 0.9rem; color: #94a3b8; }
  .nav-links a { color: #94a3b8; }
  .nav-links a:hover { color: #e2e8f0; }

  /* ---- Main layout ---- */
  .container { max-width: 900px; margin: 0 auto; padding: 2rem 1.5rem; }

  /* ---- Hero / scanner card ---- */
  .scanner-card {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 2rem;
    margin-bottom: 2rem;
  }
  .scanner-card h1 {
    font-size: 1.6rem;
    font-weight: 700;
    color: #f8fafc;
    margin-bottom: 0.4rem;
  }
  .scanner-card p.subtitle {
    color: #94a3b8;
    margin-bottom: 1.5rem;
    font-size: 0.95rem;
  }
  .url-form { display: flex; gap: 0.75rem; flex-wrap: wrap; }
  .url-input {
    flex: 1;
    min-width: 0;
    background: #0f172a;
    border: 1px solid #475569;
    border-radius: 8px;
    color: #e2e8f0;
    font-size: 1rem;
    padding: 0.6rem 1rem;
    outline: none;
    transition: border-color 0.2s;
  }
  .url-input:focus { border-color: #38bdf8; }
  .url-input::placeholder { color: #64748b; }
  .btn {
    border: none;
    border-radius: 8px;
    cursor: pointer;
    font-size: 0.95rem;
    font-weight: 600;
    padding: 0.6rem 1.4rem;
    transition: opacity 0.15s;
    white-space: nowrap;
  }
  .btn:hover { opacity: 0.88; }
  .btn-primary { background: #2563eb; color: #fff; }
  .btn-demo    { background: #7c3aed; color: #fff; }
  .btn-sm      { padding: 0.35rem 0.9rem; font-size: 0.82rem; }

  /* ---- Disclaimer ---- */
  .disclaimer {
    background: #1e3a5f;
    border: 1px solid #2563eb;
    border-radius: 8px;
    padding: 0.9rem 1.2rem;
    font-size: 0.85rem;
    color: #93c5fd;
    margin-bottom: 2rem;
  }
  .disclaimer strong { color: #bfdbfe; }

  /* ---- Demo banner ---- */
  .demo-banner {
    background: #3b1f6b;
    border: 1px solid #7c3aed;
    border-radius: 8px;
    padding: 0.75rem 1.2rem;
    font-size: 0.88rem;
    color: #c4b5fd;
    margin-bottom: 1.5rem;
  }

  /* ---- Error box ---- */
  .error-box {
    background: #450a0a;
    border: 1px solid #dc2626;
    border-radius: 8px;
    padding: 0.9rem 1.2rem;
    color: #fca5a5;
    margin-bottom: 1.5rem;
  }

  /* ---- Summary cards ---- */
  .summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
  }
  .summary-card {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 10px;
    padding: 1.1rem;
    text-align: center;
  }
  .summary-card .val {
    font-size: 2rem;
    font-weight: 800;
    line-height: 1.1;
  }
  .summary-card .lbl {
    font-size: 0.78rem;
    color: #94a3b8;
    margin-top: 0.3rem;
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }

  /* ---- Section headings ---- */
  .section-heading {
    font-size: 1.05rem;
    font-weight: 700;
    color: #f8fafc;
    border-bottom: 1px solid #334155;
    padding-bottom: 0.5rem;
    margin-bottom: 1rem;
  }

  /* ---- Findings table ---- */
  .findings-table { width: 100%; border-collapse: collapse; margin-bottom: 2rem; }
  .findings-table th {
    background: #1e293b;
    color: #94a3b8;
    font-size: 0.78rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    padding: 0.65rem 1rem;
    text-align: left;
    border-bottom: 1px solid #334155;
  }
  .findings-table td {
    padding: 0.75rem 1rem;
    border-bottom: 1px solid #1e293b;
    vertical-align: top;
    font-size: 0.88rem;
  }
  .findings-table tr:hover td { background: #1e293b44; }

  /* ---- Severity badges ---- */
  .badge {
    display: inline-block;
    border-radius: 4px;
    font-size: 0.72rem;
    font-weight: 700;
    letter-spacing: 0.06em;
    padding: 0.18em 0.6em;
    text-transform: uppercase;
  }
  .badge-HIGH   { background: #450a0a; color: #fca5a5; border: 1px solid #dc2626; }
  .badge-MEDIUM { background: #431407; color: #fdba74; border: 1px solid #ea580c; }
  .badge-LOW    { background: #422006; color: #fcd34d; border: 1px solid #d97706; }
  .badge-INFO   { background: #0c1a2e; color: #93c5fd; border: 1px solid #2563eb; }
  .badge-PASS   { background: #052e16; color: #86efac; border: 1px solid #16a34a; }

  /* ---- Status indicators in table ---- */
  .status-present { color: #86efac; font-weight: 600; }
  .status-missing { color: #fca5a5; font-weight: 600; }

  /* ---- CORS section ---- */
  .cors-card {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 10px;
    padding: 1.4rem;
    margin-bottom: 2rem;
  }
  .cors-card h3 { font-size: 1rem; font-weight: 700; margin-bottom: 0.75rem; }
  .cors-headers { margin: 0.75rem 0; }
  .cors-header-row { display: flex; gap: 0.75rem; margin-bottom: 0.35rem; flex-wrap: wrap; }
  .cors-hname { color: #94a3b8; font-size: 0.82rem; min-width: 260px; }
  .cors-hval  { color: #e2e8f0; font-size: 0.82rem; font-family: monospace; word-break: break-all; }
  .issue-list { list-style: none; margin-top: 0.6rem; }
  .issue-list li {
    background: #0f172a;
    border-left: 3px solid #ea580c;
    border-radius: 0 6px 6px 0;
    font-size: 0.85rem;
    margin-bottom: 0.5rem;
    padding: 0.5rem 0.75rem;
    color: #fdba74;
  }
  .cors-disclaimer {
    font-size: 0.8rem;
    color: #64748b;
    margin-top: 0.75rem;
    font-style: italic;
  }

  /* ---- Detail expand ---- */
  .detail-toggle { cursor: pointer; color: #60a5fa; font-size: 0.8rem; }
  .detail-box {
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 6px;
    font-size: 0.82rem;
    margin-top: 0.5rem;
    padding: 0.75rem;
    display: none;
    white-space: pre-wrap;
    word-break: break-word;
    color: #cbd5e1;
  }
  .detail-box.open { display: block; }
  .detail-box a { color: #60a5fa; }

  /* ---- Scan metadata ---- */
  .meta-row {
    display: flex;
    gap: 1.5rem;
    flex-wrap: wrap;
    font-size: 0.82rem;
    color: #64748b;
    margin-bottom: 2rem;
  }
  .meta-row span { display: flex; align-items: center; gap: 0.3rem; }

  /* ---- Footer ---- */
  footer {
    border-top: 1px solid #1e293b;
    color: #475569;
    font-size: 0.78rem;
    margin-top: 3rem;
    padding: 1.5rem 0;
    text-align: center;
  }

  /* ---- Spinner ---- */
  .spinner { display: none; }
  .scanning .spinner { display: inline-block; }
  .scanning .scan-label { display: none; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .spin-icon {
    animation: spin 0.8s linear infinite;
    border: 2px solid #ffffff44;
    border-top-color: #fff;
    border-radius: 50%;
    display: inline-block;
    height: 14px;
    vertical-align: middle;
    width: 14px;
  }
</style>
</head>
<body>

<!-- Navigation -->
<nav>
  <div class="nav-brand">Header<span>Hawk</span> 🦅</div>
  <div class="nav-links">
    <a href="/">Home</a>
    <a href="/demo">Demo</a>
    <a href="https://owasp.org/www-project-secure-headers/" target="_blank" rel="noopener">OWASP</a>
  </div>
</nav>

<div class="container">

  <!-- Scanner card -->
  <div class="scanner-card">
    <h1>HTTP Security Header Scanner</h1>
    <p class="subtitle">
      Audit a website's security headers and CORS configuration — instantly.
      Enter a URL and click <strong>Scan</strong>, or try <strong>Demo Mode</strong>
      to see sample results without making any network requests.
    </p>
    <form class="url-form" method="POST" action="/scan" id="scanForm">
      <input
        class="url-input"
        type="url"
        name="url"
        id="urlInput"
        placeholder="https://example.com"
        required
        autocomplete="off"
        spellcheck="false"
        value="{{ request.form.get('url', '') }}"
      >
      <button type="submit" class="btn btn-primary" id="scanBtn">
        <span class="scan-label">🔍 Scan</span>
        <span class="spinner"><span class="spin-icon"></span> Scanning…</span>
      </button>
      <a href="/demo" class="btn btn-demo">🧪 Demo</a>
    </form>
  </div>

  <!-- Disclaimer -->
  <div class="disclaimer">
    <strong>⚠ Disclaimer:</strong>
    HeaderHawk performs a <em>preliminary configuration audit</em> — it is
    <strong>not</strong> a penetration test or vulnerability assessment.
    Results reflect observable HTTP response headers only. Missing or
    misconfigured headers indicate risk; they are not proof of exploitability.
    Only scan websites you own or have explicit written permission to test.
  </div>

  {% if error %}
  <div class="error-box">
    <strong>Error:</strong> {{ error }}
  </div>
  {% endif %}

  {% if result %}

  {% if result.is_demo %}
  <div class="demo-banner">
    🧪 <strong>DEMO MODE</strong> — These are illustrative sample results.
    No network requests were made. Real scan results will differ.
  </div>
  {% endif %}

  <!-- Scan metadata -->
  <div class="meta-row">
    <span>🌐 <strong>Target:</strong> {{ result.url }}</span>
    <span>📅 <strong>Scanned:</strong> {{ result.timestamp }}</span>
    <span>📶 <strong>HTTP Status:</strong> {{ result.status_code }}</span>
    {% if result.server %}
    <span>🖥 <strong>Server:</strong> {{ result.server }}</span>
    {% endif %}
  </div>

  <!-- Summary cards -->
  {% set s = result.summary %}
  <div class="summary-grid">
    <div class="summary-card">
      <div class="val" style="color: {{ s.color }}">{{ s.grade }}</div>
      <div class="lbl">Security Grade</div>
    </div>
    <div class="summary-card">
      <div class="val" style="color: {{ s.color }}">{{ s.score }}</div>
      <div class="lbl">Score / 100</div>
    </div>
    <div class="summary-card">
      <div class="val" style="color: #86efac">{{ s.headers_present }}</div>
      <div class="lbl">Headers Present</div>
    </div>
    <div class="summary-card">
      <div class="val" style="color: #fca5a5">{{ s.headers_missing }}</div>
      <div class="lbl">Headers Missing</div>
    </div>
    <div class="summary-card">
      <div class="val" style="color:
        {% if s.cors_severity == 'HIGH' %}#fca5a5
        {% elif s.cors_severity == 'MEDIUM' %}#fdba74
        {% elif s.cors_severity == 'LOW' %}#fcd34d
        {% else %}#86efac{% endif %}
      ">{{ s.cors_severity }}</div>
      <div class="lbl">CORS Risk</div>
    </div>
  </div>

  <!-- Header findings table -->
  <div class="section-heading">Security Header Findings</div>
  <table class="findings-table">
    <thead>
      <tr>
        <th>Header</th>
        <th>Status</th>
        <th>Severity</th>
        <th>Value / Note</th>
        <th>Details</th>
      </tr>
    </thead>
    <tbody>
    {% for f in result.header_findings %}
    <tr>
      <td><code>{{ f.header }}</code></td>
      <td>
        {% if f.present %}
          <span class="status-present">✔ Present</span>
        {% else %}
          <span class="status-missing">✘ Missing</span>
        {% endif %}
      </td>
      <td>
        <span class="badge badge-{{ f.severity }}">{{ f.severity }}</span>
      </td>
      <td style="max-width:220px; word-break:break-word;">
        {% if f.value %}
          <code>{{ f.value[:80] }}{% if f.value|length > 80 %}…{% endif %}</code>
        {% endif %}
        {% if f.quality_note %}
          <br><span style="color:#fcd34d; font-size:0.8rem;">⚠ {{ f.quality_note }}</span>
        {% endif %}
      </td>
      <td>
        <span class="detail-toggle" onclick="toggleDetail(this)">▶ Show</span>
        <div class="detail-box">
<b>Why it matters:</b>
{{ f.description }}

<b>Remediation:</b>
{{ f.remediation }}

<b>Reference:</b> <a href="{{ f.reference }}" target="_blank" rel="noopener">{{ f.reference }}</a>
        </div>
      </td>
    </tr>
    {% endfor %}
    </tbody>
  </table>

  <!-- CORS findings -->
  <div class="section-heading">CORS Configuration Analysis</div>
  {% set c = result.cors_finding %}
  <div class="cors-card">
    <h3>
      CORS Probe Result —
      <span class="badge badge-{{ c.severity }}">{{ c.severity }}</span>
    </h3>
    <div style="font-size:0.83rem; color:#64748b; margin-bottom:0.75rem;">
      Probe origin sent: <code>{{ c.probe_origin }}</code>
    </div>

    {% if c.headers_observed %}
    <div class="cors-headers">
      <strong style="font-size:0.85rem; color:#94a3b8;">Observed CORS Headers:</strong>
      {% for hname, hval in c.headers_observed.items() %}
      <div class="cors-header-row">
        <span class="cors-hname">{{ hname }}</span>
        <span class="cors-hval">{{ hval }}</span>
      </div>
      {% endfor %}
    </div>
    {% endif %}

    {% if c.issues %}
    <ul class="issue-list">
      {% for issue in c.issues %}
      <li>{{ issue }}</li>
      {% endfor %}
    </ul>
    {% endif %}

    <p class="cors-disclaimer">{{ c.disclaimer }}</p>
  </div>

  {% endif %} {# end if result #}

  <!-- How it works (always shown) -->
  <div class="section-heading">How HeaderHawk Works</div>
  <div style="background:#1e293b; border:1px solid #334155; border-radius:10px; padding:1.4rem; margin-bottom:2rem; font-size:0.88rem; color:#cbd5e1; line-height:1.8;">
    <ol style="padding-left:1.2rem;">
      <li><strong>URL Validation</strong> — The entered URL is parsed, scheme-checked, and the hostname is resolved via DNS. All resolved IP addresses are checked against private/reserved ranges to prevent SSRF attacks.</li>
      <li><strong>Header Scan</strong> — A single GET request is made to the target. The response headers are compared against the expected security-header catalog.</li>
      <li><strong>CORS Probe</strong> — A second GET request is made with a controlled <code>Origin</code> header. The server's CORS response headers are inspected for common misconfigurations.</li>
      <li><strong>Scoring</strong> — A heuristic score (0–100) and letter grade are calculated from missing and misconfigured headers, weighted by severity.</li>
      <li><strong>Findings</strong> — Each result is presented with a severity label, explanation, and remediation guidance.</li>
    </ol>
    <p style="margin-top:1rem; color:#64748b; font-size:0.82rem;">
      <strong>Limitations:</strong> This tool checks HTTP response headers only. It does not assess authentication, input validation, server-side logic, cryptographic configurations, or any other security dimension. A passing score here does not mean a site is secure.
    </p>
  </div>

</div><!-- end .container -->

<footer>
  HeaderHawk — Educational Cybersecurity Project &nbsp;|&nbsp;
  Built with Python &amp; Flask &nbsp;|&nbsp;
  <a href="https://owasp.org/www-project-secure-headers/" target="_blank" rel="noopener">OWASP Secure Headers Project</a>
</footer>

<script>
  // Spinner on form submit
  document.getElementById('scanForm').addEventListener('submit', function() {
    var btn = document.getElementById('scanBtn');
    btn.classList.add('scanning');
    btn.disabled = true;
  });

  // Toggle detail panels in the findings table
  function toggleDetail(el) {
    var box = el.nextElementSibling;
    var open = box.classList.toggle('open');
    el.textContent = open ? '▼ Hide' : '▶ Show';
  }
</script>

</body>
</html>
"""


# ---------------------------------------------------------------------------
# 9. Unit tests
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Helpers shared by the test cases below
# ---------------------------------------------------------------------------

def _make_mock_response(status_code=200, headers=None, body=b""):
    """
    Build a minimal mock of a requests.Response for use in unit tests.
    All network-dependent attributes are stubbed so no real I/O occurs.
    """
    resp = unittest.mock.MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.headers = requests.structures.CaseInsensitiveDict(headers or {})
    resp.iter_content.return_value = iter([body] if body else [])
    resp.close.return_value = None
    return resp


class TestHeaderHawk(unittest.TestCase):
    """
    Unit tests for HeaderHawk.

    All tests are fully deterministic — no real DNS queries or HTTP connections
    are made.  DNS is patched via unittest.mock.patch; HTTP responses are
    replaced with mock objects.

    Run with:  python app.py test
    """

    # ------------------------------------------------------------------ #
    #  URL validation — deterministic (hostname blocklist, scheme)          #
    # ------------------------------------------------------------------ #

    def test_empty_url_rejected(self):
        valid, msg = validate_url("")
        self.assertFalse(valid)
        self.assertIn("empty", msg.lower())

    def test_non_http_scheme_rejected(self):
        valid, msg = validate_url("ftp://example.com/file.txt")
        self.assertFalse(valid)
        self.assertIn("HTTP", msg)

    def test_file_scheme_rejected(self):
        valid, msg = validate_url("file:///etc/passwd")
        self.assertFalse(valid)
        self.assertIn("HTTP", msg)

    def test_localhost_rejected(self):
        valid, msg = validate_url("http://localhost/admin")
        self.assertFalse(valid)
        self.assertIn("localhost", msg.lower())

    def test_local_tld_rejected(self):
        valid, msg = validate_url("http://myserver.local/")
        self.assertFalse(valid)
        self.assertIn(".local", msg.lower())

    def test_internal_tld_rejected(self):
        valid, msg = validate_url("http://db.internal/")
        self.assertFalse(valid)
        self.assertIn(".internal", msg.lower())

    def test_url_without_scheme_gets_https_prepended(self):
        """Bare hostname (no scheme) should have https:// prepended, then be
        validated normally.  Mock DNS to return a public address."""
        public_addr = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))
        ]
        with unittest.mock.patch("socket.getaddrinfo", return_value=public_addr):
            valid, result = validate_url("example.com")
        self.assertTrue(valid, result)
        self.assertTrue(result.startswith("https://"))

    def test_valid_https_url_with_mocked_dns(self):
        """Public-IP hostname passes after mock DNS returns a global address."""
        public_addr = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))
        ]
        with unittest.mock.patch("socket.getaddrinfo", return_value=public_addr):
            valid, result = validate_url("https://example.com")
        self.assertTrue(valid, result)

    def test_dns_failure_is_rejected(self):
        """A DNS resolution failure returns a clear error message."""
        with unittest.mock.patch(
            "socket.getaddrinfo",
            side_effect=socket.gaierror("mock: no such host"),
        ):
            valid, msg = validate_url("https://nonexistent.example.test")
        self.assertFalse(valid)
        self.assertIn("DNS", msg)

    # ------------------------------------------------------------------ #
    #  IP restriction (SSRF guard) — raw IP / mocked DNS                   #
    # ------------------------------------------------------------------ #

    def test_loopback_ip_rejected(self):
        valid, msg = _check_hostname("127.0.0.1")
        self.assertFalse(valid)
        self.assertIn("reserved", msg.lower())

    def test_private_10_block_rejected(self):
        valid, _msg = _check_hostname("10.0.0.1")
        self.assertFalse(valid)

    def test_private_172_block_rejected(self):
        valid, _msg = _check_hostname("172.16.5.5")
        self.assertFalse(valid)

    def test_private_192_168_rejected(self):
        valid, _msg = _check_hostname("192.168.1.100")
        self.assertFalse(valid)

    def test_link_local_rejected(self):
        valid, _msg = _check_hostname("169.254.1.1")
        self.assertFalse(valid)

    def test_ipv6_loopback_rejected(self):
        valid, _msg = _check_hostname("::1")
        self.assertFalse(valid)

    def test_ipv4_mapped_ipv6_loopback_rejected(self):
        """::ffff:127.0.0.1 is the IPv4-mapped form of 127.0.0.1 and must be blocked."""
        valid, _msg = _check_hostname("::ffff:127.0.0.1")
        self.assertFalse(valid)

    def test_ipv4_mapped_ipv6_private_rejected(self):
        """::ffff:192.168.1.1 wraps a private IPv4 address and must be blocked."""
        valid, _msg = _check_hostname("::ffff:192.168.1.1")
        self.assertFalse(valid)

    def test_public_ip_allowed(self):
        """1.1.1.1 (Cloudflare) is a globally routable address — must be allowed."""
        valid, msg = _check_hostname("1.1.1.1")
        self.assertTrue(valid, msg)

    def test_hostname_resolving_to_private_ip_rejected(self):
        """Mock DNS resolution that returns a private IP must be blocked."""
        private_addr = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.50", 0))
        ]
        with unittest.mock.patch("socket.getaddrinfo", return_value=private_addr):
            valid, msg = _check_hostname("evil.example.com")
        self.assertFalse(valid)
        self.assertIn("reserved", msg.lower())

    def test_hostname_resolving_to_public_ip_allowed(self):
        """Mock DNS resolution that returns a public IP must be allowed."""
        public_addr = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))
        ]
        with unittest.mock.patch("socket.getaddrinfo", return_value=public_addr):
            valid, msg = _check_hostname("example.com")
        self.assertTrue(valid, msg)

    # ------------------------------------------------------------------ #
    #  Redirect URL policy                                                  #
    # ------------------------------------------------------------------ #

    def test_redirect_to_private_ip_rejected(self):
        private_addr = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.0.1", 0))
        ]
        with unittest.mock.patch("socket.getaddrinfo", return_value=private_addr):
            ok, reason = _validate_redirect_url("http://internal.corp/secret")
        self.assertFalse(ok)
        self.assertIn("blocked", reason.lower())

    def test_redirect_with_credentials_rejected(self):
        ok, reason = _validate_redirect_url("https://user:pass@example.com/")
        self.assertFalse(ok)
        self.assertIn("credentials", reason.lower())

    def test_redirect_ftp_scheme_rejected(self):
        ok, reason = _validate_redirect_url("ftp://example.com/file")
        self.assertFalse(ok)
        self.assertIn("scheme", reason.lower())

    def test_redirect_to_local_tld_rejected(self):
        ok, reason = _validate_redirect_url("http://db.internal/")
        self.assertFalse(ok)
        self.assertIn("internal", reason.lower())

    def test_redirect_to_public_url_allowed(self):
        public_addr = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))
        ]
        with unittest.mock.patch("socket.getaddrinfo", return_value=public_addr):
            ok, reason = _validate_redirect_url("https://example.com/page")
        self.assertTrue(ok, reason)

    # ------------------------------------------------------------------ #
    #  _safe_fetch — bounded read and response closure                      #
    # ------------------------------------------------------------------ #

    def test_safe_fetch_drains_bounded_body_and_closes(self):
        """
        _safe_fetch must:
        1. Call iter_content (not resp.content) on the final response.
        2. Close the response after draining.
        """
        mock_resp = _make_mock_response(200, {}, body=b"hello")

        with unittest.mock.patch("requests.Session.get", return_value=mock_resp):
            result = _safe_fetch("https://example.com")

        mock_resp.iter_content.assert_called()
        mock_resp.close.assert_called()
        self.assertIs(result, mock_resp)

    def test_safe_fetch_closes_redirect_response(self):
        """
        Intermediate redirect responses must be closed before following the
        redirect to avoid leaking connections.
        """
        public_addr = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))
        ]
        redirect_resp = _make_mock_response(
            301, {"Location": "https://example.com/final"}
        )
        final_resp = _make_mock_response(200, {})

        with unittest.mock.patch("socket.getaddrinfo", return_value=public_addr):
            with unittest.mock.patch(
                "requests.Session.get", side_effect=[redirect_resp, final_resp]
            ):
                result = _safe_fetch("https://example.com/")

        redirect_resp.close.assert_called()
        self.assertIs(result, final_resp)

    def test_safe_fetch_closes_response_on_exception(self):
        """
        If an exception is raised after the response is received, the response
        must still be closed.
        """
        # Return a redirect response with a private-IP destination.
        private_addr = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 0))
        ]
        redirect_resp = _make_mock_response(
            301, {"Location": "http://internal.example.com/"}
        )
        with unittest.mock.patch("socket.getaddrinfo", return_value=private_addr):
            with unittest.mock.patch(
                "requests.Session.get", return_value=redirect_resp
            ):
                with self.assertRaises(ValueError):
                    _safe_fetch("https://example.com/start")
        redirect_resp.close.assert_called()

    def test_drain_response_stops_at_max_bytes(self):
        """
        _drain_response must not read more than MAX_RESPONSE_BYTES.
        It counts bytes across chunks and stops early.
        """
        # Generate chunks that together exceed MAX_RESPONSE_BYTES
        chunk_size = 8192
        n_chunks = (MAX_RESPONSE_BYTES // chunk_size) + 10  # deliberately over limit
        chunks = [b"x" * chunk_size] * n_chunks

        mock_resp = unittest.mock.MagicMock(spec=requests.Response)
        mock_resp.iter_content.return_value = iter(chunks)
        mock_resp.close.return_value = None

        _drain_response(mock_resp)

        # iter_content was called; close was called in the finally block
        mock_resp.iter_content.assert_called_once_with(chunk_size=8192)
        mock_resp.close.assert_called_once()

    def test_drain_response_closes_on_exception(self):
        """_drain_response must close the response even if iter_content raises."""
        mock_resp = unittest.mock.MagicMock(spec=requests.Response)
        mock_resp.iter_content.side_effect = IOError("simulated read error")
        mock_resp.close.return_value = None

        with self.assertRaises(IOError):
            _drain_response(mock_resp)

        mock_resp.close.assert_called_once()

    # ------------------------------------------------------------------ #
    #  Header analysis                                                      #
    # ------------------------------------------------------------------ #

    def test_all_headers_missing_over_https(self):
        """With no security headers over HTTPS, all findings should be non-INFO."""
        findings = analyze_headers({}, response_scheme="https")
        for f in findings:
            self.assertFalse(f["present"])
            self.assertNotEqual(f["severity"], "INFO")

    def test_all_headers_present_good_values(self):
        """With all recommended headers set correctly, all should be INFO (pass)."""
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=()",
        }
        findings = analyze_headers(headers, response_scheme="https")
        for f in findings:
            self.assertTrue(f["present"])
            self.assertEqual(
                f["severity"], "INFO",
                f"{f['header']} should be INFO but got {f['severity']}: {f.get('quality_note')}",
            )

    def test_header_names_are_case_insensitive(self):
        """Headers sent in lowercase should be detected correctly."""
        findings = analyze_headers({"x-content-type-options": "nosniff"})
        xcto = next(f for f in findings if f["header"] == "X-Content-Type-Options")
        self.assertTrue(xcto["present"])

    def test_hsts_short_max_age_flagged(self):
        findings = analyze_headers(
            {"Strict-Transport-Security": "max-age=300"}, response_scheme="https"
        )
        hsts = next(f for f in findings if f["header"] == "Strict-Transport-Security")
        self.assertTrue(hsts["present"])
        self.assertNotEqual(hsts["severity"], "INFO")
        self.assertIn("max-age", hsts["quality_note"])

    def test_hsts_absent_over_http_is_medium_not_high(self):
        """
        HSTS is only enforceable over HTTPS.  When the scan target is HTTP,
        the absence of HSTS should be MEDIUM (not HIGH) because the header
        cannot be honoured by browsers anyway.
        """
        findings = analyze_headers({}, response_scheme="http")
        hsts = next(f for f in findings if f["header"] == "Strict-Transport-Security")
        self.assertFalse(hsts["present"])
        self.assertEqual(hsts["severity"], "MEDIUM",
            "HSTS missing over HTTP should be MEDIUM, not HIGH")

    def test_hsts_present_over_http_flagged(self):
        """
        An HSTS header on a plain HTTP response is browser-ignored; we should
        flag it with a quality note.
        """
        findings = analyze_headers(
            {"Strict-Transport-Security": "max-age=31536000"}, response_scheme="http"
        )
        hsts = next(f for f in findings if f["header"] == "Strict-Transport-Security")
        self.assertTrue(hsts["present"])
        self.assertNotEqual(hsts["quality_note"], "")
        self.assertIn("HTTP", hsts["quality_note"])

    def test_hsts_absent_over_https_is_high(self):
        """HSTS absent over HTTPS must remain HIGH severity."""
        findings = analyze_headers({}, response_scheme="https")
        hsts = next(f for f in findings if f["header"] == "Strict-Transport-Security")
        self.assertEqual(hsts["severity"], "HIGH")

    def test_csp_unsafe_inline_flagged(self):
        findings = analyze_headers({
            "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'"
        })
        csp = next(f for f in findings if f["header"] == "Content-Security-Policy")
        self.assertTrue(csp["present"])
        self.assertIn("unsafe-inline", csp["quality_note"])

    def test_x_content_type_wrong_value_flagged(self):
        findings = analyze_headers({"X-Content-Type-Options": "sniff"})
        xcto = next(f for f in findings if f["header"] == "X-Content-Type-Options")
        self.assertIn("nosniff", xcto["quality_note"])

    def test_x_frame_options_invalid_value_flagged(self):
        findings = analyze_headers({"X-Frame-Options": "ALLOWALL"})
        xfo = next(f for f in findings if f["header"] == "X-Frame-Options")
        self.assertNotEqual(xfo["quality_note"], "")

    def test_findings_sorted_by_severity(self):
        """Missing HIGH headers should appear before missing LOW headers."""
        findings = analyze_headers({}, response_scheme="https")
        high_indices = [i for i, f in enumerate(findings) if f["severity"] == "HIGH"]
        low_indices  = [i for i, f in enumerate(findings) if f["severity"] == "LOW"]
        if high_indices and low_indices:
            self.assertLess(min(high_indices), max(low_indices))

    # ------------------------------------------------------------------ #
    #  CORS analysis                                                        #
    # ------------------------------------------------------------------ #

    def test_cors_wildcard_flagged(self):
        result = analyze_cors({"Access-Control-Allow-Origin": "*"}, CORS_TEST_ORIGIN)
        self.assertIn(result["severity"], ("MEDIUM", "HIGH"))
        self.assertGreater(len(result["issues"]), 0)

    def test_cors_reflection_with_credentials_is_high(self):
        result = analyze_cors({
            "Access-Control-Allow-Origin": CORS_TEST_ORIGIN,
            "Access-Control-Allow-Credentials": "true",
        }, CORS_TEST_ORIGIN)
        self.assertEqual(result["severity"], "HIGH")

    def test_cors_no_headers_info(self):
        """No CORS headers at all → severity INFO, one informational note."""
        result = analyze_cors({}, CORS_TEST_ORIGIN)
        self.assertEqual(result["severity"], "INFO")
        self.assertEqual(len(result["issues"]), 1)

    def test_cors_missing_vary_origin_flagged(self):
        result = analyze_cors({
            "Access-Control-Allow-Origin": "https://trusted.example.com",
        }, CORS_TEST_ORIGIN)
        vary_issue = any("Vary" in i for i in result["issues"])
        self.assertTrue(vary_issue)

    def test_cors_wildcard_with_credentials_flagged(self):
        result = analyze_cors({
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }, CORS_TEST_ORIGIN)
        self.assertEqual(result["severity"], "HIGH")
        critical_issue = any("CRITICAL" in i for i in result["issues"])
        self.assertTrue(critical_issue)

    # ------------------------------------------------------------------ #
    #  Score / summary calculation                                          #
    # ------------------------------------------------------------------ #

    def test_score_perfect(self):
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=()",
        }
        findings = analyze_headers(headers, response_scheme="https")
        cors = analyze_cors({}, CORS_TEST_ORIGIN)
        summary = calculate_score(findings, cors)
        self.assertEqual(summary["grade"], "A")
        self.assertGreaterEqual(summary["score"], 90)

    def test_score_all_missing(self):
        findings = analyze_headers({}, response_scheme="https")
        cors = analyze_cors({
            "Access-Control-Allow-Origin": CORS_TEST_ORIGIN,
            "Access-Control-Allow-Credentials": "true",
        }, CORS_TEST_ORIGIN)
        summary = calculate_score(findings, cors)
        self.assertLess(summary["score"], 40)
        self.assertEqual(summary["grade"], "F")

    def test_score_bounds(self):
        """Score must always be in [0, 100]."""
        findings = analyze_headers({}, response_scheme="https")
        cors = analyze_cors({
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }, CORS_TEST_ORIGIN)
        summary = calculate_score(findings, cors)
        self.assertGreaterEqual(summary["score"], 0)
        self.assertLessEqual(summary["score"], 100)

    # ------------------------------------------------------------------ #
    #  Demo mode                                                            #
    # ------------------------------------------------------------------ #

    def test_demo_result_structure(self):
        result = get_demo_result()
        self.assertIn("header_findings", result)
        self.assertIn("cors_finding", result)
        self.assertIn("summary", result)
        self.assertTrue(result["is_demo"])

    def test_demo_result_no_network(self):
        """get_demo_result must not make any network calls."""
        with unittest.mock.patch("socket.getaddrinfo", side_effect=OSError("blocked")):
            result = get_demo_result()
        self.assertTrue(result["is_demo"])

    # ------------------------------------------------------------------ #
    #  API input validation                                                 #
    # ------------------------------------------------------------------ #

    def test_api_scan_empty_body_returns_400(self):
        with app.test_client() as client:
            resp = client.post("/api/scan", data=b"", content_type="application/json")
        self.assertEqual(resp.status_code, 400)
        body = resp.get_json()
        self.assertIn("error", body)

    def test_api_scan_invalid_json_returns_400(self):
        with app.test_client() as client:
            resp = client.post(
                "/api/scan", data=b"not json", content_type="application/json"
            )
        self.assertEqual(resp.status_code, 400)
        body = resp.get_json()
        self.assertIn("error", body)

    def test_api_scan_json_array_returns_400(self):
        with app.test_client() as client:
            resp = client.post(
                "/api/scan",
                data=json.dumps(["https://example.com"]).encode(),
                content_type="application/json",
            )
        self.assertEqual(resp.status_code, 400)
        body = resp.get_json()
        self.assertIn("error", body)
        self.assertIn("object", body["error"].lower())

    def test_api_scan_missing_url_field_returns_400(self):
        with app.test_client() as client:
            resp = client.post(
                "/api/scan",
                data=json.dumps({"target": "https://example.com"}).encode(),
                content_type="application/json",
            )
        self.assertEqual(resp.status_code, 400)
        body = resp.get_json()
        self.assertIn("error", body)
        self.assertIn("url", body["error"].lower())

    def test_api_scan_non_string_url_returns_400(self):
        with app.test_client() as client:
            resp = client.post(
                "/api/scan",
                data=json.dumps({"url": 12345}).encode(),
                content_type="application/json",
            )
        self.assertEqual(resp.status_code, 400)
        body = resp.get_json()
        self.assertIn("error", body)
        self.assertIn("string", body["error"].lower())

    def test_api_scan_null_url_returns_400(self):
        with app.test_client() as client:
            resp = client.post(
                "/api/scan",
                data=json.dumps({"url": None}).encode(),
                content_type="application/json",
            )
        self.assertEqual(resp.status_code, 400)
        body = resp.get_json()
        self.assertIn("error", body)

    # ------------------------------------------------------------------ #
    #  validate_url — embedded credentials                                  #
    # ------------------------------------------------------------------ #

    def test_validate_url_rejects_username_in_url(self):
        """https://user@example.com/ must be rejected regardless of DNS."""
        valid, msg = validate_url("https://user@example.com/path")
        self.assertFalse(valid)
        self.assertIn("credentials", msg.lower())

    def test_validate_url_rejects_username_and_password_in_url(self):
        """https://user:secret@example.com/ must be rejected regardless of DNS."""
        valid, msg = validate_url("https://user:secret@example.com/")
        self.assertFalse(valid)
        self.assertIn("credentials", msg.lower())

    def test_validate_url_without_credentials_still_allowed(self):
        """A normal URL without credentials passes the credentials check."""
        public_addr = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))
        ]
        with unittest.mock.patch("socket.getaddrinfo", return_value=public_addr):
            valid, result = validate_url("https://example.com/path?q=1")
        self.assertTrue(valid, result)

    # ------------------------------------------------------------------ #
    #  Scoring consistency — HSTS severity vs score deduction              #
    # ------------------------------------------------------------------ #

    def test_hsts_http_severity_and_score_agree(self):
        """
        Regression: when HSTS is missing over HTTP, analyze_headers() reports
        MEDIUM.  calculate_score() must deduct as MEDIUM (12 pts), not as HIGH
        (20 pts).  Both observations must agree so the badge and the score tell
        the same story.
        """
        findings_http = analyze_headers({}, response_scheme="http")
        hsts_finding = next(
            f for f in findings_http if f["header"] == "Strict-Transport-Security"
        )
        # Displayed severity must be MEDIUM
        self.assertEqual(hsts_finding["severity"], "MEDIUM",
            "analyze_headers() should report MEDIUM for missing HSTS over HTTP")

        cors_info = analyze_cors({}, CORS_TEST_ORIGIN)  # no CORS impact

        # Score over HTTP (all headers missing)
        score_http = calculate_score(findings_http, cors_info)["score"]

        # Score over HTTPS (all headers missing) — HSTS now deducts HIGH (20)
        findings_https = analyze_headers({}, response_scheme="https")
        score_https = calculate_score(findings_https, cors_info)["score"]

        # Over HTTP, HSTS deducts 12 (MEDIUM); over HTTPS it deducts 20 (HIGH).
        # So score_http must be 8 points higher than score_https.
        expected_diff = 20 - 12  # HIGH deduction minus MEDIUM deduction
        self.assertEqual(
            score_http - score_https, expected_diff,
            f"score_http={score_http}, score_https={score_https}; "
            f"expected difference of {expected_diff} (MEDIUM vs HIGH deduction)"
        )

    def test_hsts_https_severity_and_score_are_high(self):
        """
        When HSTS is missing over HTTPS, the severity badge is HIGH and the
        score deduction is 20 points.
        """
        findings = analyze_headers({}, response_scheme="https")
        hsts = next(f for f in findings if f["header"] == "Strict-Transport-Security")
        self.assertEqual(hsts["severity"], "HIGH")

        # Only HSTS missing, no CORS issues — deduction should be exactly 20
        only_hsts = [hsts]
        cors_info = analyze_cors({}, CORS_TEST_ORIGIN)
        score = calculate_score(only_hsts, cors_info)["score"]
        self.assertEqual(score, 80,
            "Sole deduction: HIGH HSTS missing = 20 pts; 100 - 20 = 80")

    # ------------------------------------------------------------------ #
    #  IP validation — is_global + mixed DNS result sets                   #
    # ------------------------------------------------------------------ #

    def test_is_blocked_ip_rejects_loopback_via_is_global(self):
        """127.0.0.1 is not globally routable; is_global=False must block it."""
        blocked, reason = _is_blocked_ip(ipaddress.ip_address("127.0.0.1"))
        self.assertTrue(blocked)
        self.assertIn("globally", reason.lower())

    def test_is_blocked_ip_rejects_private_10_via_is_global(self):
        """10.x.x.x is not globally routable."""
        blocked, _reason = _is_blocked_ip(ipaddress.ip_address("10.1.2.3"))
        self.assertTrue(blocked)

    def test_is_blocked_ip_rejects_link_local_via_is_global(self):
        """169.254.x.x is not globally routable."""
        blocked, _reason = _is_blocked_ip(ipaddress.ip_address("169.254.1.1"))
        self.assertTrue(blocked)

    def test_is_blocked_ip_allows_public_ipv4(self):
        """93.184.216.34 (example.com) is globally routable."""
        blocked, _reason = _is_blocked_ip(ipaddress.ip_address("93.184.216.34"))
        self.assertFalse(blocked)

    def test_is_blocked_ip_rejects_ipv6_loopback_via_is_global(self):
        """::1 is not globally routable."""
        blocked, _reason = _is_blocked_ip(ipaddress.ip_address("::1"))
        self.assertTrue(blocked)

    def test_is_blocked_ip_rejects_ipv4_mapped_loopback(self):
        """::ffff:127.0.0.1 unwraps to 127.0.0.1 which is not globally routable."""
        blocked, _reason = _is_blocked_ip(ipaddress.ip_address("::ffff:127.0.0.1"))
        self.assertTrue(blocked)

    def test_is_blocked_ip_rejects_ipv4_mapped_private(self):
        """::ffff:10.0.0.1 unwraps to 10.0.0.1 which is not globally routable."""
        blocked, _reason = _is_blocked_ip(ipaddress.ip_address("::ffff:10.0.0.1"))
        self.assertTrue(blocked)

    def test_check_hostname_mixed_dns_result_rejected(self):
        """
        If getaddrinfo returns a mix of public and private addresses (e.g. an
        A record pointing to a CDN plus an internal CNAME resolution artefact),
        _check_hostname must reject the hostname because at least one address
        is non-global.  A scanner must never proceed when any resolved address
        is internal.
        """
        mixed_addrs = [
            # Public address first
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            # Private address second — must cause rejection
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.50", 0)),
        ]
        with unittest.mock.patch("socket.getaddrinfo", return_value=mixed_addrs):
            valid, msg = _check_hostname("mixed.example.com")
        self.assertFalse(valid,
            "A hostname resolving to any non-global address must be rejected")
        self.assertIn("reserved", msg.lower())

    def test_check_hostname_all_public_dns_allowed(self):
        """All-public DNS result set must be accepted."""
        all_public = [
            (socket.AF_INET,  socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", 0)),
        ]
        with unittest.mock.patch("socket.getaddrinfo", return_value=all_public):
            valid, msg = _check_hostname("example.com")
        self.assertTrue(valid, msg)

    def test_redirect_to_private_ip_rejected_via_is_global(self):
        """
        _validate_redirect_url must block a redirect to a private IP via
        _check_hostname / _is_blocked_ip (is_global path, not just BLOCKED_NETWORKS).
        """
        private_addr = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("172.16.0.5", 0))
        ]
        with unittest.mock.patch("socket.getaddrinfo", return_value=private_addr):
            ok, reason = _validate_redirect_url("http://internal.host/page")
        self.assertFalse(ok)
        self.assertIn("blocked", reason.lower())

    # ------------------------------------------------------------------ #
    #  Severity helper                                                      #
    # ------------------------------------------------------------------ #

    def test_severity_upgrade(self):
        self.assertEqual(_upgrade_severity("LOW", "HIGH"), "HIGH")
        self.assertEqual(_upgrade_severity("HIGH", "LOW"), "HIGH")
        self.assertEqual(_upgrade_severity("MEDIUM", "MEDIUM"), "MEDIUM")
        self.assertEqual(_upgrade_severity("INFO", "LOW"), "LOW")


# ---------------------------------------------------------------------------
# 10. __main__ entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        # Strip the "test" argument so unittest doesn't try to interpret it.
        sys.argv.pop(1)
        unittest.main(verbosity=2)
    else:
        print("HeaderHawk — HTTP Security Header Scanner")
        print("==========================================")
        print("Starting Flask development server on http://127.0.0.1:5000")
        print("Press Ctrl+C to stop.\n")
        app.run(debug=False, host="127.0.0.1", port=5000)
