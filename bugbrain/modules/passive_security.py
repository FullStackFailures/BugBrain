from urllib.parse import urlparse


INTERESTING_HEADERS = {
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-generator",
}


SENSITIVE_PATHS = {
    "/.env",
    "/.git/config",
    "/config.php",
    "/wp-config.php",
    "/debug",
    "/phpinfo.php",
    "/server-status",
    "/server-info",
    "/actuator",
    "/actuator/env",
}


DANGEROUS_METHODS = {
    "PUT",
    "DELETE",
    "TRACE",
}


def _finding(
    target,
    url,
    finding_type,
    title,
    severity,
    evidence,
    summary,
    remediation,
):
    return {
        "target": target,
        "url": url,
        "type": finding_type,
        "title": title,
        "severity": severity,
        "status": "candidate",
        "confidence": 0.60,
        "evidence": evidence,
        "summary": summary,
        "remediation": remediation,
    }


def _deduplicate(findings):
    seen = set()
    output = []

    for finding in findings:
        key = (
            finding.get("type"),
            finding.get("url"),
            finding.get("title"),
        )

        if key in seen:
            continue

        seen.add(key)
        output.append(finding)

    return output


def analyze(target, http_results):
    findings = []

    for result in http_results or []:
        url = result.get("url", "")

        if not url:
            continue

        parsed = urlparse(url)

        headers = {
            str(key).lower(): str(value)
            for key, value in (result.get("headers") or {}).items()
        }

        status = int(result.get("status", 0) or 0)

        body = str(result.get("body", "") or "")

        # --------------------------------------------------
        # Server / technology information disclosure
        # --------------------------------------------------

        for header in INTERESTING_HEADERS:
            if header not in headers:
                continue

            value = headers[header]

            findings.append(
                _finding(
                    target=target,
                    url=url,
                    finding_type="server_information_disclosure",
                    title=f"Technology/version disclosure through {header}",
                    severity="low",
                    evidence=f"{header}: {value}",
                    summary=(
                        "The response exposes server or technology "
                        "information."
                    ),
                    remediation=(
                        "Remove unnecessary technology/version "
                        "information from HTTP responses."
                    ),
                )
            )

        # --------------------------------------------------
        # HSTS
        # --------------------------------------------------

        if parsed.scheme == "https":
            if "strict-transport-security" not in headers:
                findings.append(
                    _finding(
                        target=target,
                        url=url,
                        finding_type="missing_hsts",
                        title="Strict-Transport-Security header missing",
                        severity="medium",
                        evidence=(
                            "HTTPS response does not contain "
                            "Strict-Transport-Security."
                        ),
                        summary=(
                            "The HTTPS endpoint does not advertise "
                            "HSTS."
                        ),
                        remediation=(
                            "Configure an appropriate "
                            "Strict-Transport-Security policy."
                        ),
                    )
                )

        # --------------------------------------------------
        # Cookie security
        # --------------------------------------------------

        set_cookie = headers.get("set-cookie", "")

        if set_cookie:
            cookie_lower = set_cookie.lower()

            if (
                parsed.scheme == "https"
                and "secure" not in cookie_lower
            ):
                findings.append(
                    _finding(
                        target=target,
                        url=url,
                        finding_type="cookie_missing_secure",
                        title="HTTPS cookie without Secure attribute",
                        severity="medium",
                        evidence=f"Set-Cookie: {set_cookie}",
                        summary=(
                            "A cookie was observed over HTTPS without "
                            "the Secure attribute."
                        ),
                        remediation=(
                            "Set the Secure attribute on sensitive "
                            "cookies."
                        ),
                    )
                )

            if "httponly" not in cookie_lower:
                findings.append(
                    _finding(
                        target=target,
                        url=url,
                        finding_type="cookie_missing_httponly",
                        title="Cookie without HttpOnly attribute",
                        severity="low",
                        evidence=f"Set-Cookie: {set_cookie}",
                        summary=(
                            "A cookie was observed without HttpOnly."
                        ),
                        remediation=(
                            "Use HttpOnly for cookies that do not "
                            "need JavaScript access."
                        ),
                    )
                )

            if "samesite" not in cookie_lower:
                findings.append(
                    _finding(
                        target=target,
                        url=url,
                        finding_type="cookie_missing_samesite",
                        title="Cookie without SameSite attribute",
                        severity="low",
                        evidence=f"Set-Cookie: {set_cookie}",
                        summary=(
                            "A cookie was observed without SameSite."
                        ),
                        remediation=(
                            "Configure an appropriate SameSite policy."
                        ),
                    )
                )

        # --------------------------------------------------
        # CORS
        # --------------------------------------------------

        acao = headers.get(
            "access-control-allow-origin"
        )

        if acao == "*":
            findings.append(
                _finding(
                    target=target,
                    url=url,
                    finding_type="cors_wildcard",
                    title="Wildcard CORS policy",
                    severity="low",
                    evidence=(
                        "Access-Control-Allow-Origin: *"
                    ),
                    summary=(
                        "The endpoint permits cross-origin requests "
                        "from any origin."
                    ),
                    remediation=(
                        "Restrict CORS to trusted origins when "
                        "cross-origin access is required."
                    ),
                )
            )

        # --------------------------------------------------
        # HTTP methods
        # --------------------------------------------------

        allow = headers.get("allow", "")

        if allow:
            methods = {
                item.strip().upper()
                for item in allow.split(",")
            }

            dangerous = sorted(
                methods.intersection(DANGEROUS_METHODS)
            )

            if dangerous:
                findings.append(
                    _finding(
                        target=target,
                        url=url,
                        finding_type="dangerous_http_methods",
                        title=(
                            "Potentially dangerous HTTP methods exposed"
                        ),
                        severity="medium",
                        evidence=f"Allow: {allow}",
                        summary=(
                            "The endpoint advertises HTTP methods: "
                            + ", ".join(dangerous)
                            + "."
                        ),
                        remediation=(
                            "Disable unnecessary HTTP methods and "
                            "verify that dangerous methods require "
                            "appropriate authorization."
                        ),
                    )
                )

        # --------------------------------------------------
        # Sensitive endpoint exposure
        # --------------------------------------------------

        path = parsed.path.rstrip("/") or "/"

        if path in SENSITIVE_PATHS:
            if status not in {404, 410}:
                findings.append(
                    _finding(
                        target=target,
                        url=url,
                        finding_type="sensitive_file_exposure",
                        title=(
                            "Potentially sensitive endpoint accessible"
                        ),
                        severity="medium",
                        evidence=(
                            f"HTTP status: {status} for {path}"
                        ),
                        summary=(
                            "A commonly sensitive path returned a "
                            "response other than 404/410."
                        ),
                        remediation=(
                            "Verify whether the resource is intended "
                            "to be publicly accessible and restrict "
                            "it if necessary."
                        ),
                    )
                )

        # --------------------------------------------------
        # Debug / error disclosure
        # --------------------------------------------------

        body_lower = body.lower()

        indicators = [
            "traceback (most recent call last)",
            "stack trace",
            "debug mode",
            "exception at",
            "fatal error",
            "sql syntax",
        ]

        matched = [
            indicator
            for indicator in indicators
            if indicator in body_lower
        ]

        if matched:
            findings.append(
                _finding(
                    target=target,
                    url=url,
                    finding_type="error_information_disclosure",
                    title="Potential error/debug information disclosure",
                    severity="medium",
                    evidence=(
                        "Response contains indicators: "
                        + ", ".join(matched)
                    ),
                    summary=(
                        "The response appears to expose internal "
                        "error or debugging information."
                    ),
                    remediation=(
                        "Disable debug output and return generic "
                        "production error responses."
                    ),
                )
            )

    return _deduplicate(findings)
