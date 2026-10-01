from urllib.parse import urlparse


AUTH_WORDS = (
    "login",
    "signin",
    "sign-in",
    "auth",
    "authenticate",
    "oauth",
    "sso",
)

ADMIN_WORDS = (
    "admin",
    "administrator",
    "dashboard",
    "manage",
    "management",
)

SENSITIVE_INPUTS = (
    "password",
    "passwd",
    "token",
    "secret",
    "session",
    "authorization",
    "username",
    "email",
)


def _finding(
    target,
    title,
    finding_type,
    url,
    evidence,
    summary,
    impact,
    remediation,
    confidence=0.85,
):
    return {
        "target": target,
        "url": url,
        "type": finding_type,
        "title": title,
        "severity": "info",
        "confidence": confidence,
        "summary": summary,
        "evidence": evidence,
        "impact": impact,
        "remediation": remediation,
    }


def analyze(target, recon, http_results):
    findings = []

    seen = set()

    # ---------------------------------------------------------
    # Discovered URLs
    # ---------------------------------------------------------

    for url in recon.get("urls", []):

        parsed = urlparse(url)
        path = parsed.path.lower()

        if not path:
            continue

        for word in AUTH_WORDS:

            if word not in path:
                continue

            key = ("auth", url)

            if key in seen:
                break

            seen.add(key)

            findings.append(
                _finding(
                    target,
                    "Authentication endpoint discovered",
                    "authentication_surface",
                    url,
                    f"URL path contains authentication keyword: {word}",
                    "An authentication-related endpoint was discovered.",
                    "Authentication endpoints should enforce appropriate authentication, session, CSRF, and rate-limiting controls.",
                    "Manually review the authentication flow and its security controls.",
                    0.90,
                )
            )

            break

        for word in ADMIN_WORDS:

            if word not in path:
                continue

            key = ("admin", url)

            if key in seen:
                break

            seen.add(key)

            findings.append(
                _finding(
                    target,
                    "Administrative endpoint discovered",
                    "administrative_surface",
                    url,
                    f"URL path contains administrative keyword: {word}",
                    "An administrative or management-related endpoint was discovered.",
                    "Administrative functionality should enforce server-side authentication and authorization.",
                    "Manually verify that unauthorized users cannot access administrative functionality.",
                    0.88,
                )
            )

            break

    # ---------------------------------------------------------
    # Forms
    # ---------------------------------------------------------

    for form in recon.get("forms", []):

        action = form.get("action", "")
        inputs = form.get("inputs", [])

        names = []

        for field in inputs:
            name = field.get("name", "").strip().lower()

            if name:
                names.append(name)

        sensitive = [
            name
            for name in names
            if any(
                keyword in name
                for keyword in SENSITIVE_INPUTS
            )
        ]

        if sensitive:

            findings.append(
                _finding(
                    target,
                    "Sensitive authentication form discovered",
                    "authentication_form",
                    action,
                    f"Sensitive fields: {', '.join(sensitive)}",
                    "A form contains fields associated with authentication or credentials.",
                    "Credential-handling forms require appropriate transport security, session protection, CSRF protection, and server-side validation.",
                    "Manually review the complete authentication flow and session controls.",
                    0.95,
                )
            )

    # ---------------------------------------------------------
    # HTTP response observations
    # ---------------------------------------------------------

    for result in http_results:

        if result.get("error"):
            continue

        url = result.get("url", "")
        status = result.get("status")

        parsed = urlparse(url)
        path = parsed.path.lower()

        is_sensitive = any(
            word in path
            for word in (
                *AUTH_WORDS,
                *ADMIN_WORDS,
            )
        )

        if not is_sensitive:
            continue

        # This is an observation only.
        # A 2xx response does NOT prove an access-control vulnerability.
        if status and 200 <= status < 300:

            findings.append(
                _finding(
                    target,
                    "Sensitive endpoint returned a successful response",
                    "access_control_candidate",
                    url,
                    f"HTTP status: {status}",
                    "A potentially authentication-sensitive endpoint returned a successful HTTP response.",
                    "If the endpoint exposes privileged functionality without appropriate authorization, it could represent an access-control issue.",
                    "Manually verify the endpoint's authorization requirements using an authorized test account or explicitly permitted test procedure.",
                    0.65,
                )
            )

    return findings
