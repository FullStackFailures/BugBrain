from urllib.parse import urlparse, parse_qsl
import re


API_PATTERNS = (
    "/api/",
    "/api-",
    "/rest/",
    "/graphql",
    "/gql",
    "/rpc/",
    "/json/",
    "/ajax/",
    "/service/",
    "/services/",
)


DOCUMENTATION_PATTERNS = (
    "/swagger",
    "/swagger-ui",
    "/openapi",
    "/api-docs",
    "/apidocs",
    "/redoc",
    "/docs",
)


AUTH_PATTERNS = (
    "/login",
    "/signin",
    "/signup",
    "/register",
    "/logout",
    "/oauth",
    "/authorize",
    "/token",
    "/callback",
    "/sso",
    "/saml",
    "/oidc",
)


ADMIN_PATTERNS = (
    "/admin",
    "/administrator",
    "/manage",
    "/management",
    "/staff",
    "/moderator",
    "/operator",
    "/internal",
)


DEBUG_PATTERNS = (
    "/debug",
    "/metrics",
    "/health",
    "/healthz",
    "/ready",
    "/readiness",
    "/actuator",
    "/actuator/env",
    "/server-status",
    "/server-info",
    "/phpinfo",
)


WEBHOOK_PATTERNS = (
    "/webhook",
    "/webhooks",
    "/callback",
    "/callbacks",
)


SENSITIVE_PARAMETER_NAMES = {
    "id",
    "user_id",
    "account_id",
    "customer_id",
    "order_id",
    "invoice_id",
    "document_id",
    "file_id",
    "project_id",
    "tenant_id",
    "organization_id",
    "owner_id",
    "redirect",
    "redirect_uri",
    "return_url",
    "callback",
    "callback_url",
    "next",
    "url",
    "uri",
    "target",
    "file",
    "path",
}


def _candidate(
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
        "confidence": 0.50,
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


def _classify_path(path):
    value = path.lower()

    if any(item in value for item in API_PATTERNS):
        return "api"

    if any(item in value for item in DOCUMENTATION_PATTERNS):
        return "api_documentation"

    if any(item in value for item in AUTH_PATTERNS):
        return "authentication"

    if any(item in value for item in ADMIN_PATTERNS):
        return "privileged"

    if any(item in value for item in DEBUG_PATTERNS):
        return "debug_or_management"

    if any(item in value for item in WEBHOOK_PATTERNS):
        return "webhook"

    return None


def analyze(target, recon=None, http_results=None):
    recon = recon or {}
    http_results = http_results or []

    findings = []

    urls = set()

    for url in recon.get("urls") or []:
        if url:
            urls.add(url)

    for result in http_results:
        url = result.get("url")

        if url:
            urls.add(url)

    # --------------------------------------------------
    # Analyze discovered URLs
    # --------------------------------------------------

    for url in sorted(urls):
        parsed = urlparse(url)
        path = parsed.path or "/"

        category = _classify_path(path)

        if category == "api":
            findings.append(
                _candidate(
                    target,
                    url,
                    "api_endpoint_surface",
                    "API endpoint surface discovered",
                    "info",
                    f"API-like path: {path}",
                    "The application exposes a path consistent with an API endpoint.",
                    "Inventory the endpoint and verify authentication and authorization controls.",
                )
            )

        elif category == "api_documentation":
            findings.append(
                _candidate(
                    target,
                    url,
                    "api_documentation_surface",
                    "API documentation surface discovered",
                    "low",
                    f"Documentation-like path: {path}",
                    "An API documentation or schema endpoint was discovered.",
                    "Ensure API documentation does not expose sensitive implementation details or unauthorized operations.",
                )
            )

        elif category == "authentication":
            findings.append(
                _candidate(
                    target,
                    url,
                    "authentication_surface",
                    "Authentication endpoint discovered",
                    "info",
                    f"Authentication-related path: {path}",
                    "An authentication or identity-management endpoint was discovered.",
                    "Review authentication, session, authorization, and rate-control behavior.",
                )
            )

        elif category == "privileged":
            findings.append(
                _candidate(
                    target,
                    url,
                    "privileged_endpoint_surface",
                    "Privileged endpoint discovered",
                    "medium",
                    f"Privileged-looking path: {path}",
                    "The endpoint appears associated with administrative or privileged functionality.",
                    "Verify server-side authorization for the endpoint.",
                )
            )

        elif category == "debug_or_management":
            findings.append(
                _candidate(
                    target,
                    url,
                    "debug_management_surface",
                    "Debug or management endpoint discovered",
                    "medium",
                    f"Management/debug path: {path}",
                    "The endpoint appears related to operational, diagnostic, or management functionality.",
                    "Restrict diagnostic and management interfaces to authorized users.",
                )
            )

        elif category == "webhook":
            findings.append(
                _candidate(
                    target,
                    url,
                    "webhook_surface",
                    "Webhook/callback surface discovered",
                    "medium",
                    f"Webhook-like path: {path}",
                    "The application exposes a webhook or callback-style endpoint.",
                    "Review authentication, signatures, replay protection, and destination validation.",
                )
            )

        # --------------------------------------------------
        # Query parameter intelligence
        # --------------------------------------------------

        parameters = {
            key.lower()
            for key, _ in parse_qsl(
                parsed.query,
                keep_blank_values=True,
            )
        }

        sensitive = sorted(
            parameters.intersection(
                SENSITIVE_PARAMETER_NAMES
            )
        )

        if sensitive:
            findings.append(
                _candidate(
                    target,
                    url,
                    "sensitive_parameter_surface",
                    "Security-sensitive URL parameters discovered",
                    "low",
                    "Parameters: " + ", ".join(sensitive),
                    "The endpoint accepts parameters commonly associated with object references, redirects, files, or callbacks.",
                    "Review authorization, input validation, redirect validation, and object ownership checks.",
                )
            )

    # --------------------------------------------------
    # Recon API endpoints
    # --------------------------------------------------

    for endpoint in recon.get("api_endpoints") or []:
        if not endpoint:
            continue

        findings.append(
            _candidate(
                target,
                endpoint,
                "api_endpoint_inventory",
                "API endpoint recorded by reconnaissance",
                "info",
                f"Recon API endpoint: {endpoint}",
                "Reconnaissance identified an API endpoint.",
                "Inventory the endpoint and verify authentication and authorization.",
            )
        )

    # --------------------------------------------------
    # JavaScript-discovered routes
    # --------------------------------------------------

    javascript_records = []

    javascript_records.extend(
        recon.get("javascript") or []
    )

    for record in javascript_records:
        if not isinstance(record, dict):
            continue

        for discovered in record.get("urls") or []:
            if not discovered:
                continue

            category = _classify_path(
                urlparse(discovered).path
            )

            if category:
                findings.append(
                    _candidate(
                        target,
                        discovered,
                        "javascript_route_surface",
                        "Security-relevant route discovered in JavaScript",
                        "info",
                        f"JavaScript-discovered route: {discovered}",
                        "Client-side JavaScript references a security-relevant route.",
                        "Include client-discovered routes in the server-side security review.",
                    )
                )

    # --------------------------------------------------
    # WebSocket inventory
    # --------------------------------------------------

    for websocket in recon.get("websocket_urls") or []:
        findings.append(
            _candidate(
                target,
                websocket,
                "websocket_surface",
                "WebSocket endpoint discovered",
                "medium",
                f"WebSocket URL: {websocket}",
                "A WebSocket communication surface was discovered.",
                "Review authentication, authorization, origin validation, and message-level access controls.",
            )
        )

    return _deduplicate(findings)
