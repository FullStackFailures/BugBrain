from urllib.parse import urlparse, parse_qsl
import re


API_VERSION_RE = re.compile(
    r"/(?:api/)?v(?:0|1|2|3|4|5|6|7|8|9)(?:/|$)",
    re.I,
)

OBJECT_ID_RE = re.compile(
    r"/(?:users?|accounts?|customers?|orders?|"
    r"profiles?|documents?|files?|projects?|"
    r"organizations?|tenants?|payments?|invoices?|"
    r"messages?|tickets?|products?)/"
    r"(?:[A-Za-z0-9_-]{2,}|[0-9]+)(?:/|$)",
    re.I,
)

GRAPHQL_RE = re.compile(
    r"(?:/graphql(?:/|$)|graphql)",
    re.I,
)

PRIVILEGED_RE = re.compile(
    r"/(?:admin|administrator|manage|management|"
    r"staff|internal|private|moderator|ops|operator)(?:/|$)",
    re.I,
)

SENSITIVE_FLOW_RE = re.compile(
    r"/(?:password|passwd|reset|forgot|"
    r"invite|invitation|verify|verification|"
    r"transfer|payment|payout|refund|checkout|"
    r"withdraw|deposit|email|phone|mfa|2fa)(?:/|$)",
    re.I,
)

WEBHOOK_RE = re.compile(
    r"/(?:webhook|webhooks|callback|callbacks)(?:/|$)",
    re.I,
)

DEBUG_RE = re.compile(
    r"/(?:actuator|metrics|health|debug|"
    r"phpinfo|server-status|server-info)(?:/|$)",
    re.I,
)

STORAGE_RE = re.compile(
    r"(?:s3\.amazonaws\.com|storage\.googleapis\.com|"
    r"blob\.core\.windows\.net|bucket|s3|gcs|azureblob)",
    re.I,
)

OAUTH_RE = re.compile(
    r"/(?:oauth|authorize|authorization|token|"
    r"openid|oidc|\.well-known/openid-configuration)(?:/|$)",
    re.I,
)

JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.",
)

MASS_ASSIGNMENT_KEYS = {
    "role",
    "roles",
    "admin",
    "is_admin",
    "permissions",
    "permission",
    "owner",
    "owner_id",
    "user_id",
    "account_id",
    "tenant_id",
    "organization_id",
    "status",
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
        "confidence": 0.55,
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


def analyze(target, http_results, recon=None):
    findings = []

    recon = recon or {}

    urls = set(
        recon.get("urls") or []
    )

    for result in http_results or []:
        url = result.get("url", "")

        if not url:
            continue

        urls.add(url)

    for url in sorted(urls):
        parsed = urlparse(url)

        path = parsed.path or "/"
        path_lower = path.lower()

        query = dict(
            parse_qsl(
                parsed.query,
                keep_blank_values=True,
            )
        )

        # --------------------------------------------------
        # API endpoint discovery
        # --------------------------------------------------

        if (
            "/api/" in path_lower
            or API_VERSION_RE.search(path)
        ):
            findings.append(
                _finding(
                    target,
                    url,
                    "api_surface",
                    "API endpoint discovered",
                    "info",
                    f"API-like path: {path}",
                    "An API-style endpoint was discovered.",
                    "Inventory API endpoints and apply authentication and authorization consistently.",
                )
            )

        # --------------------------------------------------
        # BOLA / IDOR candidate
        # --------------------------------------------------

        if OBJECT_ID_RE.search(path):
            findings.append(
                _finding(
                    target,
                    url,
                    "bola_candidate",
                    "Potential object-level authorization surface",
                    "medium",
                    f"Object-like identifier in URL: {path}",
                    "The endpoint appears to address an individual object by an identifier.",
                    "Verify that the authenticated caller can access only objects they are authorized to access.",
                )
            )

        # --------------------------------------------------
        # Object property / mass assignment candidate
        # --------------------------------------------------

        suspicious_keys = sorted(
            key
            for key in query
            if key.lower() in MASS_ASSIGNMENT_KEYS
        )

        if suspicious_keys:
            findings.append(
                _finding(
                    target,
                    url,
                    "bopla_candidate",
                    "Potential object-property authorization surface",
                    "medium",
                    "Sensitive object properties observed: "
                    + ", ".join(suspicious_keys),
                    "The endpoint exposes parameters that may represent security-sensitive object properties.",
                    "Verify server-side authorization for every mutable property.",
                )
            )

        # --------------------------------------------------
        # Privileged function candidate
        # --------------------------------------------------

        if PRIVILEGED_RE.search(path):
            findings.append(
                _finding(
                    target,
                    url,
                    "function_authorization_candidate",
                    "Potential privileged function endpoint",
                    "medium",
                    f"Privileged-looking path: {path}",
                    "The endpoint appears associated with administrative or privileged functionality.",
                    "Verify that authorization is enforced server-side for every privileged function.",
                )
            )

        # --------------------------------------------------
        # Sensitive business flow
        # --------------------------------------------------

        if SENSITIVE_FLOW_RE.search(path):
            findings.append(
                _finding(
                    target,
                    url,
                    "sensitive_business_flow",
                    "Sensitive business workflow discovered",
                    "medium",
                    f"Business-flow path: {path}",
                    "The endpoint appears related to authentication, account recovery, payments, transfers, verification, or another sensitive workflow.",
                    "Review authorization, replay protection, rate controls, state transitions, and business rules.",
                )
            )

        # --------------------------------------------------
        # GraphQL
        # --------------------------------------------------

        if GRAPHQL_RE.search(url):
            findings.append(
                _finding(
                    target,
                    url,
                    "graphql_surface",
                    "GraphQL endpoint discovered",
                    "info",
                    f"GraphQL-like endpoint: {url}",
                    "A GraphQL application surface was discovered.",
                    "Review authentication, authorization at resolver level, query complexity controls, and schema exposure.",
                )
            )

        # --------------------------------------------------
        # OAuth / OIDC
        # --------------------------------------------------

        if OAUTH_RE.search(path):
            findings.append(
                _finding(
                    target,
                    url,
                    "oauth_oidc_surface",
                    "OAuth/OIDC security surface discovered",
                    "info",
                    f"OAuth/OIDC-like path: {path}",
                    "An OAuth or OpenID Connect related endpoint was discovered.",
                    "Review redirect URI validation, state handling, token audience, issuer validation, and authorization-code flow protections.",
                )
            )

        # --------------------------------------------------
        # Webhooks
        # --------------------------------------------------

        if WEBHOOK_RE.search(path):
            findings.append(
                _finding(
                    target,
                    url,
                    "webhook_surface",
                    "Webhook or callback endpoint discovered",
                    "medium",
                    f"Webhook-like path: {path}",
                    "A webhook or callback endpoint was discovered.",
                    "Verify request authentication, signature validation, replay protection, and destination validation.",
                )
            )

        # --------------------------------------------------
        # Debug / management surfaces
        # --------------------------------------------------

        if DEBUG_RE.search(path):
            findings.append(
                _finding(
                    target,
                    url,
                    "management_surface",
                    "Debug or management endpoint discovered",
                    "medium",
                    f"Management/debug path: {path}",
                    "A potentially sensitive operational endpoint was discovered.",
                    "Verify that the endpoint is required and protected by appropriate authentication and authorization.",
                )
            )

        # --------------------------------------------------
        # Cloud storage references
        # --------------------------------------------------

        if STORAGE_RE.search(url):
            findings.append(
                _finding(
                    target,
                    url,
                    "cloud_storage_surface",
                    "Cloud storage reference discovered",
                    "medium",
                    f"Storage-related URL: {url}",
                    "The application references a cloud storage service or bucket-like resource.",
                    "Verify bucket/object permissions and ensure sensitive objects are not publicly accessible.",
                )
            )

        # --------------------------------------------------
        # API version inventory
        # --------------------------------------------------

        version_match = API_VERSION_RE.search(path)

        if version_match:
            version = version_match.group(0)

            findings.append(
                _finding(
                    target,
                    url,
                    "api_version_inventory",
                    "Versioned API endpoint discovered",
                    "low",
                    f"API version indicator: {version}",
                    "A versioned API endpoint was discovered.",
                    "Inventory active API versions and retire deprecated interfaces that are no longer required.",
                )
            )

        # --------------------------------------------------
        # Resource-consumption parameters
        # --------------------------------------------------

        resource_keys = {
            "limit",
            "offset",
            "page",
            "size",
            "count",
            "depth",
            "batch",
            "ids",
        }

        matched_resource_keys = sorted(
            key
            for key in query
            if key.lower() in resource_keys
        )

        if matched_resource_keys:
            findings.append(
                _finding(
                    target,
                    url,
                    "resource_consumption_surface",
                    "Potential resource-consumption surface",
                    "low",
                    "Resource-related parameters: "
                    + ", ".join(matched_resource_keys),
                    "The endpoint accepts parameters commonly associated with pagination, batching, or resource sizing.",
                    "Verify server-side limits, pagination bounds, batching controls, and rate protections.",
                )
            )

        # --------------------------------------------------
        # JWT observation
        # --------------------------------------------------

        body = str(
            next(
                (
                    item.get("body", "")
                    for item in (http_results or [])
                    if item.get("url") == url
                ),
                "",
            )
            or ""
        )

        if JWT_RE.search(body):
            findings.append(
                _finding(
                    target,
                    url,
                    "jwt_observation",
                    "JWT-like token observed in response",
                    "medium",
                    "Response contains a JWT-like token structure.",
                    "A JWT-shaped value was observed in the response.",
                    "Verify that tokens are delivered and stored securely and that issuer, audience, expiry, and signature validation are enforced.",
                )
            )

    return _deduplicate(findings)
