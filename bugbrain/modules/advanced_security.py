from urllib.parse import urlparse, parse_qsl


# ---------------------------------------------------------
# Names commonly associated with security-sensitive inputs
# ---------------------------------------------------------

REDIRECT_NAMES = {
    "redirect",
    "redirect_url",
    "redirect_uri",
    "return",
    "return_url",
    "return_to",
    "next",
    "continue",
    "dest",
    "destination",
    "url",
    "uri",
    "link",
    "target",
}

SSRF_NAMES = {
    "url",
    "uri",
    "url",
    "target",
    "dest",
    "destination",
    "callback",
    "webhook",
    "endpoint",
    "proxy",
    "remote",
    "remote_url",
    "image_url",
    "feed",
    "source",
}

PATH_TRAVERSAL_NAMES = {
    "file",
    "filepath",
    "file_path",
    "filename",
    "path",
    "document",
    "template",
    "page",
    "include",
    "folder",
    "directory",
    "download",
}

IDOR_NAMES = {
    "id",
    "user_id",
    "userid",
    "account_id",
    "account",
    "profile_id",
    "order_id",
    "invoice_id",
    "document_id",
    "file_id",
    "customer_id",
    "uid",
}

CSRF_NAMES = {
    "csrf",
    "csrf_token",
    "csrftoken",
    "_csrf",
    "_token",
    "xsrf",
    "xsrf_token",
    "authenticity_token",
    "request_token",
}

SENSITIVE_PATH_WORDS = (
    "login",
    "signin",
    "sign-in",
    "account",
    "profile",
    "admin",
    "dashboard",
    "settings",
    "password",
    "payment",
    "billing",
    "checkout",
    "user",
    "users",
    "order",
)


def _finding(
    target,
    title,
    finding_type,
    url,
    severity,
    confidence,
    summary,
    evidence,
    remediation,
):
    return {
        "target": target,
        "url": url,
        "type": finding_type,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "summary": summary,
        "evidence": evidence,
        "remediation": remediation,
    }


def _headers(result):
    return {
        str(key).lower(): str(value)
        for key, value in result.get("headers", {}).items()
    }


def _is_sensitive_url(url):
    path = urlparse(url).path.lower()

    return any(
        word in path
        for word in SENSITIVE_PATH_WORDS
    )


def analyze(target, http_results, recon=None):
    """
    Passive security analysis.

    These checks inspect already collected HTTP responses,
    forms, URLs and headers.

    They do not send exploit payloads.
    """

    findings = []
    seen = set()

    recon = recon or {}

    # ---------------------------------------------------------
    # HTTP response analysis
    # ---------------------------------------------------------

    for result in http_results:

        if result.get("error"):
            continue

        url = result.get("url", "")

        if not url:
            continue

        headers = _headers(result)
        body = result.get("body_preview", "") or ""

        # -----------------------------------------------------
        # CORS
        # -----------------------------------------------------

        allow_origin = headers.get(
            "access-control-allow-origin",
            ""
        ).strip()

        allow_credentials = headers.get(
            "access-control-allow-credentials",
            ""
        ).strip().lower()

        if allow_origin == "*":

            if allow_credentials == "true":

                key = ("cors", url, "wildcard_credentials")

                if key not in seen:
                    seen.add(key)

                    findings.append(
                        _finding(
                            target,
                            "Potentially unsafe CORS configuration",
                            "cors_misconfiguration",
                            url,
                            "medium",
                            0.98,
                            "The response allows all origins while also allowing credentials.",
                            (
                                "Access-Control-Allow-Origin: *; "
                                "Access-Control-Allow-Credentials: true"
                            ),
                            "Restrict allowed origins to trusted origins and review credentialed cross-origin access.",
                        )
                    )

            else:

                key = ("cors", url, "wildcard")

                if key not in seen:
                    seen.add(key)

                    findings.append(
                        _finding(
                            target,
                            "Wildcard CORS policy observed",
                            "cors_wildcard",
                            url,
                            "low",
                            0.92,
                            "The endpoint permits cross-origin requests from any origin.",
                            "Access-Control-Allow-Origin: *",
                            "Restrict CORS origins when the endpoint handles sensitive information.",
                        )
                    )

        # -----------------------------------------------------
        # Clickjacking protection
        # -----------------------------------------------------

        x_frame = headers.get(
            "x-frame-options",
            ""
        )

        csp = headers.get(
            "content-security-policy",
            ""
        )

        has_frame_ancestors = (
            "frame-ancestors"
            in csp.lower()
        )

        if not x_frame and not has_frame_ancestors:

            key = ("clickjacking", url)

            if key not in seen:
                seen.add(key)

                findings.append(
                    _finding(
                        target,
                        "Missing clickjacking protection",
                        "clickjacking_protection",
                        url,
                        "low",
                        0.96,
                        "The response does not expose X-Frame-Options or a CSP frame-ancestors directive.",
                        "X-Frame-Options header absent; CSP frame-ancestors directive absent.",
                        "Use an appropriate X-Frame-Options policy and/or CSP frame-ancestors policy.",
                    )
                )

        # -----------------------------------------------------
        # Cookie security
        # -----------------------------------------------------

        set_cookie = headers.get(
            "set-cookie",
            ""
        )

        if set_cookie:

            cookie_text = set_cookie.lower()

            if "secure" not in cookie_text:

                key = ("cookie", url, "secure")

                if key not in seen:
                    seen.add(key)

                    findings.append(
                        _finding(
                            target,
                            "Cookie without Secure attribute observed",
                            "cookie_secure",
                            url,
                            "low",
                            0.95,
                            "A Set-Cookie response was observed without the Secure attribute.",
                            "Set-Cookie does not contain Secure.",
                            "Set Secure on cookies that should only be transmitted over HTTPS.",
                        )
                    )

            if "httponly" not in cookie_text:

                key = ("cookie", url, "httponly")

                if key not in seen:
                    seen.add(key)

                    findings.append(
                        _finding(
                            target,
                            "Cookie without HttpOnly attribute observed",
                            "cookie_httponly",
                            url,
                            "low",
                            0.95,
                            "A Set-Cookie response was observed without the HttpOnly attribute.",
                            "Set-Cookie does not contain HttpOnly.",
                            "Use HttpOnly for cookies that do not need JavaScript access, especially session cookies.",
                        )
                    )

            if "samesite" not in cookie_text:

                key = ("cookie", url, "samesite")

                if key not in seen:
                    seen.add(key)

                    findings.append(
                        _finding(
                            target,
                            "Cookie without SameSite attribute observed",
                            "cookie_samesite",
                            url,
                            "low",
                            0.90,
                            "A Set-Cookie response was observed without SameSite.",
                            "Set-Cookie does not contain SameSite.",
                            "Use an appropriate SameSite policy for session and security-sensitive cookies.",
                        )
                    )

        # -----------------------------------------------------
        # TRACE
        # -----------------------------------------------------

        allow = headers.get(
            "allow",
            ""
        ).upper()

        if "TRACE" in allow.split(","):

            key = ("trace", url)

            if key not in seen:
                seen.add(key)

                findings.append(
                    _finding(
                        target,
                        "TRACE method advertised",
                        "trace_method",
                        url,
                        "low",
                        0.99,
                        "The HTTP Allow header advertises the TRACE method.",
                        f"Allow: {allow}",
                        "Disable HTTP methods that are unnecessary for the application.",
                    )
                )

        # -----------------------------------------------------
        # Mixed content references
        # -----------------------------------------------------

        if url.lower().startswith("https://"):

            http_references = []

            for reference in result.get("links", []):

                if str(reference).lower().startswith("http://"):
                    http_references.append(reference)

            if http_references:

                key = ("mixed_content", url)

                if key not in seen:
                    seen.add(key)

                    findings.append(
                        _finding(
                            target,
                            "HTTP resource reference discovered on HTTPS page",
                            "mixed_content",
                            url,
                            "low",
                            0.90,
                            "An HTTPS page references an HTTP URL.",
                            (
                                "HTTP references: "
                                + ", ".join(http_references[:10])
                            ),
                            "Serve security-sensitive resources over HTTPS and avoid mixed-content references.",
                        )
                    )

        # -----------------------------------------------------
        # Reflected parameter value
        # -----------------------------------------------------

        parsed = urlparse(url)

        for name, value in parse_qsl(
            parsed.query,
            keep_blank_values=True
        ):

            if not value:
                continue

            if len(value) > 200:
                continue

            if value not in body:
                continue

            key = (
                "reflection",
                url,
                name,
            )

            if key in seen:
                continue

            seen.add(key)

            findings.append(
                _finding(
                    target,
                    f"Potential reflected input: {name}",
                    "xss_reflection_candidate",
                    url,
                    "medium",
                    0.82,
                    "A URL parameter value was observed in the collected response body.",
                    (
                        f"Parameter: {name}; "
                        f"Observed value: {value[:100]}"
                    ),
                    "Review output encoding and context-specific escaping before treating the reflection as an XSS vulnerability.",
                )
            )

        # -----------------------------------------------------
        # Sensitive data in query string
        # -----------------------------------------------------

        sensitive_names = {
            "password",
            "passwd",
            "secret",
            "token",
            "access_token",
            "api_key",
            "apikey",
            "authorization",
            "session",
            "sessionid",
        }

        for name, value in parse_qsl(
            parsed.query,
            keep_blank_values=True
        ):

            if name.lower() not in sensitive_names:
                continue

            if not value:
                continue

            key = (
                "sensitive-url",
                url,
                name.lower()
            )

            if key in seen:
                continue

            seen.add(key)

            findings.append(
                _finding(
                    target,
                    f"Sensitive value in URL parameter: {name}",
                    "sensitive_data_url",
                    url,
                    "medium",
                    0.98,
                    "A parameter name suggests sensitive authentication or secret data is being transmitted in the URL.",
                    f"Parameter: {name}; value present: yes",
                    "Avoid transmitting credentials, session identifiers, or secrets in URLs. Prefer secure request bodies or appropriate authorization headers.",
                )
            )

        # -----------------------------------------------------
        # Cache-control on sensitive pages
        # -----------------------------------------------------

        if _is_sensitive_url(url):

            cache_control = headers.get(
                "cache-control",
                ""
            ).lower()

            if (
                "no-store" not in cache_control
                and "private" not in cache_control
            ):

                key = ("cache", url)

                if key not in seen:
                    seen.add(key)

                    findings.append(
                        _finding(
                            target,
                            "Sensitive page without explicit private/no-store cache policy",
                            "sensitive_cache_policy",
                            url,
                            "low",
                            0.75,
                            "A potentially sensitive endpoint does not advertise a private or no-store cache policy.",
                            (
                                f"URL: {url}; "
                                f"Cache-Control: {cache_control or '(absent)'}"
                            ),
                            "Review caching behavior and use an appropriate Cache-Control policy for sensitive responses.",
                        )
                    )

    # ---------------------------------------------------------
    # Form analysis
    # ---------------------------------------------------------

    for form in recon.get("forms", []):

        action = form.get("action", "")
        method = form.get(
            "method",
            "GET"
        ).upper()

        inputs = form.get(
            "inputs",
            []
        )

        names = {
            str(field.get("name", "")).strip().lower()
            for field in inputs
            if field.get("name")
        }

        # -----------------------------------------------------
        # CSRF candidate
        # -----------------------------------------------------

        if method == "POST":

            has_csrf = any(
                name in CSRF_NAMES
                or "csrf" in name
                or "xsrf" in name
                for name in names
            )

            if not has_csrf:

                key = ("csrf", action)

                if key not in seen:
                    seen.add(key)

                    findings.append(
                        _finding(
                            target,
                            "POST form without an obvious CSRF token",
                            "csrf_candidate",
                            action,
                            "medium",
                            0.72,
                            "A state-changing POST form was discovered without a field that appears to contain a CSRF token.",
                            (
                                f"Method: POST; "
                                f"Inputs: {', '.join(sorted(names)) or '(none)'}"
                            ),
                            "Verify whether the application uses another CSRF defense such as SameSite cookies or a framework-level token mechanism.",
                        )
                    )

        # -----------------------------------------------------
        # Open redirect candidate
        # -----------------------------------------------------

        redirect_fields = names.intersection(
            REDIRECT_NAMES
        )

        if redirect_fields:

            key = (
                "redirect",
                action,
                tuple(sorted(redirect_fields))
            )

            if key not in seen:
                seen.add(key)

                findings.append(
                    _finding(
                        target,
                        "Potential open-redirect input",
                        "open_redirect_candidate",
                        action,
                        "medium",
                        0.70,
                        "A form contains a parameter commonly used for redirects.",
                        (
                            "Redirect-like parameters: "
                            + ", ".join(
                                sorted(redirect_fields)
                            )
                        ),
                        "Validate redirect destinations against an allowlist or use server-side route identifiers instead of arbitrary URLs.",
                    )
                )

        # -----------------------------------------------------
        # SSRF candidate
        # -----------------------------------------------------

        ssrf_fields = names.intersection(
            SSRF_NAMES
        )

        if ssrf_fields:

            key = (
                "ssrf",
                action,
                tuple(sorted(ssrf_fields))
            )

            if key not in seen:
                seen.add(key)

                findings.append(
                    _finding(
                        target,
                        "Potential server-side URL input",
                        "ssrf_candidate",
                        action,
                        "medium",
                        0.70,
                        "A form contains a field that may accept a remote URL or destination.",
                        (
                            "URL-like parameters: "
                            + ", ".join(
                                sorted(ssrf_fields)
                            )
                        ),
                        "Review whether the server performs outbound requests and restrict destinations, protocols, redirects, and internal network access.",
                    )
                )

        # -----------------------------------------------------
        # Path traversal candidate
        # -----------------------------------------------------

        path_fields = names.intersection(
            PATH_TRAVERSAL_NAMES
        )

        if path_fields:

            key = (
                "path",
                action,
                tuple(sorted(path_fields))
            )

            if key not in seen:
                seen.add(key)

                findings.append(
                    _finding(
                        target,
                        "Potential file/path manipulation input",
                        "path_traversal_candidate",
                        action,
                        "medium",
                        0.70,
                        "A form contains a field commonly associated with filesystem or template selection.",
                        (
                            "Path-like parameters: "
                            + ", ".join(
                                sorted(path_fields)
                            )
                        ),
                        "Use allowlisted identifiers instead of filesystem paths and canonicalize/validate server-side input.",
                    )
                )

        # -----------------------------------------------------
        # IDOR / authorization candidate
        # -----------------------------------------------------

        id_fields = names.intersection(
            IDOR_NAMES
        )

        if id_fields:

            key = (
                "idor",
                action,
                tuple(sorted(id_fields))
            )

            if key not in seen:
                seen.add(key)

                findings.append(
                    _finding(
                        target,
                        "Object identifier requiring authorization review",
                        "idor_candidate",
                        action,
                        "medium",
                        0.65,
                        "A form contains an object or account identifier that may select server-side resources.",
                        (
                            "Identifier fields: "
                            + ", ".join(
                                sorted(id_fields)
                            )
                        ),
                        "Verify that every object access performs server-side authorization for the authenticated user.",
                    )
                )

        # -----------------------------------------------------
        # Password over HTTP
        # -----------------------------------------------------

        password_fields = {
            name
            for name in names
            if name in {
                "password",
                "passwd",
                "pass",
                "current_password",
                "new_password",
            }
        }

        if password_fields and action.lower().startswith("http://"):

            key = (
                "password-http",
                action
            )

            if key not in seen:
                seen.add(key)

                findings.append(
                    _finding(
                        target,
                        "Password form submitted over HTTP",
                        "password_over_http",
                        action,
                        "high",
                        0.99,
                        "A form containing a password field submits to a plaintext HTTP URL.",
                        (
                            "Action: "
                            + action
                        ),
                        "Require HTTPS for authentication and password submission.",
                    )
                )

    return findings
