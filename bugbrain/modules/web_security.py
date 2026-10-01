from urllib.parse import urlparse


def analyze(target, http_result):

    findings = []

    url = http_result.get("url", "")
    headers = {
        key.lower(): value
        for key, value in http_result.get(
            "headers",
            {}
        ).items()
    }

    # ---------------------------------------------------------
    # Cookie security
    # ---------------------------------------------------------

    set_cookie = headers.get(
        "set-cookie",
        ""
    )

    if set_cookie:

        cookies = set_cookie.split(",")

        for cookie in cookies:

            cookie_lower = cookie.lower()

            cookie_name = cookie.split(
                "=",
                1
            )[0].strip()

            if (
                "secure" not in cookie_lower
                and urlparse(url).scheme == "https"
            ):

                findings.append({
                    "target": target,
                    "url": url,
                    "type": "cookie_security",
                    "title": (
                        f"Cookie missing Secure flag: "
                        f"{cookie_name}"
                    ),
                    "severity": "low",
                    "confidence": 0.90,
                    "summary": (
                        "A cookie was observed over HTTPS "
                        "without the Secure attribute."
                    ),
                    "evidence": cookie,
                    "reproduction": (
                        f"Inspect the Set-Cookie header "
                        f"returned by {url}."
                    ),
                    "impact": (
                        "Without Secure, a browser may "
                        "send the cookie over an insecure "
                        "connection if such a connection "
                        "is available."
                    ),
                    "remediation": (
                        "Set the Secure attribute on "
                        "security-sensitive cookies."
                    )
                })

            if "httponly" not in cookie_lower:

                findings.append({
                    "target": target,
                    "url": url,
                    "type": "cookie_security",
                    "title": (
                        f"Cookie missing HttpOnly flag: "
                        f"{cookie_name}"
                    ),
                    "severity": "info",
                    "confidence": 0.90,
                    "summary": (
                        "A cookie was observed without "
                        "the HttpOnly attribute."
                    ),
                    "evidence": cookie,
                    "reproduction": (
                        f"Inspect the Set-Cookie header "
                        f"returned by {url}."
                    ),
                    "impact": (
                        "Client-side JavaScript may be able "
                        "to access the cookie."
                    ),
                    "remediation": (
                        "Use HttpOnly for cookies that do "
                        "not need JavaScript access."
                    )
                })

    # ---------------------------------------------------------
    # CORS observation
    # ---------------------------------------------------------

    allow_origin = headers.get(
        "access-control-allow-origin"
    )

    if allow_origin == "*":

        findings.append({
            "target": target,
            "url": url,
            "type": "cors_configuration",
            "title": "Wildcard CORS origin observed",
            "severity": "info",
            "confidence": 0.95,
            "summary": (
                "The response allows requests from "
                "any origin according to the "
                "Access-Control-Allow-Origin header."
            ),
            "evidence": (
                "Access-Control-Allow-Origin: *"
            ),
            "reproduction": (
                f"Inspect the HTTP response headers "
                f"from {url}."
            ),
            "impact": (
                "Wildcard CORS can expose resources "
                "to cross-origin web pages depending "
                "on the resource and authentication "
                "configuration."
            ),
            "remediation": (
                "Restrict allowed origins to trusted "
                "origins when cross-origin access is "
                "actually required."
            )
        })

    # ---------------------------------------------------------
    # Server disclosure
    # ---------------------------------------------------------

    server = headers.get(
        "server"
    )

    if server:

        findings.append({
            "target": target,
            "url": url,
            "type": "information_disclosure",
            "title": "Server header disclosed",
            "severity": "info",
            "confidence": 0.98,
            "summary": (
                "The HTTP response exposes server "
                "information through the Server header."
            ),
            "evidence": (
                f"Server: {server}"
            ),
            "reproduction": (
                f"Inspect the HTTP response headers "
                f"from {url}."
            ),
            "impact": (
                "Server information can help an "
                "attacker fingerprint the technology "
                "stack."
            ),
            "remediation": (
                "Consider minimizing unnecessary "
                "server identification information."
            )
        })

    # ---------------------------------------------------------
    # HTTPS observation
    # ---------------------------------------------------------

    parsed = urlparse(url)

    if parsed.scheme == "http":

        findings.append({
            "target": target,
            "url": url,
            "type": "transport_security",
            "title": "HTTP endpoint observed",
            "severity": "info",
            "confidence": 0.99,
            "summary": (
                "The discovered web service is "
                "accessible over HTTP."
            ),
            "evidence": url,
            "reproduction": (
                f"Request the endpoint using HTTP: {url}"
            ),
            "impact": (
                "HTTP traffic is not encrypted and "
                "may expose transmitted information "
                "to network observers."
            ),
            "remediation": (
                "Use HTTPS and redirect HTTP traffic "
                "to HTTPS where appropriate."
            )
        })

    return findings
