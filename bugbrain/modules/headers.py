SECURITY_HEADERS = {
    "strict-transport-security":
        "Strict-Transport-Security",

    "content-security-policy":
        "Content-Security-Policy",

    "x-content-type-options":
        "X-Content-Type-Options",

    "referrer-policy":
        "Referrer-Policy"
}


def analyze(target, http_result):

    findings = []

    headers = {
        key.lower(): value
        for key, value
        in http_result.get(
            "headers",
            {}
        ).items()
    }

    url = http_result.get(
        "url",
        ""
    )

    for key, display_name in (
        SECURITY_HEADERS.items()
    ):

        if key not in headers:

            findings.append({
                "target": target,
                "url": url,
                "type": "security_header",
                "title": (
                    f"Missing {display_name}"
                ),
                "severity": "info",
                "confidence": 0.95,
                "evidence": (
                    f"{display_name} was not "
                    "present in the HTTP response."
                )
            })

    return findings