from urllib.parse import urlparse, parse_qsl


SENSITIVE_NAMES = (
    "id",
    "user",
    "userid",
    "user_id",
    "account",
    "account_id",
    "uid",
    "role",
    "admin",
    "redirect",
    "url",
    "uri",
    "next",
    "return",
    "callback",
    "file",
    "path",
    "filename",
    "token",
    "key",
    "secret",
    "password",
)


def _finding(
    target,
    title,
    finding_type,
    url,
    evidence,
    summary,
    remediation,
    confidence=0.80,
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
        "remediation": remediation,
    }


def analyze(
    target,
    recon,
    javascript_results=None,
):
    javascript_results = javascript_results or []

    findings = []
    seen = set()

    # ---------------------------------------------------------
    # Parameters embedded in discovered URLs
    # ---------------------------------------------------------

    for url in recon.get("urls", []):

        parsed = urlparse(url)

        parameters = parse_qsl(
            parsed.query,
            keep_blank_values=True
        )

        for name, value in parameters:

            name_lower = name.lower()

            if name_lower not in SENSITIVE_NAMES:
                continue

            key = ("url", url, name_lower)

            if key in seen:
                continue

            seen.add(key)

            findings.append(
                _finding(
                    target,
                    f"Security-sensitive URL parameter discovered: {name}",
                    "sensitive_parameter",
                    url,
                    f"Parameter: {name}; Value present: {bool(value)}",
                    "A parameter commonly associated with object selection, redirection, files, credentials, or security-sensitive behavior was discovered.",
                    "Review server-side authorization, validation, and canonicalization for this parameter.",
                    0.82,
                )
            )

    # ---------------------------------------------------------
    # HTML forms
    # ---------------------------------------------------------

    for form in recon.get("forms", []):

        action = form.get("action", "")
        inputs = form.get("inputs", [])

        for field in inputs:

            name = field.get("name", "").strip()

            if not name:
                continue

            name_lower = name.lower()

            if name_lower in SENSITIVE_NAMES:

                key = ("form", action, name_lower)

                if key in seen:
                    continue

                seen.add(key)

                findings.append(
                    _finding(
                        target,
                        f"Security-sensitive form parameter discovered: {name}",
                        "form_parameter",
                        action,
                        f"Form method: {form.get('method', 'GET')}; Parameter: {name}",
                        "A form contains a parameter associated with security-sensitive application behavior.",
                        "Verify server-side authorization and strict input validation for this parameter.",
                        0.85,
                    )
                )

            if field.get("type", "").lower() == "file":

                findings.append(
                    _finding(
                        target,
                        "File upload input discovered",
                        "file_upload_parameter",
                        action,
                        f"File input name: {name or '(unnamed)'}",
                        "The application exposes a file-upload input.",
                        "Review authentication, authorization, file type validation, storage isolation, filename handling, and execution controls.",
                        0.94,
                    )
                )

    # ---------------------------------------------------------
    # JavaScript parameters
    # ---------------------------------------------------------

    for result in javascript_results:

        page_url = result.get(
            "page_url",
            ""
        )

        for parameter in result.get(
            "parameters",
            []
        ):

            parameter_lower = parameter.lower()

            if parameter_lower not in SENSITIVE_NAMES:
                continue

            key = (
                "javascript",
                page_url,
                parameter_lower
            )

            if key in seen:
                continue

            seen.add(key)

            findings.append(
                _finding(
                    target,
                    f"Security-sensitive JavaScript parameter discovered: {parameter}",
                    "javascript_parameter",
                    page_url,
                    f"Parameter referenced by client-side JavaScript: {parameter}",
                    "Client-side code references a parameter that may influence security-sensitive application behavior.",
                    "Review server-side authorization and input validation for operations using this parameter.",
                    0.80,
                )
            )

    return findings
