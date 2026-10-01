from urllib.parse import urlparse, parse_qsl


XSS_NAMES = {
    "q", "query", "search", "keyword", "name",
    "message", "comment", "content", "text",
    "title", "description", "redirect", "next"
}

SSRF_NAMES = {
    "url", "uri", "target", "dest", "destination",
    "redirect", "redirect_url", "callback",
    "webhook", "endpoint", "proxy", "image",
    "source", "host"
}

SQL_NAMES = {
    "id", "uid", "user_id", "account_id",
    "item_id", "product_id", "order_id",
    "category", "sort", "filter", "search"
}


def _finding(
    target,
    title,
    finding_type,
    url,
    evidence,
    summary,
    remediation,
    confidence=0.75,
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


def analyze(target, recon):

    findings = []
    seen = set()

    # ---------------------------------------------------------
    # URL parameters
    # ---------------------------------------------------------

    for url in recon.get("urls", []):

        parsed = urlparse(url)

        for name, value in parse_qsl(
            parsed.query,
            keep_blank_values=True
        ):

            parameter = name.lower()

            # Potential reflected-input surface
            if parameter in XSS_NAMES:

                key = ("xss", url, parameter)

                if key not in seen:

                    seen.add(key)

                    findings.append(
                        _finding(
                            target,
                            f"Potential XSS input surface: {name}",
                            "xss_candidate",
                            url,
                            f"Parameter: {name}",
                            "The URL contains a parameter commonly used for user-controlled text or search input.",
                            "Manually determine whether the parameter is reflected into an unsafe HTML or JavaScript context. Do not assume the parameter is vulnerable from its name alone.",
                            0.72,
                        )
                    )

            # Potential server-side URL-fetch surface
            if parameter in SSRF_NAMES:

                key = ("ssrf", url, parameter)

                if key not in seen:

                    seen.add(key)

                    findings.append(
                        _finding(
                            target,
                            f"Potential server-side URL input: {name}",
                            "ssrf_candidate",
                            url,
                            f"Parameter: {name}",
                            "The parameter name suggests that the application may accept a URL, destination, callback, proxy, or remote resource.",
                            "Manually verify whether the server retrieves user-controlled URLs and whether destination restrictions are enforced.",
                            0.76,
                        )
                    )

            # Potential database/query input
            if parameter in SQL_NAMES:

                key = ("sql", url, parameter)

                if key not in seen:

                    seen.add(key)

                    findings.append(
                        _finding(
                            target,
                            f"Potential database-query input: {name}",
                            "injection_candidate",
                            url,
                            f"Parameter: {name}",
                            "The parameter may influence object selection, filtering, sorting, or search operations.",
                            "Review server-side parameterization, type validation, authorization, and error handling.",
                            0.68,
                        )
                    )

    # ---------------------------------------------------------
    # Forms
    # ---------------------------------------------------------

    for form in recon.get("forms", []):

        action = form.get("action", "")

        for field in form.get("inputs", []):

            name = field.get("name", "").strip()

            if not name:
                continue

            parameter = name.lower()

            if parameter in XSS_NAMES:

                key = ("form-xss", action, parameter)

                if key not in seen:

                    seen.add(key)

                    findings.append(
                        _finding(
                            target,
                            f"Potential reflected-input surface: {name}",
                            "xss_candidate",
                            action,
                            f"Form parameter: {name}",
                            "A form contains a field commonly associated with user-controlled text.",
                            "Review how submitted data is encoded and rendered in HTML, JavaScript, and other output contexts.",
                            0.70,
                        )
                    )

            if parameter in SSRF_NAMES:

                key = ("form-ssrf", action, parameter)

                if key not in seen:

                    seen.add(key)

                    findings.append(
                        _finding(
                            target,
                            f"Potential server-side URL input: {name}",
                            "ssrf_candidate",
                            action,
                            f"Form parameter: {name}",
                            "A form field may accept a URL, destination, callback, or remote resource.",
                            "Determine whether the server performs outbound requests using this value and whether destinations are restricted.",
                            0.74,
                        )
                    )

            if parameter in SQL_NAMES:

                key = ("form-sql", action, parameter)

                if key not in seen:

                    seen.add(key)

                    findings.append(
                        _finding(
                            target,
                            f"Potential query input: {name}",
                            "injection_candidate",
                            action,
                            f"Form parameter: {name}",
                            "A form field may influence lookup, filtering, sorting, or object selection.",
                            "Review server-side parameterization, type validation, and authorization.",
                            0.66,
                        )
                    )

    return findings
