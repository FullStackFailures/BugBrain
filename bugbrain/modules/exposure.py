from urllib.parse import urlparse

import requests


DISCOVERY_PATHS = [
    "/robots.txt",
    "/security.txt",
    "/.well-known/security.txt",
]


def _origin(url):
    """
    Return only scheme + host + optional port.

    Discovery files must be requested from the site origin,
    never appended to an arbitrary discovered page or query URL.
    """
    try:
        parsed = urlparse(str(url or "").strip())

        if parsed.scheme not in ("http", "https"):
            return ""

        if not parsed.netloc:
            return ""

        return f"{parsed.scheme}://{parsed.netloc}"

    except Exception:
        return ""


def analyze(
    target,
    base_url,
    timeout=10
):
    findings = []

    origin = _origin(base_url)

    if not origin:
        return findings

    for path in DISCOVERY_PATHS:

        url = origin + path

        try:
            response = requests.get(
                url,
                timeout=timeout,
                allow_redirects=False,
                headers={
                    "User-Agent": "BugBrain/0.1"
                }
            )

            if response.status_code != 200:
                continue

            findings.append({
                "target": target,
                "url": url,
                "type": "discovery_file",
                "title": f"Accessible {path}",
                "severity": "info",
                "confidence": 0.99,
                "evidence": (
                    f"HTTP {response.status_code}; "
                    f"{len(response.content)} bytes"
                )
            })

        except requests.RequestException:
            continue

    return findings
