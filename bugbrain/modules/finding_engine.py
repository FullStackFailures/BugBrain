from urllib.parse import urlparse


def analyze_recon(recon):
    findings = []

    urls = recon.get("urls", [])
    technologies = recon.get("technologies", [])
    forms = recon.get("forms", [])

    # HTTP forms discovered
    for form in forms:
        findings.append({
            "type": "attack_surface",
            "title": "Web form discovered",
            "severity": "info",
            "confidence": 0.99,
            "url": form.get("action", ""),
            "evidence": (
                f"Method: {form.get('method', 'GET')}; "
                f"Inputs: {len(form.get('inputs', []))}"
            )
        })

    # Technology inventory
    for technology in technologies:
        findings.append({
            "type": "technology",
            "title": f"Technology detected: {technology}",
            "severity": "info",
            "confidence": 0.90,
            "url": urls[0] if urls else "",
            "evidence": technology
        })

    # Interesting endpoint inventory
    interesting_words = (
        "api",
        "admin",
        "login",
        "upload",
        "dashboard"
    )

    for url in urls:

        path = urlparse(url).path.lower()

        for word in interesting_words:

            if word in path:

                findings.append({
                    "type": "interesting_endpoint",
                    "title": (
                        f"Interesting endpoint discovered: "
                        f"{word}"
                    ),
                    "severity": "info",
                    "confidence": 0.85,
                    "url": url,
                    "evidence": (
                        f"URL path contains '{word}'."
                    )
                })

                break

    return findings