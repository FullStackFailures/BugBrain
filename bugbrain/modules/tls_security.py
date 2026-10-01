from datetime import datetime, timezone


def analyze(target, tls_result):
    findings = []

    if not tls_result.get("ok"):
        return findings

    protocol = tls_result.get("protocol", "")
    certificate = tls_result.get("certificate", {})

    # Weak/obsolete TLS protocol observation
    if protocol in ("TLSv1", "TLSv1.1", "SSLv3"):
        findings.append({
            "target": target,
            "url": f"https://{target}",
            "type": "tls_configuration",
            "title": f"Obsolete TLS protocol observed: {protocol}",
            "severity": "medium",
            "confidence": 0.99,
            "summary": (
                f"The server negotiated {protocol}, which is an obsolete "
                "TLS protocol."
            ),
            "evidence": f"Negotiated protocol: {protocol}",
            "impact": (
                "Older TLS protocols may provide weaker transport security "
                "than modern TLS configurations."
            ),
            "remediation": (
                "Disable obsolete TLS protocols and require modern TLS "
                "versions."
            )
        })

    # Certificate expiration
    not_after = certificate.get("not_after")

    if not_after:
        try:
            expiry = datetime.strptime(
                not_after,
                "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)

            now = datetime.now(timezone.utc)

            if expiry < now:
                findings.append({
                    "target": target,
                    "url": f"https://{target}",
                    "type": "tls_certificate",
                    "title": "TLS certificate has expired",
                    "severity": "medium",
                    "confidence": 0.99,
                    "summary": "The TLS certificate presented by the server is expired.",
                    "evidence": f"Certificate expiry: {not_after}",
                    "impact": (
                        "An expired certificate can cause browser warnings "
                        "and indicates that certificate management requires attention."
                    ),
                    "remediation": (
                        "Replace the expired certificate with a valid certificate."
                    )
                })

        except ValueError:
            pass

    return findings