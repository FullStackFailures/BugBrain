from datetime import datetime
from hashlib import sha256


def _text(value):
    if value is None:
        return ""
    return str(value)


def _hash(value):
    return sha256(_text(value).encode("utf-8", errors="ignore")).hexdigest()


def create_evidence(
    finding,
    *,
    request=None,
    response=None,
    observation=None,
    source="scanner",
):
    """
    Build normalized evidence for a BugBrain finding.

    Evidence does NOT automatically confirm a vulnerability.
    The verifier decides whether the evidence is sufficient.
    """

    request = request or {}
    response = response or {}

    evidence = {
        "id": None,
        "source": source,
        "timestamp": datetime.utcnow().isoformat() + "Z",

        "finding_type": finding.get("type"),
        "title": finding.get("title"),
        "url": finding.get("url"),

        "request": {
            "method": request.get("method"),
            "url": request.get("url"),
            "headers": request.get("headers", {}),
            "body_present": bool(request.get("body")),
        },

        "response": {
            "status_code": response.get("status_code"),
            "headers": response.get("headers", {}),
            "content_type": response.get("content_type"),
            "body_length": response.get("body_length"),
        },

        "observation": observation or {},

        "verification": {
            "required": True,
            "performed": False,
            "result": "not_verified",
            "reason": None,
        },
    }

    evidence["id"] = _hash(
        (
            evidence["finding_type"],
            evidence["url"],
            evidence["timestamp"],
        )
    )[:16]

    return evidence


def add_observation(evidence, key, value):
    evidence.setdefault("observation", {})
    evidence["observation"][key] = value
    return evidence


def mark_verification(evidence, result, reason):
    """
    result should normally be one of:
        not_verified
        insufficient_evidence
        verified
    """

    allowed = {
        "not_verified",
        "insufficient_evidence",
        "verified",
    }

    if result not in allowed:
        raise ValueError(
            f"Invalid verification result: {result}"
        )

    evidence.setdefault("verification", {})

    evidence["verification"]["performed"] = True
    evidence["verification"]["result"] = result
    evidence["verification"]["reason"] = reason

    return evidence


def evidence_is_verified(evidence):
    verification = evidence.get("verification", {})

    return (
        verification.get("performed") is True
        and verification.get("result") == "verified"
    )


def evidence_summary(evidence):
    finding_type = evidence.get("finding_type", "unknown")
    url = evidence.get("url", "")

    verification = evidence.get(
        "verification",
        {},
    )

    result = verification.get(
        "result",
        "not_verified",
    )

    return {
        "finding_type": finding_type,
        "url": url,
        "verification": result,
        "evidence_id": evidence.get("id"),
    }
