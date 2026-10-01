from __future__ import annotations

from typing import Any, Dict, List


EVIDENCE_WEIGHTS = {
    "discovery": 10,
    "relevant_endpoint": 10,
    "security_sensitive_object": 10,
    "response_difference": 15,
    "authorization_difference": 25,
    "reproducible_behavior": 20,
    "independent_corroboration": 10,
}


def _truthy(value: Any) -> bool:
    return bool(value)


def _get_structured_evidence(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return structured evidence when available.

    Older BugBrain modules store evidence as a string.
    Newer modules may store evidence as a dictionary.

    String evidence is deliberately NOT converted into a
    vulnerability-confirming signal. It is preserved as legacy
    evidence only.
    """

    evidence = finding.get("evidence")

    if isinstance(evidence, dict):
        return evidence

    return {}


def calculate_confidence(finding: Dict[str, Any]) -> Dict[str, Any]:
    evidence = _get_structured_evidence(finding)

    signals: List[str] = []

    for signal, weight in EVIDENCE_WEIGHTS.items():

        if _truthy(evidence.get(signal)):
            signals.append(signal)

    score = sum(
        EVIDENCE_WEIGHTS[signal]
        for signal in signals
    )

    score = max(
        0,
        min(100, score)
    )

    result = dict(finding)

    result["confidence_score"] = score
    result["evidence_signals"] = signals

    if score >= 95:
        result["confidence_level"] = "confirmed"

    elif score >= 90:
        result["confidence_level"] = "strong"

    elif score >= 80:
        result["confidence_level"] = "high"

    elif score >= 60:
        result["confidence_level"] = "medium"

    else:
        result["confidence_level"] = "low"

    return result


def should_confirm(finding: Dict[str, Any]) -> bool:
    score = int(
        finding.get(
            "confidence_score",
            0
        )
    )

    evidence = _get_structured_evidence(finding)

    # Confirmation requires reproducible evidence.
    if not evidence.get("reproducible_behavior"):
        return False

    # Confirmation requires a very strong evidence score.
    if score < 95:
        return False

    return True


def classify_finding(
    finding: Dict[str, Any]
) -> Dict[str, Any]:

    result = calculate_confidence(finding)

    if should_confirm(result):

        result["status"] = "confirmed"

        return result

    score = result["confidence_score"]

    if score >= 80:

        result["status"] = "high-confidence-candidate"

    else:

        result["status"] = "candidate"

    return result
