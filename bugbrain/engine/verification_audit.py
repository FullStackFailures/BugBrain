from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import json


AUDIT_FILE = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "active_verification_audit.jsonl"
)


def _timestamp():
    return datetime.now(timezone.utc).isoformat()


def _safe_result(result: dict) -> dict:
    """
    Keep useful verification metadata while excluding
    secrets, request bodies, and response bodies.
    """

    allowed_keys = {
        "status",
        "exploitability",
        "confidence",
        "method",
        "reproducible",
        "security_impact",
        "authorization_boundary",
    }

    safe = {}

    for key in allowed_keys:
        if key in result:
            safe[key] = result[key]

    # Preserve aggregate differential-verification metadata
    # when supplied by the verifier.
    evidence = result.get("evidence")

    if isinstance(evidence, list):

        changed_counts = []
        comparison_counts = []
        reproducibility_values = []

        for item in evidence:

            if not isinstance(item, dict):
                continue

            observation = item.get("observation")

            if not isinstance(observation, dict):
                continue

            if "changed_comparison_count" in observation:
                changed_counts.append(
                    observation["changed_comparison_count"]
                )

            if "comparison_count" in observation:
                comparison_counts.append(
                    observation["comparison_count"]
                )

            if "reproducibility_established" in observation:
                reproducibility_values.append(
                    observation["reproducibility_established"]
                )

        if changed_counts:
            safe["changed_comparison_count"] = max(
                changed_counts
            )

        if comparison_counts:
            safe["comparison_count"] = max(
                comparison_counts
            )

        if reproducibility_values:
            safe["reproducibility_established"] = any(
                reproducibility_values
            )

    return safe


def record_execution(
    *,
    target: str,
    test_name: str,
    event: str,
    status: str,
    reason: str = "",
    result: dict | None = None,
):
    """
    Record active-verification execution events.

    The audit log intentionally excludes:
    - passwords
    - authentication secrets
    - request bodies
    - response bodies
    - raw response contents

    Only bounded verification metadata is retained.
    """

    safe_result = {}

    if isinstance(result, dict):
        safe_result = _safe_result(result)

    record = {
        "timestamp": _timestamp(),
        "event": event,
        "status": status,
        "target": target,
        "test_name": test_name,
        "reason": reason,
        "result": safe_result,
    }

    try:
        AUDIT_FILE.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with AUDIT_FILE.open(
            "a",
            encoding="utf-8",
        ) as handle:
            handle.write(
                json.dumps(
                    record,
                    ensure_ascii=False,
                )
                + "\n"
            )

    except OSError as exc:
        print(
            f"[!] Warning: could not write execution audit log: {exc}"
        )
