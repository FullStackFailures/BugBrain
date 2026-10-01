from datetime import datetime, timezone
import hashlib

from .config import FINDINGS_FILE, load_json, save_json


STATUS_PRIORITY = {
    "rejected": 0,
    "candidate": 1,
    "verifying": 2,
    "confirmed": 3,
}


def finding_fingerprint(finding):
    raw = "|".join([
        str(finding.get("target", "")),
        str(finding.get("url", "")),
        str(finding.get("type", "")),
        str(finding.get("title", "")),
    ])

    return hashlib.sha256(raw.encode()).hexdigest()


def _status_priority(status):
    return STATUS_PRIORITY.get(
        str(status or "candidate").lower(),
        1,
    )


def _merge_evidence(existing, new):
    old_evidence = str(existing.get("evidence", "") or "")
    new_evidence = str(new.get("evidence", "") or "")

    if new_evidence and new_evidence != old_evidence:
        if old_evidence:
            existing["evidence"] = old_evidence + "\n" + new_evidence
        else:
            existing["evidence"] = new_evidence


def add_finding(finding):
    findings = load_json(FINDINGS_FILE, [])

    fingerprint = finding_fingerprint(finding)
    finding["fingerprint"] = fingerprint

    now = datetime.now(timezone.utc).isoformat()

    new_status = str(
        finding.get("status", "candidate")
    ).lower()

    for existing in findings:
        # Upgrade findings created before fingerprint/status support.
        existing_fingerprint = existing.get("fingerprint")

        if not existing_fingerprint:
            existing_fingerprint = finding_fingerprint(existing)
            existing["fingerprint"] = existing_fingerprint

        if existing_fingerprint != fingerprint:
            continue

        old_status = str(
            existing.get("status", "candidate")
        ).lower()

        finding["id"] = existing.get(
            "id",
            len(findings) + 1
        )

        finding["created_at"] = existing.get(
            "created_at",
            now
        )

        finding["updated_at"] = now

        if _status_priority(new_status) >= _status_priority(old_status):
            existing.update(finding)
        else:
            _merge_evidence(existing, finding)

            old_confidence = float(
                existing.get("confidence", 0) or 0
            )
            new_confidence = float(
                finding.get("confidence", 0) or 0
            )

            if new_confidence > old_confidence:
                existing["confidence"] = new_confidence

            existing["updated_at"] = now

        save_json(FINDINGS_FILE, findings)

        return existing

    finding["id"] = (
        max(
            [item.get("id", 0) for item in findings],
            default=0,
        ) + 1
    )

    finding["created_at"] = now
    finding["updated_at"] = now

    findings.append(finding)

    save_json(FINDINGS_FILE, findings)

    return finding


def get_findings():
    return load_json(FINDINGS_FILE, [])


def clear_findings():
    save_json(FINDINGS_FILE, [])
