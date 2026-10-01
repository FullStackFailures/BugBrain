from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import json


AUDIT_FILE = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "active_verification_audit.jsonl"
)


@dataclass
class PermissionDecision:
    allowed: bool
    operator: str
    reason: str
    risk_level: str
    test_name: str
    target: str = ""
    timestamp: str = ""

    def as_dict(self):
        return {
            "timestamp": self.timestamp,
            "allowed": self.allowed,
            "operator": self.operator,
            "reason": self.reason,
            "risk_level": self.risk_level,
            "test_name": self.test_name,
            "target": self.target,
        }


class ActivePermissionManager:
    """
    Per-test operator permission manager.

    A potentially impactful verification test must receive
    an explicit YES from the local operator.

    Non-interactive execution fails closed and denies the test.

    Every permission decision is written to the local audit log.
    Passwords and other authentication secrets are never logged.
    """

    def __init__(self):
        self.decisions = []

    def _timestamp(self):
        return datetime.now(timezone.utc).isoformat()

    def _audit(self, decision: PermissionDecision):
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
                        decision.as_dict(),
                        ensure_ascii=False,
                    )
                    + "\n"
                )

        except OSError as exc:
            # Audit failure must never turn into permission
            # approval. The verification decision itself remains
            # authoritative.
            print(
                f"[!] Warning: could not write active "
                f"verification audit log: {exc}"
            )

    def _record(
        self,
        *,
        allowed: bool,
        operator: str,
        reason: str,
        risk_level: str,
        test_name: str,
        target: str,
    ) -> PermissionDecision:

        decision = PermissionDecision(
            allowed=allowed,
            operator=operator,
            reason=reason,
            risk_level=risk_level,
            test_name=test_name,
            target=target,
            timestamp=self._timestamp(),
        )

        self.decisions.append(decision)
        self._audit(decision)

        return decision

    def request(
        self,
        *,
        test_name: str,
        target: str,
        risk_level: str = "medium",
        description: str = "",
    ) -> PermissionDecision:

        print()
        print("=" * 72)
        print("BUGBRAIN ACTIVE VERIFICATION PERMISSION")
        print("=" * 72)
        print(f"Target     : {target}")
        print(f"Test       : {test_name}")
        print(f"Risk level : {risk_level}")
        print()

        if description:
            print("Test description:")
            print(description)
            print()

        print("This operation requires explicit operator permission.")
        print("Enter YES to execute this test.")
        print("Enter NO to skip this test.")
        print()

        try:
            answer = input(
                "Proceed with this test? [YES/NO]: "
            ).strip().upper()

        except (EOFError, KeyboardInterrupt):

            decision = self._record(
                allowed=False,
                operator="local_operator",
                reason=(
                    "No interactive permission was available; "
                    "test denied by default."
                ),
                risk_level=risk_level,
                test_name=test_name,
                target=target,
            )

            print()
            print("Permission unavailable. Test denied safely.")

            return decision

        if answer == "YES":

            return self._record(
                allowed=True,
                operator="local_operator",
                reason="Operator explicitly approved the test.",
                risk_level=risk_level,
                test_name=test_name,
                target=target,
            )

        return self._record(
            allowed=False,
            operator="local_operator",
            reason="Operator denied the test.",
            risk_level=risk_level,
            test_name=test_name,
            target=target,
        )

    def history(self):
        return [
            decision.as_dict()
            for decision in self.decisions
        ]


permission_manager = ActivePermissionManager()
