from __future__ import annotations

import getpass
import hashlib
import hmac
import os
from dataclasses import dataclass


@dataclass
class ActiveModeResult:
    enabled: bool
    reason: str

    def as_dict(self):
        return {
            "enabled": self.enabled,
            "reason": self.reason,
        }


class ActiveVerificationMode:
    """
    Controls entry into BugBrain's active verification mode.

    The password is never stored in this module.
    It is supplied through BUGBRAIN_ACTIVE_VERIFY_PASSWORD.
    """

    ENV_NAME = "BUGBRAIN_ACTIVE_VERIFY_PASSWORD"

    def __init__(self):
        self.enabled = False

    def activate(self) -> ActiveModeResult:
        expected = os.environ.get(self.ENV_NAME)

        if not expected:
            self.enabled = False
            return ActiveModeResult(
                enabled=False,
                reason=(
                    f"{self.ENV_NAME} is not configured. "
                    "Active verification remains disabled."
                ),
            )

        try:
            supplied = getpass.getpass(
                "BugBrain Active Verification password: "
            )
        except (EOFError, KeyboardInterrupt):
            self.enabled = False
            return ActiveModeResult(
                enabled=False,
                reason="Password input was unavailable or cancelled.",
            )

        if not self._secure_compare(supplied, expected):
            self.enabled = False
            return ActiveModeResult(
                enabled=False,
                reason="Incorrect Active Verification password.",
            )

        self.enabled = True

        return ActiveModeResult(
            enabled=True,
            reason="Active Verification Mode enabled for this process.",
        )

    def deactivate(self):
        self.enabled = False

        return ActiveModeResult(
            enabled=False,
            reason="Active Verification Mode disabled.",
        )

    def require_enabled(self):
        if not self.enabled:
            raise PermissionError(
                "BugBrain Active Verification Mode is not enabled."
            )

        return True

    @staticmethod
    def _secure_compare(left: str, right: str) -> bool:
        return hmac.compare_digest(
            left,
            right,
        )


active_mode = ActiveVerificationMode()
