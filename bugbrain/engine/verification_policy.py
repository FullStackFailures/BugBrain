from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from bugbrain.core.config import get_config
from bugbrain.core.scope import is_in_scope


@dataclass
class VerificationPolicyResult:
    allowed: bool
    reason: str


class VerificationPolicy:
    """
    Central safety policy for BugBrain exploitability verification.

    Every active verification request should pass through this policy
    before the request is sent.
    """

    ALLOWED_METHODS = {
        "GET",
        "HEAD",
        "POST",
    }

    MAX_RESPONSE_BYTES = 1_000_000

    def __init__(self):
        config = get_config()
        settings = config.get("settings", {})

        self.safe_mode = bool(
            settings.get("safe_mode", True)
        )

        self.max_redirects = int(
            settings.get("max_redirects", 5)
        )

    def check_url(
        self,
        url: str,
    ) -> VerificationPolicyResult:

        if not self.safe_mode:
            return VerificationPolicyResult(
                False,
                "Verification requires safe_mode=True.",
            )

        if not url:
            return VerificationPolicyResult(
                False,
                "Missing verification URL.",
            )

        try:
            parsed = urlparse(url)
        except ValueError:
            return VerificationPolicyResult(
                False,
                "Invalid verification URL.",
            )

        if parsed.scheme not in {
            "http",
            "https",
        }:
            return VerificationPolicyResult(
                False,
                "Only HTTP and HTTPS verification targets are allowed.",
            )

        if not parsed.hostname:
            return VerificationPolicyResult(
                False,
                "Verification URL has no hostname.",
            )

        if not is_in_scope(parsed.hostname):
            return VerificationPolicyResult(
                False,
                f"Target is outside BugBrain scope: {parsed.hostname}",
            )

        return VerificationPolicyResult(
            True,
            "Target is in scope and passed the URL policy.",
        )

    def check_method(
        self,
        method: str,
    ) -> VerificationPolicyResult:

        method = str(method or "").upper()

        if method not in self.ALLOWED_METHODS:
            return VerificationPolicyResult(
                False,
                f"HTTP method is not allowed for safe verification: {method}",
            )

        return VerificationPolicyResult(
            True,
            "HTTP method is allowed.",
        )

    def check_response_size(
        self,
        content_length: int,
    ) -> VerificationPolicyResult:

        try:
            size = int(content_length)
        except (TypeError, ValueError):
            size = 0

        if size > self.MAX_RESPONSE_BYTES:
            return VerificationPolicyResult(
                False,
                "Response exceeded the verification size limit.",
            )

        return VerificationPolicyResult(
            True,
            "Response size is within the verification limit.",
        )


verification_policy = VerificationPolicy()
