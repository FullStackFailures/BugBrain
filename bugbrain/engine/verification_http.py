from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

import requests

from bugbrain.core.config import get_config
from bugbrain.engine.verification_policy import verification_policy


@dataclass
class VerificationResponse:
    url: str
    status_code: int
    headers: Dict[str, str]
    body: str
    elapsed_ms: float
    content_length: int


class VerificationHTTPClient:
    """
    Controlled HTTP client for BugBrain exploitability verification.

    Every request passes through VerificationPolicy before being sent.
    """

    def __init__(
        self,
        timeout: Optional[int] = None,
        user_agent: Optional[str] = None,
    ) -> None:

        config = get_config()
        settings = config.get("settings", {})

        self.timeout = int(
            timeout
            if timeout is not None
            else settings.get("timeout", 10)
        )

        self.user_agent = (
            user_agent
            or settings.get(
                "user_agent",
                "BugBrain/0.1",
            )
        )

        self.session = requests.Session()

        self.session.headers.update({
            "User-Agent": self.user_agent,
        })

    def get(
        self,
        url: str,
        params: Optional[dict] = None,
    ) -> VerificationResponse:

        return self._request(
            "GET",
            url,
            params=params,
        )

    def post(
        self,
        url: str,
        data: Optional[dict] = None,
    ) -> VerificationResponse:

        return self._request(
            "POST",
            url,
            data=data,
        )

    def _request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
    ) -> VerificationResponse:

        url_check = verification_policy.check_url(url)

        if not url_check.allowed:
            raise PermissionError(
                url_check.reason
            )

        method_check = verification_policy.check_method(
            method
        )

        if not method_check.allowed:
            raise PermissionError(
                method_check.reason
            )

        response = self.session.request(
            method=method,
            url=url,
            params=params,
            data=data,
            timeout=self.timeout,
            allow_redirects=False,
        )

        size_check = (
            verification_policy.check_response_size(
                len(response.content)
            )
        )

        if not size_check.allowed:
            raise RuntimeError(
                size_check.reason
            )

        return self._convert(response)

    @staticmethod
    def _convert(
        response: requests.Response,
    ) -> VerificationResponse:

        # HTTP header names are case-insensitive.
        # Normalize them so verification evidence is consistent.
        headers = {
            str(key).lower(): str(value)
            for key, value in response.headers.items()
        }

        return VerificationResponse(
            url=response.url,
            status_code=response.status_code,
            headers=headers,
            body=response.text[:100000],
            elapsed_ms=(
                response.elapsed.total_seconds()
                * 1000
            ),
            content_length=len(response.content),
        )
