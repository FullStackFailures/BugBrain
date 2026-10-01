from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

from bugbrain.engine.evidence import (
    create_evidence,
    mark_verification,
    evidence_is_verified,
)

from bugbrain.engine.confidence import (
    calculate_confidence,
    should_confirm,
)


class VerificationResult:

    def __init__(
        self,
        status,
        confidence,
        method,
        evidence,
        repeatable=True,
        reason="",
    ):
        self.status = status
        self.confidence = confidence
        self.method = method
        self.evidence = evidence
        self.repeatable = repeatable
        self.reason = reason

    def as_dict(self):

        return {
            "status": self.status,
            "confidence": self.confidence,
            "verification": {
                "method": self.method,
                "repeatable": self.repeatable,
                "verified_at": datetime.now(
                    timezone.utc
                ).isoformat(),
                "reason": self.reason,
            },
            "evidence": self.evidence,
        }


class FindingVerifier:
    """
    Strict BugBrain evidence verifier.

    Detection and verification are intentionally separate.

    A suspicious pattern is NOT a confirmed vulnerability.

    Confirmation requires:
        1. A deterministic verifier or strong verification evidence.
        2. Reproducible behavior.
        3. Sufficient evidence.
        4. The final evidence gate must also permit confirmation.
    """

    DIRECT_OBSERVATION_TYPES = {
        "security_header",
        "transport_security",
        "tls_configuration",
        "tls_certificate",
        "discovery_file",
        "source_map_exposure",
        "cookie_security",
        "cors_configuration",
        "information_disclosure",
    }

    HEURISTIC_ONLY_TYPES = {

        # Original candidates
        "injection_candidate",
        "xss_reflection_candidate",
        "csrf_candidate",
        "ssrf_candidate",
        "open_redirect_candidate",
        "idor_candidate",
        "path_traversal_candidate",
        "sensitive_data_url",
        "file_upload_surface",
        "authentication_surface",
        "sensitive_endpoint",
        "api_discovery",
        "websocket_discovery",

        # Injection signatures
        "sqli_candidate",
        "xss_candidate",
        "command_injection_candidate",
        "ssti_candidate",
        "ldap_injection_candidate",
        "nosql_injection_candidate",

        # Application/security candidates
        "authentication_candidate",
        "file_upload_candidate",
        "api_security_candidate",
        "websocket_security_candidate",

        # Modern security candidates
        "api_surface",
        "bola_candidate",
        "bopla_candidate",
        "privileged_function_candidate",
        "sensitive_business_flow",
        "graphql_surface",
        "oauth_oidc_surface",
        "webhook_surface",
        "debug_management_surface",
        "cloud_storage_reference",
        "api_version_inventory",
        "resource_consumption_candidate",
        "jwt_observation",

        # Endpoint intelligence
        "api_endpoint_surface",
        "api_documentation_surface",
        "privileged_endpoint_surface",
        "debug_management_surface",
        "webhook_surface",
        "sensitive_parameter_surface",
        "api_endpoint_inventory",
        "javascript_route_surface",
        "websocket_surface",
    }

    def verify(self, finding):

        finding_type = str(
            finding.get(
                "type",
                "",
            )
        ).strip().lower()

        # -----------------------------------------------------
        # HARD HEURISTIC SAFETY GATE
        # -----------------------------------------------------

        if finding_type in self.HEURISTIC_ONLY_TYPES:

            return self._candidate(
                finding,
                method="heuristic_detection_only",
                reason=(
                    "The scanner detected a security-relevant "
                    "pattern, but the available evidence does "
                    "not prove exploitability or security impact."
                ),
            )

        # -----------------------------------------------------
        # Dedicated deterministic verifier
        # -----------------------------------------------------

        verifier = getattr(
            self,
            f"_verify_{finding_type}",
            None,
        )

        if verifier is None:

            return self._candidate(
                finding,
                method="no_deterministic_verifier",
                reason=(
                    "No dedicated verifier exists for this "
                    "finding type."
                ),
            )

        return verifier(finding)

    # =========================================================
    # Candidate
    # =========================================================

    def _candidate(
        self,
        finding,
        method,
        reason,
    ):

        confidence = float(
            finding.get(
                "confidence",
                0.50,
            ) or 0.50
        )

        confidence = min(
            confidence,
            0.89,
        )

        return VerificationResult(
            status="candidate",
            confidence=confidence,
            method=method,
            evidence=finding.get(
                "evidence",
                "",
            ),
            repeatable=False,
            reason=reason,
        )

    # =========================================================
    # Confirmed deterministic observation
    # =========================================================

    def _confirmed(
        self,
        method,
        evidence,
        reason,
    ):

        return VerificationResult(
            status="confirmed",
            confidence=0.99,
            method=method,
            evidence=evidence,
            repeatable=True,
            reason=reason,
        )

    # =========================================================
    # Security header
    # =========================================================

    def _verify_security_header(self, finding):

        evidence = str(
            finding.get(
                "evidence",
                "",
            )
        )

        if "was not present" not in evidence.lower():

            return self._candidate(
                finding,
                "security_header_evidence_check",
                (
                    "The evidence does not establish the "
                    "absence of the security header."
                ),
            )

        return self._confirmed(
            "http_response_header_observation",
            evidence,
            (
                "The HTTP response directly establishes "
                "that the specified security header was absent."
            ),
        )

    # =========================================================
    # Transport security
    # =========================================================

    def _verify_transport_security(self, finding):

        url = str(
            finding.get(
                "url",
                "",
            )
        ).strip()

        if url.lower().startswith("http://"):

            return self._confirmed(
                "http_scheme_observation",
                f"Endpoint is accessible over plaintext HTTP: {url}",
                (
                    "The endpoint URL directly establishes "
                    "plaintext HTTP transport."
                ),
            )

        return self._candidate(
            finding,
            "http_scheme_check",
            (
                "The collected evidence does not establish "
                "plaintext transport."
            ),
        )

    # =========================================================
    # TLS configuration
    # =========================================================

    def _verify_tls_configuration(self, finding):

        evidence = str(
            finding.get(
                "evidence",
                "",
            )
        )

        title = str(
            finding.get(
                "title",
                "",
            )
        ).lower()

        if (
            "obsolete tls protocol" in title
            or "obsolete protocol" in evidence.lower()
        ):

            return self._confirmed(
                "tls_negotiation_observation",
                evidence,
                (
                    "The scanner directly observed an obsolete "
                    "TLS protocol during negotiation."
                ),
            )

        return self._candidate(
            finding,
            "tls_configuration_check",
            (
                "The available evidence does not establish "
                "an obsolete protocol."
            ),
        )

    # =========================================================
    # TLS certificate
    # =========================================================

    def _verify_tls_certificate(self, finding):

        title = str(
            finding.get(
                "title",
                "",
            )
        ).lower()

        evidence = str(
            finding.get(
                "evidence",
                "",
            )
        )

        if "expired" in title:

            return self._confirmed(
                "tls_certificate_validity_check",
                evidence,
                (
                    "The certificate validity data directly "
                    "establishes expiration."
                ),
            )

        return self._candidate(
            finding,
            "tls_certificate_check",
            (
                "The available certificate evidence does not "
                "establish a confirmed certificate problem."
            ),
        )

    # =========================================================
    # Discovery file
    # =========================================================

    def _verify_discovery_file(self, finding):

        evidence = str(
            finding.get(
                "evidence",
                "",
            )
        )

        if "http 200" in evidence.lower():

            return self._confirmed(
                "http_status_observation",
                evidence,
                (
                    "The HTTP response establishes that the "
                    "discovery file is publicly accessible."
                ),
            )

        return self._candidate(
            finding,
            "discovery_file_status_check",
            (
                "The available evidence does not establish "
                "public accessibility."
            ),
        )

    # =========================================================
    # Source map
    # =========================================================

    def _verify_source_map_exposure(self, finding):

        url = str(
            finding.get(
                "url",
                "",
            )
        ).strip()

        if not url:

            return self._candidate(
                finding,
                "source_map_retrieval_check",
                "No source-map URL was available.",
            )

        parsed = urlparse(url)

        if parsed.scheme not in (
            "http",
            "https",
        ):

            return self._candidate(
                finding,
                "source_map_retrieval_check",
                (
                    f"Unsupported URL scheme: "
                    f"{parsed.scheme}"
                ),
            )

        try:

            response = requests.get(
                url,
                timeout=10,
                allow_redirects=False,
                headers={
                    "User-Agent": "BugBrain/verification",
                },
            )

        except requests.RequestException as exc:

            return self._candidate(
                finding,
                "source_map_retrieval_check",
                f"Source map retrieval failed: {exc}",
            )

        body = response.text[:200000]

        looks_like_map = (
            '"version"' in body
            and (
                '"sources"' in body
                or '"mappings"' in body
            )
        )

        evidence = (
            f"HTTP {response.status_code}; "
            f"Content-Type: "
            f"{response.headers.get('Content-Type', '')}; "
            f"source-map structure: {looks_like_map}"
        )

        if (
            response.status_code == 200
            and looks_like_map
        ):

            return self._confirmed(
                "source_map_retrieval_and_content_check",
                evidence,
                (
                    "The URL returned source-map data, "
                    "establishing public source-map exposure."
                ),
            )

        return self._candidate(
            finding,
            "source_map_retrieval_and_content_check",
            evidence,
        )

    # =========================================================
    # Cookie security
    # =========================================================

    def _verify_cookie_security(self, finding):

        evidence = str(
            finding.get(
                "evidence",
                "",
            )
        )

        if evidence:

            return self._confirmed(
                "set_cookie_header_observation",
                evidence,
                (
                    "The Set-Cookie header directly establishes "
                    "the observed cookie configuration."
                ),
            )

        return self._candidate(
            finding,
            "set_cookie_header_check",
            "No concrete Set-Cookie evidence was available.",
        )

    # =========================================================
    # CORS
    # =========================================================

    def _verify_cors_configuration(self, finding):

        evidence = str(
            finding.get(
                "evidence",
                "",
            )
        )

        if (
            "access-control-allow-origin: *"
            in evidence.lower()
        ):

            return self._confirmed(
                "http_cors_header_observation",
                evidence,
                (
                    "The HTTP response directly establishes "
                    "the observed wildcard CORS configuration."
                ),
            )

        return self._candidate(
            finding,
            "http_cors_header_check",
            (
                "The available evidence does not establish "
                "the reported CORS configuration."
            ),
        )

    # =========================================================
    # Information disclosure
    # =========================================================

    def _verify_information_disclosure(self, finding):

        evidence = str(
            finding.get(
                "evidence",
                "",
            )
        )

        if evidence.lower().startswith(
            "server:"
        ):

            return self._confirmed(
                "http_response_header_observation",
                evidence,
                (
                    "The HTTP response directly establishes "
                    "the disclosed server information."
                ),
            )

        return self._candidate(
            finding,
            "information_disclosure_check",
            (
                "The evidence does not establish the "
                "reported information disclosure."
            ),
        )

    # =========================================================
    # Evidence-aware generic verification
    # =========================================================

    def _verify_with_structured_evidence(self, finding):

        evidence = finding.get(
            "evidence"
        )

        if not isinstance(
            evidence,
            dict
        ):

            return None

        analyzed = calculate_confidence(
            finding
        )

        if should_confirm(
            analyzed
        ):

            return self._confirmed(
                "structured_reproducible_evidence",
                evidence,
                (
                    "Structured evidence contains sufficient "
                    "reproducible evidence for confirmation."
                ),
            )

        return self._candidate(
            finding,
            "structured_evidence_insufficient",
            (
                "Structured evidence exists, but it does not "
                "yet establish reproducible security impact."
            ),
        )

    # =========================================================
    # Default
    # =========================================================

    def _verify_generic(self, finding):

        structured_result = (
            self._verify_with_structured_evidence(
                finding
            )
        )

        if structured_result is not None:

            return structured_result

        return self._candidate(
            finding,
            "generic_evidence_review",
            (
                "BugBrain has no dedicated deterministic "
                "verification rule for this finding."
            ),
        )


def verify_finding(finding):

    verifier = FindingVerifier()

    result = verifier.verify(
        finding
    )

    verified = dict(
        finding
    )

    verified.update(
        result.as_dict()
    )

    # ---------------------------------------------------------
    # Preserve original evidence when verifier returns
    # textual evidence, while retaining structured evidence.
    # ---------------------------------------------------------

    if (
        isinstance(
            finding.get("evidence"),
            dict
        )
        and isinstance(
            verified.get("evidence"),
            str
        )
    ):

        verified["evidence_text"] = verified[
            "evidence"
        ]

        verified["evidence"] = finding[
            "evidence"
        ]

    return verified


# ============================================================
# BUGBRAIN STRICT EVIDENCE GATE
# ============================================================

HEURISTIC_ONLY_TYPES = (
    FindingVerifier.HEURISTIC_ONLY_TYPES
)


def apply_evidence_gate(finding):

    """
    Final safety gate.

    This function is intentionally stricter than the
    confidence engine.

    A confidence score alone can never confirm a finding.
    """

    if not isinstance(
        finding,
        dict
    ):

        return finding

    finding = dict(
        finding
    )

    finding_type = str(
        finding.get(
            "type",
            ""
        )
    ).lower()

    # ---------------------------------------------------------
    # Heuristic findings can NEVER be automatically confirmed.
    # ---------------------------------------------------------

    if finding_type in HEURISTIC_ONLY_TYPES:

        finding["status"] = "candidate"

        finding["verification"] = {
            "required": True,
            "performed": False,
            "result": "not_verified",
            "reason": (
                "Heuristic detection only. "
                "Security-impact evidence is required "
                "before confirmation."
            ),
        }

        return finding

    # ---------------------------------------------------------
    # Structured evidence
    # ---------------------------------------------------------

    evidence = finding.get(
        "evidence"
    )

    if isinstance(
        evidence,
        dict
    ):

        # Evidence must explicitly contain verification data.
        verified = evidence_is_verified(
            evidence
        )

        if verified:

            # Even verified evidence does not automatically
            # become confirmed unless it is reproducible.
            if evidence.get(
                "reproducible_behavior"
            ):

                finding["status"] = "confirmed"

            else:

                finding["status"] = "candidate"

                finding["verification"] = {
                    "required": True,
                    "performed": True,
                    "result": "verified_observation",
                    "reason": (
                        "Evidence was verified, but reproducible "
                        "security impact was not established."
                    ),
                }

        else:

            finding["status"] = "candidate"

        return finding

    # ---------------------------------------------------------
    # Never allow unsupported "confirmed".
    # ---------------------------------------------------------

    if finding.get(
        "status"
    ) == "confirmed":

        finding["status"] = "candidate"

        finding["verification"] = {
            "required": True,
            "performed": False,
            "result": "insufficient_evidence",
            "reason": (
                "No structured verification evidence "
                "was supplied."
            ),
        }

    return finding
