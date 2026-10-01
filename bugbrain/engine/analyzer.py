import hashlib

from .confidence import calculate_confidence


SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0
}


class Analyzer:

    def analyze(self, findings):

        unique = {}

        for finding in findings:

            fingerprint = self.fingerprint(
                finding
            )

            finding["fingerprint"] = fingerprint

            existing = unique.get(
                fingerprint
            )

            if existing is None:

                unique[fingerprint] = finding

                continue

            existing_score = (
                SEVERITY_ORDER.get(
                    existing.get(
                        "severity",
                        "info"
                    ),
                    0
                )
            )

            new_score = (
                SEVERITY_ORDER.get(
                    finding.get(
                        "severity",
                        "info"
                    ),
                    0
                )
            )

            # Keep the higher severity finding.
            if new_score > existing_score:

                unique[fingerprint] = finding

                continue

            # If severity is equal, merge
            # additional evidence.
            if new_score == existing_score:

                self.merge_evidence(
                    existing,
                    finding
                )

        # Calculate evidence confidence only
        # after duplicate findings have been merged.
        analyzed = []

        for finding in unique.values():

            result = calculate_confidence(
                finding
            )

            analyzed.append(
                result
            )

        return sorted(
            analyzed,
            key=lambda item: (
                -SEVERITY_ORDER.get(
                    item.get(
                        "severity",
                        "info"
                    ),
                    0
                ),
                -int(
                    item.get(
                        "confidence_score",
                        0
                    ) or 0
                ),
                item.get(
                    "title",
                    ""
                )
            )
        )

    @staticmethod
    def fingerprint(finding):

        target = str(
            finding.get(
                "target",
                ""
            )
        ).lower()

        url = str(
            finding.get(
                "url",
                ""
            )
        ).lower()

        finding_type = str(
            finding.get(
                "type",
                ""
            )
        ).lower()

        title = str(
            finding.get(
                "title",
                ""
            )
        ).lower()

        raw = "|".join([
            target,
            url,
            finding_type,
            title
        ])

        return hashlib.sha256(
            raw.encode()
        ).hexdigest()

    @staticmethod
    def merge_evidence(
        existing,
        new
    ):

        # --------------------------------------------------
        # Structured evidence
        # --------------------------------------------------

        old_evidence = existing.get(
            "evidence"
        )

        new_evidence = new.get(
            "evidence"
        )

        if isinstance(old_evidence, dict) and isinstance(
            new_evidence,
            dict
        ):

            for key, value in new_evidence.items():

                if value is True:

                    old_evidence[key] = True

                elif (
                    key not in old_evidence
                    or not old_evidence[key]
                ):

                    old_evidence[key] = value

        elif isinstance(new_evidence, dict):

            existing["evidence"] = dict(
                new_evidence
            )

        # --------------------------------------------------
        # Legacy textual evidence
        # --------------------------------------------------

        old_text = existing.get(
            "evidence_text",
            ""
        )

        new_text = new.get(
            "evidence_text",
            ""
        )

        if (
            new_text
            and new_text not in old_text
        ):

            if old_text:

                existing["evidence_text"] = (
                    old_text
                    + "\n"
                    + new_text
                )

            else:

                existing["evidence_text"] = (
                    new_text
                )

        # --------------------------------------------------
        # Preserve legacy string evidence.
        #
        # Older BugBrain modules may still use:
        #
        #     evidence: "some text"
        #
        # Do not destroy that information.
        # --------------------------------------------------

        if isinstance(
            old_evidence,
            str
        ):

            old_text = old_evidence

            if isinstance(
                new_evidence,
                str
            ):

                if (
                    new_evidence
                    and new_evidence not in old_text
                ):

                    existing["evidence"] = (
                        old_text
                        + "\n"
                        + new_evidence
                    )

        elif isinstance(
            new_evidence,
            str
        ):

            existing["evidence_text"] = (
                new_evidence
            )

        # --------------------------------------------------
        # Preserve highest legacy confidence value.
        # --------------------------------------------------

        old_confidence = float(
            existing.get(
                "confidence",
                0
            ) or 0
        )

        new_confidence = float(
            new.get(
                "confidence",
                0
            ) or 0
        )

        if new_confidence > old_confidence:

            existing["confidence"] = (
                new_confidence
            )
