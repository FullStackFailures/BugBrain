from pathlib import Path
from datetime import datetime


class Reporter:

    def generate(
        self,
        target,
        findings,
        output_dir
    ):
        output_dir = Path(output_dir)

        output_dir.mkdir(
            parents=True,
            exist_ok=True
        )

        timestamp = datetime.now().strftime(
            "%Y%m%d-%H%M%S"
        )

        filename = (
            output_dir
            / f"bugbrain-{timestamp}.md"
        )

        severity_counts = {}

        for finding in findings:

            severity = finding.get(
                "severity",
                "info"
            ).lower()

            severity_counts[severity] = (
                severity_counts.get(
                    severity,
                    0
                ) + 1
            )

        lines = [
            "# BugBrain Security Assessment",
            "",
            f"**Target:** `{target}`",
            "",
            f"**Generated:** "
            f"{datetime.now().isoformat()}",
            "",
            "## Executive Summary",
            "",
            "BugBrain performed automated, "
            "low-impact reconnaissance and "
            "security checks against the "
            "authorized target.",
            "",
            f"Total observations: "
            f"**{len(findings)}**",
            ""
        ]

        if severity_counts:

            lines.extend([
                "### Severity Overview",
                ""
            ])

            for severity in (
                "critical",
                "high",
                "medium",
                "low",
                "info"
            ):

                count = severity_counts.get(
                    severity,
                    0
                )

                if count:
                    lines.append(
                        f"- **{severity.title()}:** "
                        f"{count}"
                    )

            lines.append("")

        lines.extend([
            "## Methodology",
            "",
            "- Authorized target validation",
            "- Network service discovery",
            "- HTTP/HTTPS discovery",
            "- Web-page reconnaissance",
            "- Technology observation",
            "- Security-header analysis",
            "- Discovery-file checks",
            "",
            "No destructive exploitation was "
            "performed by BugBrain.",
            "",
            "## Findings",
            ""
        ])

        if not findings:

            lines.extend([
                "No findings were generated.",
                ""
            ])

        for number, finding in enumerate(
            findings,
            start=1
        ):

            severity = finding.get(
                "severity",
                "info"
            )

            lines.extend([
                f"## {number}. "
                f"{finding.get('title', 'Untitled')}",
                "",
                f"**Severity:** `{severity}`",
                "",
                f"**Confidence:** "
                f"`{finding.get('confidence', '')}`",
                "",
                f"**Type:** "
                f"`{finding.get('type', '')}`",
                ""
            ])

            if finding.get("url"):

                lines.extend([
                    "**Affected URL:**",
                    "",
                    f"`{finding['url']}`",
                    ""
                ])

            if finding.get("summary"):

                lines.extend([
                    "### Summary",
                    "",
                    finding["summary"],
                    ""
                ])

            if finding.get("evidence"):

                lines.extend([
                    "### Evidence",
                    "",
                    "```text",
                    str(
                        finding["evidence"]
                    ),
                    "```",
                    ""
                ])

            if finding.get(
                "reproduction"
            ):

                lines.extend([
                    "### Reproduction",
                    "",
                    finding["reproduction"],
                    ""
                ])

            if finding.get("impact"):

                lines.extend([
                    "### Impact",
                    "",
                    finding["impact"],
                    ""
                ])

            if finding.get(
                "remediation"
            ):

                lines.extend([
                    "### Remediation",
                    "",
                    finding["remediation"],
                    ""
                ])

        lines.extend([
            "## Limitations",
            "",
            "Automated reconnaissance can identify "
            "potential security issues but cannot "
            "establish exploitability for every "
            "observation.",
            "",
            "Findings should be manually validated "
            "before submission to a bug-bounty "
            "program.",
            ""
        ])

        filename.write_text(
            "\n".join(lines),
            encoding="utf-8"
        )

        return filename
