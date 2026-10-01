from __future__ import annotations

from bugbrain.engine.exploitability import exploitability_engine
from bugbrain.engine.exploitability_sqli import verify_sqli_candidate


def register_builtin_verifiers():
    """
    Register BugBrain's built-in exploitability verifiers.

    Registration happens explicitly and is safe to call more than once.
    """

    if not exploitability_engine.supported(
        "sqli_candidate"
    ):
        exploitability_engine.register(
            "sqli_candidate",
            verify_sqli_candidate,
            active=True,
            risk_level="medium",
            description=(
                "Perform a benign differential check against "
                "the identified URL parameter. This test does "
                "not submit SQL injection payloads and does "
                "not attempt database access or data extraction."
            ),
        )


register_builtin_verifiers()
