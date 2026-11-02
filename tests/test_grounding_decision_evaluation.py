
import json
from pathlib import Path

import pytest

from backend.grounding_decision_policy import (
    decide_grounding_action,
)


ROOT = Path(__file__).resolve().parent.parent

REPORT_PATH = (
    ROOT / "results" / "44_grounding_decision_evaluation.json"
)

EXPECTED_ACTIONS = {
    "GR-001": "release_candidate",
    "GR-002": "block",
    "GR-003": "block",
    "GR-004": "block",
    "GR-005": "release_candidate",
    "GR-006": "review_required",
    "GR-007": "review_required",
    "GR-008": "block",
    "GR-009": "review_required",
    "GR-010": "block",
}


@pytest.fixture(scope="module")
def evaluation_report():
    return json.loads(
        REPORT_PATH.read_text(encoding="utf-8")
    )


@pytest.mark.parametrize(
    "case_id,expected_action",
    list(EXPECTED_ACTIONS.items()),
)
def test_saved_grounding_decision(
    evaluation_report,
    case_id,
    expected_action,
):
    cases = {
        case["id"]: case
        for case in evaluation_report["results"]
    }

    case = cases[case_id]

    decision = decide_grounding_action(
        rule_status=case["rule_status"],
        hybrid_status=case["hybrid_status"],
        citations_verified=case["simulated_citation_check"],
        injection_detected=False,
    )

    assert decision["action"] == expected_action
    assert case["actual_action"] == expected_action
    assert case["matches_expectation"] is True


def test_decision_summary(evaluation_report):
    summary = evaluation_report["summary"]

    assert summary["total_cases"] == 10
    assert summary["block"] == 5
    assert summary["review_required"] == 3
    assert summary["release_candidate"] == 2
    assert summary["expectation_mismatches"] == []
    assert summary["false_release_candidates"] == []


def test_no_unsupported_claim_is_release_candidate(
    evaluation_report,
):
    for case in evaluation_report["results"]:
        if case["actual_action"] == "release_candidate":
            assert case["expected_claim_status"] == "supported"
