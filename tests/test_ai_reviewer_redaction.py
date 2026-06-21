from src.ai_reviewer import REDACTED_SECRET, build_review_item
from src.scanner import Finding


def test_build_review_item_redacts_match_preview_and_context():
    candidate = "REDACTION_TEST_VALUE"
    finding = Finding(
        file="app.py",
        line=10,
        col=5,
        secret_type="Synthetic Test Secret",
        match=candidate,
        entropy=4.5,
        pattern_confidence=0.95,
        context_lines=[
            f"10: value = '{candidate}'",
            "11: print('done')",
        ],
    )

    item = build_review_item(finding, 0)

    assert item["match_preview"] == REDACTED_SECRET
    assert candidate not in item["context"]
    assert REDACTED_SECRET in item["context"]
