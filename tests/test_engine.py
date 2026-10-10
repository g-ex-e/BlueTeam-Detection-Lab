from pathlib import Path

from bluehunt.engine import analyze


ROOT = Path(__file__).resolve().parents[1]


def test_demo_dataset_generates_expected_detections():
    events, findings = analyze(ROOT / "samples" / "events.jsonl", ROOT / "rules")
    ids = {finding.rule_id for finding in findings}
    assert len(events) == 19
    assert "BH-CORR-001" in ids
    assert "BH-CORR-002" in ids
    assert "BH-WIN-001" in ids
    assert "BH-WIN-002" in ids
    assert "BH-WIN-003" in ids
    assert "BH-WIN-004" in ids
    assert "BH-WIN-005" in ids
    assert "BH-WIN-006" in ids
