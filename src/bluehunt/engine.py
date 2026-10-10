from __future__ import annotations

from pathlib import Path

from .correlations import detect_bruteforce, detect_password_spray
from .loader import load_events
from .models import Finding
from .rules import evaluate_rules, load_rules


def analyze(event_file: str | Path, rules_directory: str | Path) -> tuple[list[dict], list[Finding]]:
    events = load_events(event_file)
    rules = load_rules(rules_directory)
    findings = evaluate_rules(events, rules)
    findings.extend(detect_bruteforce(events))
    findings.extend(detect_password_spray(events))
    findings.sort(key=lambda finding: finding.timestamp)
    return events, findings
