from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from .models import Finding
from .utils import get_field


class RuleError(ValueError):
    pass


def load_rules(directory: str | Path) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    for path in sorted(Path(directory).glob("*.yml")):
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
        if not isinstance(data, dict) or "id" not in data or "match" not in data:
            raise RuleError(f"Invalid rule file: {path}")
        data["_path"] = str(path)
        rules.append(data)
    return rules


def _compare(actual: Any, op: str, expected: Any) -> bool:
    if op == "equals":
        return str(actual).lower() == str(expected).lower()
    if op == "contains":
        return str(expected).lower() in str(actual).lower()
    if op == "regex":
        return bool(re.search(str(expected), str(actual)))
    if op == "in":
        values = expected if isinstance(expected, list) else [expected]
        return any(str(actual).lower() == str(value).lower() for value in values)
    if op == "exists":
        return (actual is not None) is bool(expected)
    raise RuleError(f"Unsupported operator: {op}")


def _condition_matches(event: dict, condition: dict) -> bool:
    field = condition.get("field")
    op = condition.get("op", "equals")
    if not field:
        raise RuleError("Condition is missing field")
    return _compare(get_field(event, field), op, condition.get("value"))


def rule_matches(event: dict, rule: dict) -> bool:
    spec = rule.get("match", {})
    if "all" in spec:
        return all(_condition_matches(event, condition) for condition in spec["all"])
    if "any" in spec:
        return any(_condition_matches(event, condition) for condition in spec["any"])
    raise RuleError(f"Rule {rule.get('id')} requires match.all or match.any")


def evaluate_rules(events: list[dict], rules: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    for event in events:
        for rule in rules:
            if not rule_matches(event, rule):
                continue
            mitre = rule.get("mitre", {})
            evidence_fields = rule.get("evidence", [])
            evidence = {field: get_field(event, field) for field in evidence_fields}
            findings.append(
                Finding(
                    rule_id=str(rule["id"]),
                    title=str(rule.get("title", rule["id"])),
                    severity=str(rule.get("severity", "medium")).lower(),
                    timestamp=event["_timestamp"],
                    host=str(event.get("host", "")),
                    user=str(event.get("user", "")),
                    src_ip=str(event.get("src_ip", "")),
                    tactic=str(mitre.get("tactic", "")),
                    technique=str(mitre.get("technique", "")),
                    description=str(rule.get("description", "")),
                    evidence=evidence,
                )
            )
    return findings
