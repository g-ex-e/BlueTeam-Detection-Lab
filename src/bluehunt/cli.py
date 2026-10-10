from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import analyze
from .report import write_html, write_json
from .rules import load_rules
from .utils import SEVERITY_ORDER


def _default_rules() -> Path:
    return Path(__file__).resolve().parents[2] / "rules"


def _print_findings(findings) -> None:
    if not findings:
        print("No findings.")
        return
    print(f"{'SEVERITY':9} {'TIME':20} {'RULE':13} {'HOST':12} {'USER':12} {'SOURCE IP':15} TITLE")
    print("-" * 112)
    for finding in findings:
        timestamp = finding.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        print(
            f"{finding.severity.upper():9} {timestamp:20} {finding.rule_id:13} "
            f"{finding.host[:12]:12} {finding.user[:12]:12} {finding.src_ip[:15]:15} {finding.title}"
        )


def command_analyze(args: argparse.Namespace) -> int:
    events, findings = analyze(args.events, args.rules)
    minimum = SEVERITY_ORDER[args.min_severity]
    findings = [finding for finding in findings if SEVERITY_ORDER.get(finding.severity, 0) >= minimum]
    _print_findings(findings)
    print(f"\nAnalyzed {len(events)} events · {len(findings)} findings")
    if args.json:
        write_json(findings, args.json)
        print(f"JSON report: {args.json}")
    if args.html:
        write_html(findings, len(events), args.html)
        print(f"HTML report: {args.html}")
    return 1 if args.fail_on_findings and findings else 0


def command_rules(args: argparse.Namespace) -> int:
    rules = load_rules(args.rules)
    print(f"{'ID':14} {'SEVERITY':9} {'MITRE':12} TITLE")
    print("-" * 80)
    for rule in rules:
        mitre = rule.get("mitre", {})
        print(f"{rule['id']:14} {str(rule.get('severity','medium')).upper():9} {str(mitre.get('technique','')):12} {rule.get('title','')}")
    print(f"\n{len(rules)} static rules loaded. Correlation detections are implemented in the engine.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bluehunt", description="Defensive security detection lab and threat-hunting CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser("analyze", help="Analyze a JSONL event file")
    analyze_parser.add_argument("events", help="Path to normalized JSONL events")
    analyze_parser.add_argument("--rules", default=str(_default_rules()), help="Directory containing YAML rules")
    analyze_parser.add_argument("--json", help="Write findings to JSON")
    analyze_parser.add_argument("--html", help="Write an HTML report")
    analyze_parser.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default="low")
    analyze_parser.add_argument("--fail-on-findings", action="store_true", help="Exit with status 1 when findings are present")
    analyze_parser.set_defaults(func=command_analyze)

    rules_parser = subparsers.add_parser("rules", help="List static detection rules")
    rules_parser.add_argument("--rules", default=str(_default_rules()))
    rules_parser.set_defaults(func=command_rules)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
