#!/usr/bin/env bash
set -euo pipefail
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
pip install -e .
pip install pytest
bluehunt analyze samples/events.jsonl --json reports/demo-findings.json --html reports/demo-report.html
echo "Open reports/demo-report.html in your browser."
