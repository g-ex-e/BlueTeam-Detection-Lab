$ErrorActionPreference = "Stop"
if (-not (Test-Path ".venv")) { python -m venv .venv }
& .\.venv\Scripts\Activate.ps1
python -m pip install -U pip
pip install -e .
pip install pytest
bluehunt analyze samples\events.jsonl --json reports\demo-findings.json --html reports\demo-report.html
Write-Host "`nOpen reports\demo-report.html in your browser."
