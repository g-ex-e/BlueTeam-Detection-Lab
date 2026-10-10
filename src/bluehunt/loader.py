from __future__ import annotations

import json
from pathlib import Path

from .utils import parse_timestamp


def load_events(path: str | Path) -> list[dict]:
    events: list[dict] = []
    source = Path(path)
    with source.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_number}: {exc}") from exc
            if "timestamp" not in event:
                raise ValueError(f"Missing timestamp on line {line_number}")
            event["_timestamp"] = parse_timestamp(str(event["timestamp"]))
            events.append(event)
    events.sort(key=lambda item: item["_timestamp"])
    return events
