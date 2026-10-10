from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    timestamp: datetime
    host: str = ""
    user: str = ""
    src_ip: str = ""
    tactic: str = ""
    technique: str = ""
    description: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "timestamp": self.timestamp.isoformat().replace("+00:00", "Z"),
            "host": self.host,
            "user": self.user,
            "src_ip": self.src_ip,
            "mitre": {"tactic": self.tactic, "technique": self.technique},
            "description": self.description,
            "evidence": self.evidence,
        }
