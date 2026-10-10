from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta

from .models import Finding


def _is_failed_auth(event: dict) -> bool:
    return str(event.get("event_id", "")) in {"4625", "AUTH_FAIL"} or (
        str(event.get("category", "")).lower() == "authentication"
        and str(event.get("status", "")).lower() == "failed"
    )


def detect_bruteforce(events: list[dict], threshold: int = 6, window_seconds: int = 120) -> list[Finding]:
    buckets: dict[tuple[str, str, str], deque] = defaultdict(deque)
    emitted: dict[tuple[str, str, str], object] = {}
    findings: list[Finding] = []
    window = timedelta(seconds=window_seconds)

    for event in events:
        if not _is_failed_auth(event):
            continue
        key = (str(event.get("host", "")), str(event.get("user", "")), str(event.get("src_ip", "")))
        queue = buckets[key]
        queue.append(event)
        while queue and event["_timestamp"] - queue[0]["_timestamp"] > window:
            queue.popleft()
        if len(queue) < threshold:
            continue
        previous = emitted.get(key)
        if previous is not None and event["_timestamp"] - previous <= window:
            continue
        emitted[key] = event["_timestamp"]
        findings.append(
            Finding(
                rule_id="BH-CORR-001",
                title="Brute-force authentication burst",
                severity="high",
                timestamp=event["_timestamp"],
                host=key[0],
                user=key[1],
                src_ip=key[2],
                tactic="Credential Access",
                technique="T1110.001",
                description=f"At least {threshold} failed authentications were observed within {window_seconds} seconds.",
                evidence={"failed_attempts": len(queue), "window_seconds": window_seconds},
            )
        )
    return findings


def detect_password_spray(events: list[dict], min_users: int = 5, window_seconds: int = 300) -> list[Finding]:
    buckets: dict[tuple[str, str], deque] = defaultdict(deque)
    emitted: dict[tuple[str, str], object] = {}
    findings: list[Finding] = []
    window = timedelta(seconds=window_seconds)

    for event in events:
        if not _is_failed_auth(event):
            continue
        key = (str(event.get("host", "")), str(event.get("src_ip", "")))
        queue = buckets[key]
        queue.append(event)
        while queue and event["_timestamp"] - queue[0]["_timestamp"] > window:
            queue.popleft()
        users = sorted({str(item.get("user", "")) for item in queue if item.get("user")})
        if len(users) < min_users:
            continue
        previous = emitted.get(key)
        if previous is not None and event["_timestamp"] - previous <= window:
            continue
        emitted[key] = event["_timestamp"]
        findings.append(
            Finding(
                rule_id="BH-CORR-002",
                title="Password spraying pattern",
                severity="high",
                timestamp=event["_timestamp"],
                host=key[0],
                src_ip=key[1],
                tactic="Credential Access",
                technique="T1110.003",
                description=f"Failed authentications targeted at least {min_users} distinct users within {window_seconds} seconds.",
                evidence={"distinct_users": users, "attempts": len(queue), "window_seconds": window_seconds},
            )
        )
    return findings
