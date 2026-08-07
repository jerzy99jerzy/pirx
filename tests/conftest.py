"""Shared fixtures and builders."""

from __future__ import annotations

import json
from typing import Any

#: An action name that must never appear in the production registry; the
#: harness asserts on it. Kept after the fixture that once used it was
#: removed as dead (F28).
TEST_ACTION = "test.noop"


def verdict(cve: str = "CVE-2026-1001", **over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "cve_id": cve,
        "priority": "P1",
        "in_kev": True,
        "epss": 0.87421,
        "cvss": 9.8,
        "cvss_pending": False,
        "estate_state": "present",
        "vex_status": "affected",
        "score": 91.5,
        "triage_note": "Exploited in the wild; internet-facing asset.",
        "recommended_action": "Patch to 4.2.1 or isolate.",
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve}",
    }
    base.update(over)
    return base


def bundle(
    verdicts: list[dict[str, Any]] | None = None,
    lane: list[str] | None = None,
    schema: str = "cve-digest.verdict/1",
) -> bytes:
    body = {
        "schema": schema,
        "verdicts": verdicts if verdicts is not None else [verdict()],
        "review_lane": lane or [],
        "notices": [],
    }
    return json.dumps(body).encode("utf-8")


class FakeClock:
    """Injected monotonic clock. The only test seam the design admits."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds
