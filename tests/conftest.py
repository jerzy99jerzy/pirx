"""Shared fixtures.

The test-only registry lives here so ``PRODUCTION_REGISTRY`` is never mutated:
the empty production registry is the property under test, and a fixture that
reached into it would dissolve the thing it verifies.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from pirx.registry import CapabilityEntry, Registry

TEST_ACTION = "test.noop"


@pytest.fixture
def test_registry() -> Registry:
    return Registry({TEST_ACTION: CapabilityEntry(TEST_ACTION, "test only")})


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
