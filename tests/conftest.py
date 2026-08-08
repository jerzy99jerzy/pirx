"""Shared fixtures and builders."""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from typing import Any

import pytest

#: Environment variables that change what the code under test does. The suite
#: strips them from every test, automatically, because a suite that passes
#: only in a clean shell is a suite that reports the shell rather than the
#: code - and the operator most likely to run it is the one with
#: `PIRX_GRANT_KEY_FILE` exported, because they are running a gate.
#:
#: This is not tidiness. A leaked key path made four unrelated attacks fail
#: with `FileNotFoundError`, which is a false red; the same leak pointing at a
#: *readable* key would have made `pirx run` silently use the gate's key in
#: tests that assume an ephemeral one, which is a false green (0.7.1.0).
PIRX_ENV_VARS = (
    "PIRX_GRANT_KEY_FILE",
    "PIRX_JIRA_BASE_URL",
    "PIRX_JIRA_EMAIL",
    "PIRX_JIRA_TOKEN",
    "PIRX_ANTHROPIC_API_KEY",
)


@pytest.fixture(autouse=True)
def _isolated_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[None]:
    """Strip Pirx's environment from every test. Autouse, no opt-out.

    A test that genuinely needs one of these sets it itself with monkeypatch,
    which makes the dependency visible in the test that has it.
    """
    for name in PIRX_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    yield


def test_the_environment_is_stripped() -> None:
    """The isolation fixture is itself measured. A fixture nobody checks is a
    fixture that silently stops applying after a refactor."""
    for name in PIRX_ENV_VARS:
        assert name not in os.environ, f"{name} leaked into the suite"

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


def justification(cve: str = "CVE-2026-1001"):
    """A verdict justification with no evidence object, for tests that build
    a proposal from an id rather than from a parsed verdict."""
    from pirx.justification import verdict_justification
    from pirx.types import VerdictId

    return verdict_justification(VerdictId(f"cve-digest.verdict/1#{cve}"))


def grant_issuer(clock, tmp_path, ttl: float | None = None):
    """An issuer with a test key and a real durable spend store.

    The store is real rather than faked: single-use is the property under
    test in half the suite, and a fake set would test the fake.
    """
    from pirx.grant import GrantIssuer
    from pirx.spendstore import SpendStore
    from pirx.types import GRANT_TTL_SECONDS

    return GrantIssuer(
        clock=clock,
        key=b"k" * 32,
        store=SpendStore(tmp_path / "spent"),
        ttl_seconds=GRANT_TTL_SECONDS if ttl is None else ttl,
    )
