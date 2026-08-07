"""Ledger tests (PT9): the chain detects edits and interior gaps, and says
plainly what it does not detect."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pirx import ledger
from pirx.errors import LedgerChainRefusal


def seeded(path: Path, n: int = 5) -> ledger.Ledger:
    book = ledger.Ledger(path)
    for i in range(n):
        book.append("test.event", index=i)
    return book


def test_genesis_chains_the_documented_sentinel(tmp_path: Path) -> None:
    path = tmp_path / "l.jsonl"
    ledger.Ledger(path).append("run.started")
    first = json.loads(path.read_text().splitlines()[0])
    assert first["prev_hash"] == ledger.GENESIS_HASH
    assert first["seq"] == 0


def test_a_fresh_ledger_verifies_empty(tmp_path: Path) -> None:
    assert ledger.verify(tmp_path / "absent.jsonl") == 0


def test_intact_chain_verifies(tmp_path: Path) -> None:
    path = tmp_path / "l.jsonl"
    seeded(path, 5)
    assert ledger.verify(path) == 5


def test_editing_a_middle_record_breaks_the_chain(tmp_path: Path) -> None:
    path = tmp_path / "l.jsonl"
    seeded(path, 5)
    lines = path.read_text().splitlines()
    record = json.loads(lines[2])
    record["payload"]["index"] = 999
    lines[2] = json.dumps(record, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")
    with pytest.raises(LedgerChainRefusal) as caught:
        ledger.verify(path)
    assert caught.value.details["line"] == 4


def test_removing_an_interior_record_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "l.jsonl"
    seeded(path, 5)
    lines = path.read_text().splitlines()
    del lines[2]
    path.write_text("\n".join(lines) + "\n")
    with pytest.raises(LedgerChainRefusal):
        ledger.verify(path)


def test_replacing_the_head_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "l.jsonl"
    seeded(path, 3)
    lines = path.read_text().splitlines()
    first = json.loads(lines[0])
    first["prev_hash"] = "0" * 64
    lines[0] = json.dumps(first, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")
    with pytest.raises(LedgerChainRefusal):
        ledger.verify(path)


def test_tail_truncation_is_NOT_detected(tmp_path: Path) -> None:
    """Measured limitation, asserted so nobody claims otherwise.

    A chain with its last records removed is internally consistent. This is
    exactly what a remote append-only sink buys and this local file does not,
    and it is why the threat model names it rather than implying coverage.
    """
    path = tmp_path / "l.jsonl"
    seeded(path, 5)
    lines = path.read_text().splitlines()[:3]
    path.write_text("\n".join(lines) + "\n")
    assert ledger.verify(path) == 3


def test_reopening_continues_the_chain(tmp_path: Path) -> None:
    path = tmp_path / "l.jsonl"
    seeded(path, 2)
    ledger.Ledger(path).append("test.event", index=99)
    assert ledger.verify(path) == 3
