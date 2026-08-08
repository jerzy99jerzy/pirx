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


def test_every_append_is_fsynced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The durability claim is measured, not asserted: at-most-once leans on
    `capability.attempt` being on disk before the adapter runs, so the fsync
    is load-bearing, not hygiene (F24)."""
    synced: list[int] = []
    monkeypatch.setattr(ledger.os, "fsync", synced.append)
    book = ledger.Ledger(tmp_path / "l.jsonl")
    book.append("test.event", index=0)
    book.append("test.event", index=1)
    assert len(synced) == 2


def test_reopening_continues_the_chain(tmp_path: Path) -> None:
    path = tmp_path / "l.jsonl"
    seeded(path, 2)
    ledger.Ledger(path).append("test.event", index=99)
    assert ledger.verify(path) == 3


# --- pirx.ledger/2 and the retained /1 reader --------------------------------


def test_verify_reports_which_format_it_read(tmp_path) -> None:
    from pirx.ledger import Ledger, verify_chain

    book = tmp_path / "ledger.jsonl"
    ledger = Ledger(book)
    ledger.append("run.started", payload="x")
    ledger.append("run.finished", exit_code=0)
    verified = verify_chain(book)
    assert verified.schema == "pirx.ledger/2"
    assert verified.records == 2


def test_a_v1_ledger_stays_verifiable(tmp_path) -> None:
    """`/1` is retired as a *writer*, not as a *reader*. A hash chain nobody
    can still check is not an audit trail, so the verifier keeps both
    genesis sentinels and says which one it matched (P8)."""
    import hashlib
    import json

    from pirx.ledger import _canonical, verify_chain
    from pirx.types import LEDGER_GENESIS_SENTINEL_V1

    prev = hashlib.sha256(LEDGER_GENESIS_SENTINEL_V1).hexdigest()
    book = tmp_path / "old.jsonl"
    lines = []
    for seq in range(3):
        record = {
            "seq": seq,
            "ts": "2026-01-01T00:00:00+00:00",
            "prev_hash": prev,
            "event": "grant.issued",
            "payload": {"verdict": "cve-digest.verdict/1#CVE-2026-1001"},
        }
        line = _canonical(record)
        lines.append(line.decode("utf-8"))
        prev = hashlib.sha256(line).hexdigest()
    book.write_text("\n".join(lines) + "\n")

    verified = verify_chain(book)
    assert verified.schema == "pirx.ledger/1"
    assert verified.records == 3
    # And the old field name is still readable, which is the whole point.
    first = json.loads(book.read_text().splitlines()[0])
    assert "verdict" in first["payload"]


def test_a_chain_with_an_unknown_genesis_is_refused(tmp_path) -> None:
    from pirx.errors import LedgerChainRefusal
    from pirx.ledger import _canonical, verify_chain

    book = tmp_path / "alien.jsonl"
    record = {
        "seq": 0, "ts": "2026-01-01T00:00:00+00:00", "prev_hash": "f" * 64,
        "event": "run.started", "payload": {},
    }
    book.write_bytes(_canonical(record) + b"\n")
    with pytest.raises(LedgerChainRefusal, match="genesis"):
        verify_chain(book)
