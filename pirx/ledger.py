"""Append-only, hash-chained JSONL event sink, plus its verifier.

Each record carries the hash of the previous record. The genesis record chains
a documented sentinel (``LEDGER_GENESIS_SENTINEL``), so a verifier can tell a
fresh ledger from one whose head was replaced (PT9). The verifier ships in
this module because a chain nobody checks is a field, not a control.

Intent events are written **before** the action they guard as well as after,
so an action with no preceding event is itself evidence.

Does NOT:
  - rotate, compress, encrypt, or ship anywhere. Local file. Tail truncation
    is the residual risk a remote append-only sink buys later; it is named in
    the threat model rather than papered over here.
  - carry payload prose. Verdict text may describe unpatched estate and this
    file is SIEM-bound, so records hold ids, counts, and reasons only
    (ARCHITECTURE A8).
  - get read by the pipeline. Events flow one way; no module makes a decision
    by reading history back.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .errors import LedgerChainRefusal
from .types import LEDGER_GENESIS_SENTINEL


def _canonical(record: dict[str, Any]) -> bytes:
    """One serialisation, used for both the file line and the chain hash."""
    return json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


GENESIS_HASH = _digest(LEDGER_GENESIS_SENTINEL)


@dataclass(frozen=True, slots=True)
class LedgerRecord:
    seq: int
    ts: str
    prev_hash: str
    event: str
    payload: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "ts": self.ts,
            "prev_hash": self.prev_hash,
            "event": self.event,
            "payload": self.payload,
        }


class Ledger:
    """Append-only sink over a single JSONL file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._seq, self._head = self._scan_tail()

    def _scan_tail(self) -> tuple[int, str]:
        if not self.path.exists():
            return 0, GENESIS_HASH
        last: dict[str, Any] | None = None
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    last = json.loads(line)
        if last is None:
            return 0, GENESIS_HASH
        return int(last["seq"]) + 1, _digest(_canonical(last))

    def append(self, event: str, **payload: Any) -> LedgerRecord:
        record = LedgerRecord(
            seq=self._seq,
            ts=datetime.now(UTC).isoformat(),
            prev_hash=self._head,
            event=event,
            payload=payload,
        )
        line = _canonical(record.as_dict())
        with self.path.open("ab") as handle:
            handle.write(line + b"\n")
        self._seq += 1
        self._head = _digest(line)
        return record


def verify(path: Path) -> int:
    """Walk the chain. Returns the record count, or raises at the first seam.

    Detects edits and interior gaps. Does NOT detect truncation of the tail:
    a chain with its last N records removed is internally consistent, which is
    exactly what a remote sink buys and this file does not.
    """
    prev = GENESIS_HASH
    count = 0
    if not path.exists():
        return 0
    with path.open("r", encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            record = json.loads(line)
            if record["prev_hash"] != prev:
                raise LedgerChainRefusal(
                    "ledger chain seam",
                    line=lineno,
                    seq=record.get("seq"),
                    expected_prev=prev,
                    found_prev=record["prev_hash"],
                )
            if record["seq"] != count:
                raise LedgerChainRefusal(
                    "ledger sequence gap", line=lineno, expected_seq=count,
                    found_seq=record["seq"],
                )
            prev = _digest(_canonical(record))
            count += 1
    return count
