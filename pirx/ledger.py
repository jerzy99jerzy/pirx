"""Append-only, hash-chained JSONL event sink, plus its verifier.

Each record carries the hash of the previous record. The genesis record chains
a documented sentinel (``LEDGER_GENESIS_SENTINEL``), so a verifier can tell a
fresh ledger from one whose head was replaced (PT9). The verifier ships in
this module because a chain nobody checks is a field, not a control.

**Two formats, from 0.7.0.0.** `pirx.ledger/1` events name a `verdict`;
`/2` events name a `justification`, because a gated MCP call has no verdict
and a field that lies to an auditor is worse than one that changes (review
finding F43). The id is not repurposed: `/2` chains a different genesis
sentinel, and ``verify`` reads both and reports which it read. A `/1` ledger
stays verifiable for as long as it exists - a hash chain nobody can still
check is not an audit trail, and retiring the *writer* is not the same act as
retiring the *reader* (P8).

Intent events are written **before** the action they guard as well as after,
so an action with no preceding event is itself evidence. Every append is
flushed and fsynced before returning: the at-most-once story leans on
``capability.attempt`` being durable *before* the adapter is called, and a
record sitting in a page cache when the host dies is a record that never
happened (F24). The cost is a few syscalls per event on a pipeline whose
bottleneck is a human reading a terminal.

Does NOT:
  - rotate, compress, encrypt, or ship anywhere. Local file. Tail truncation
    is the residual risk a remote append-only sink buys later; it is named in
    the threat model rather than papered over here.
  - serialise writers across hosts, or fall back to an unlocked append when
    locking is unavailable. `flock` is POSIX and advisory: it orders the
    writers this project ships, on one filesystem, and nothing else. The
    `fcntl` import is deliberately hard rather than guarded - a silent
    no-op lock on a platform without it would be a warning that lets
    execution continue, which is the thing P11 exists to refuse. Windows
    support is a named deferral, and this is one more thing it owes.
  - carry payload prose. Verdict text may describe unpatched estate and this
    file is SIEM-bound, so records hold ids, counts, and reasons only
    (ARCHITECTURE A8).
  - get read by the pipeline. Events flow one way; no module makes a decision
    by reading history back.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any

from .errors import LedgerChainRefusal
from .types import LEDGER_GENESIS_SENTINEL, LEDGER_GENESIS_SENTINEL_V1, LEDGER_SCHEMA


def _canonical(record: dict[str, Any]) -> bytes:
    """One serialisation, used for both the file line and the chain hash."""
    return json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


GENESIS_HASH = _digest(LEDGER_GENESIS_SENTINEL)
GENESIS_HASH_V1 = _digest(LEDGER_GENESIS_SENTINEL_V1)

#: Which sentinel a chain starts from, by the format that wrote it. Read in
#: this order so a `/2` ledger is never mistaken for a broken `/1` one.
GENESIS_BY_SCHEMA: dict[str, str] = {
    "pirx.ledger/2": GENESIS_HASH,
    "pirx.ledger/1": GENESIS_HASH_V1,
}


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
    """Append-only sink over a single JSONL file.

    **Two writers, from 0.7.3.0.** Through 0.7.2.2 an instance cached the
    sequence number and head hash at construction and trusted them for the
    rest of its life. That was true while one process owned the file and
    false the moment the gate topology shipped: `pirx-gate` is long-lived and
    holds `<gate-dir>/ledger.jsonl` open across a whole session, while
    `pirx gate-approve` opens *the same default path* for each queue walk.
    Records written by the approver landed between records the pump had
    already chained past, so the next pump append reused a sequence number
    and chained a superseded head - and `pirx verify` refused a ledger
    produced by the manual's own documented procedure (review finding F59).

    The fix is the dullest one that is correct, in the shape `spendstore.py`
    already uses: the kernel arbitrates. Every append takes an exclusive
    `flock` on the file, re-reads the real tail inside the lock if the file
    grew since this instance last looked, chains from what is actually on
    disk, and releases. The cached head survives only as an optimisation
    guarded by a length check, so the common case stays O(1) and the
    contended case stays correct.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._seq, self._head = self._scan_tail()
        self._size = self.path.stat().st_size if self.path.exists() else 0

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

    def _refresh_if_grown(self, handle: IO[bytes]) -> None:
        """Re-read the tail when another writer has extended the file.

        The length check is an *append* detector, deliberately, and not an
        integrity check: an in-place edit that preserves the byte count is
        invisible here and is `verify_chain`'s job, not the writer's. A
        writer that tried to police the file it is appending to would be a
        second verifier with a weaker view than the real one.
        """
        size = os.fstat(handle.fileno()).st_size
        if size == self._size:
            return
        self._seq, self._head = self._scan_tail()
        self._size = size

    def append(self, event: str, **payload: Any) -> LedgerRecord:
        with self.path.open("ab") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                self._refresh_if_grown(handle)
                record = LedgerRecord(
                    seq=self._seq,
                    ts=datetime.now(UTC).isoformat(),
                    prev_hash=self._head,
                    event=event,
                    payload=payload,
                )
                line = _canonical(record.as_dict())
                handle.write(line + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
                self._seq += 1
                self._head = _digest(line)
                self._size = os.fstat(handle.fileno()).st_size
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        return record


@dataclass(frozen=True, slots=True)
class VerifiedChain:
    """What ``verify`` established, including which format it read."""

    schema: str
    records: int


def _genesis_for(first_prev: str) -> str:
    """Identify the chain's format from its first link.

    A ledger does not carry a format marker in every record - it carries one
    genesis, and the first `prev_hash` names it. Trying both and reporting
    which matched is honest; guessing from a filename would not be.
    """
    for schema, digest in GENESIS_BY_SCHEMA.items():
        if first_prev == digest:
            return schema
    raise LedgerChainRefusal(
        "ledger head chains no known genesis sentinel",
        found_prev=first_prev,
        known=sorted(GENESIS_BY_SCHEMA),
    )


def verify_chain(path: Path) -> VerifiedChain:
    """Walk the chain. Returns what was verified, or raises at the first seam.

    Detects edits and interior gaps. Does NOT detect truncation of the tail:
    a chain with its last N records removed is internally consistent, which is
    exactly what a remote sink buys and this file does not.
    """
    if not path.exists():
        return VerifiedChain(schema=LEDGER_SCHEMA, records=0)
    count = 0
    prev: str | None = None
    schema = LEDGER_SCHEMA
    with path.open("r", encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            record = json.loads(line)
            if prev is None:
                schema = _genesis_for(record["prev_hash"])
                prev = GENESIS_BY_SCHEMA[schema]
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
    return VerifiedChain(schema=schema, records=count)


def verify(path: Path) -> int:
    """Record count only. Kept because callers that only want the count
    should not have to learn a type to get one."""
    return verify_chain(path).records
