"""Reconciliation: answer "did it land" for attempts with no recorded result.

A crash between `capability.attempt` and `capability.result` leaves the
ledger honestly ambiguous. This module finds those gaps and asks the target
system, using the idempotency key that the attempt event recorded and the
adapter embedded in the comment body.

**It never re-executes.** Re-running a write would require authority, the
grant is spent, and that is the design rather than a limitation: an automatic
retry that carries authority across a crash is PT8 wearing a helpful face.
Reconciliation reports; a human decides whether to approve a fresh action.

Does NOT:
  - repair the ledger. It appends `capability.outcome_unknown` or
    `capability.outcome_reconciled`; it never edits a prior record, which
    would break the chain and is exactly what PT9 watches for.
  - guess. If the adapter cannot answer, the outcome stays unknown and says
    so.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .adapters.jira import AdapterError
from .adapters.protocol import TicketAdapter
from .ledger import Ledger
from .types import TargetId


@dataclass(frozen=True, slots=True)
class OpenAttempt:
    seq: int
    action: str
    target: TargetId
    idempotency_key: str


def open_attempts(ledger_path: Path) -> tuple[OpenAttempt, ...]:
    """Attempts with no matching result, keyed by idempotency key."""
    if not ledger_path.exists():
        return ()
    attempts: dict[str, OpenAttempt] = {}
    settled: set[str] = set()
    for line in ledger_path.read_text().splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        payload = record.get("payload", {})
        key = payload.get("idempotency_key")
        if key is None:
            continue
        if record["event"] == "capability.attempt":
            attempts[key] = OpenAttempt(
                seq=int(record["seq"]),
                action=str(payload.get("action", "")),
                target=TargetId(str(payload.get("target", ""))),
                idempotency_key=str(key),
            )
        elif record["event"] in (
            "capability.result",
            "capability.outcome_reconciled",
            "capability.outcome_unknown",
        ):
            settled.add(str(key))
    return tuple(a for k, a in sorted(attempts.items()) if k not in settled)


def reconcile(ledger_path: Path, adapter: TicketAdapter) -> tuple[str, ...]:
    """Ask the target system about each open attempt. Report, never retry."""
    book = Ledger(ledger_path)
    lines: list[str] = []
    for attempt in open_attempts(ledger_path):
        try:
            found = adapter.find_comment(attempt.target, attempt.idempotency_key)
        except AdapterError as exc:
            book.append(
                "capability.outcome_unknown",
                idempotency_key=attempt.idempotency_key,
                target=attempt.target,
                attempt_seq=attempt.seq,
                reason=exc.message,
            )
            lines.append(f"{attempt.target}: unknown ({exc.message})")
            continue
        if found is None:
            book.append(
                "capability.outcome_unknown",
                idempotency_key=attempt.idempotency_key,
                target=attempt.target,
                attempt_seq=attempt.seq,
                reason="no comment carrying this key exists",
            )
            lines.append(
                f"{attempt.target}: did NOT land; a fresh grant is required "
                "to try again"
            )
        else:
            book.append(
                "capability.outcome_reconciled",
                idempotency_key=attempt.idempotency_key,
                target=attempt.target,
                attempt_seq=attempt.seq,
                comment_id=found.comment_id,
            )
            lines.append(f"{attempt.target}: landed as comment {found.comment_id}")
    return tuple(lines)
