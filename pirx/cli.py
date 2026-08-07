"""The top-level runner. One invocation, one payload, one process.

Recording lives in `session.py`; this module owns argument handling, the
human-facing output, and the exit status. It is the **only** module that
catches a `Refusal` without re-raising it - everywhere else, a caught refusal
must be re-raised, and the scrape enforces that (P11).

Flow, and the ledger event at each step:

    parse            -> run.started, payload.accepted / refusal.*
    propose          -> proposal.created (per item), refusal.budget
    render + present -> proposal.rendered, approval.decided
    issue            -> grant.issued
    spend            -> grant.spent / refusal.*
    execute          -> refusal.unregistered_action  (0.1.0.0: always)

In 0.1.0.0 and 0.2.0.0 the last step always refuses, because the registry is
empty. That is the version's demonstration, not its limitation: a human can
watch the whole loop run and end in a typed refusal with nothing written.

Does NOT:
  - retry, resume, or reconcile. Execution semantics arrive with the first
    capability at 0.3.0.0.
  - suppress a refusal. Every caught refusal is recorded and re-surfaced in
    the exit status.
"""

from __future__ import annotations

import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TextIO

from . import approve as approval
from .errors import Refusal
from .ledger import Ledger
from .registry import PRODUCTION_REGISTRY, Registry
from .session import Session


def run(
    payload_path: Path,
    ledger_path: Path,
    out: TextIO,
    read_line: Callable[[], str],
    registry: Registry = PRODUCTION_REGISTRY,
    clock: Callable[[], float] = time.monotonic,
) -> int:
    session = Session(Ledger(ledger_path), clock=clock, registry=registry)
    session.started(str(payload_path))

    try:
        bundle = session.consume(payload_path.read_bytes(), str(payload_path))
    except Refusal as exc:
        out.write(f"refused: {exc.message}\n")
        session.finished(2)
        return 2

    proposals = session.propose(bundle)
    if proposals.over_budget:
        out.write(
            f"budget {proposals.budget} exhausted; "
            f"{len(proposals.excluded)} verdict(s) not proposed\n"
        )

    exit_code = 0
    for item in proposals.proposals:
        created_at = clock()
        rendered = session.render(item)

        decision = approval.decide(
            rendered, age_seconds=clock() - created_at, out=out, read_line=read_line
        )
        session.decided(decision)
        if not decision.approved:
            out.write("declined; nothing was authorised\n")
            continue

        try:
            grant = session.issue(decision, rendered)
            spent = session.spend(grant, rendered.action_hash, item.target)
            session.execute(spent, item.action)
        except Refusal as exc:
            out.write(f"refused: {exc.message}\n")
            exit_code = 3
            continue

    session.finished(exit_code)
    return exit_code


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) not in (1, 2):
        sys.stderr.write("usage: pirx run <verdict.json> [ledger.jsonl]\n")
        return 64
    payload = Path(args[0])
    book = Path(args[1]) if len(args) == 2 else Path("pirx-ledger.jsonl")
    return run(payload, book, sys.stdout, sys.stdin.readline)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
