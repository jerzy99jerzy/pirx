"""The top-level runner. One invocation, one payload, one process.

This is the **only** module permitted to catch a ``Refusal``: everywhere else,
catching one would turn a control into a warning (family practice P11). Here,
catching means recording the refusal in the ledger and exiting non-zero.

Flow, and the ledger event at each step:

    parse            -> run.started, payload.accepted / refusal.*
    propose          -> proposal.created (per item), refusal.budget
    render + present -> proposal.rendered, approval.decided
    issue            -> grant.issued
    spend            -> grant.spent / refusal.*
    execute          -> refusal.unregistered_action  (0.1.0.0: always)

In 0.1.0.0 the last step always refuses, because the registry is empty. That
is the version's demonstration, not its limitation: a human can watch the
whole loop run and end in a typed refusal with nothing written anywhere.

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
from . import consumer, ledger, proposal, proposer
from .errors import Refusal
from .grant import GrantIssuer
from .registry import PRODUCTION_REGISTRY, Registry
from .types import MAX_PROPOSALS_PER_RUN


def run(
    payload_path: Path,
    ledger_path: Path,
    out: TextIO,
    read_line: Callable[[], str],
    registry: Registry = PRODUCTION_REGISTRY,
    clock: Callable[[], float] = time.monotonic,
) -> int:
    book = ledger.Ledger(ledger_path)
    book.append(
        "run.started",
        payload=str(payload_path),
        registered_actions=list(registry.actions()),
        budget=MAX_PROPOSALS_PER_RUN,
    )

    try:
        bundle = consumer.parse(payload_path.read_bytes())
    except Refusal as exc:
        book.append(exc.event, **exc.details, message=exc.message)
        out.write(f"refused: {exc.message}\n")
        return 2

    book.append(
        "payload.accepted",
        verdicts=len(bundle.verdicts),
        review_lane=len(bundle.review_lane),
        notices=len(bundle.notices),
    )
    for cve in bundle.collisions:
        book.append("review_lane.collision", cve_id=cve)
    for cve in bundle.truncated:
        book.append("prose.truncated", cve_id=cve)

    proposals = proposer.propose(bundle)
    if proposals.over_budget:
        book.append(
            "refusal.budget",
            budget=proposals.budget,
            excluded=list(proposals.excluded),
            message="proposal budget exhausted; excluded ids listed",
        )
        out.write(
            f"budget {proposals.budget} exhausted; "
            f"{len(proposals.excluded)} verdict(s) not proposed\n"
        )

    issuer = GrantIssuer(clock=clock)
    exit_code = 0

    for item in proposals.proposals:
        rendered = proposal.prepare(item)
        created_at = clock()
        book.append(
            "proposal.created",
            action=item.action, target=item.target, verdict=item.verdict,
        )
        book.append(
            "proposal.rendered",
            action_hash=rendered.action_hash, byte_length=len(rendered.canonical_bytes),
        )

        decision = approval.decide(
            rendered, age_seconds=clock() - created_at, out=out, read_line=read_line
        )
        book.append(
            "approval.decided",
            approved=decision.approved,
            action_hash=decision.action_hash,
            approver_claim=decision.approver_claim,
            authenticated=decision.authenticated,
        )
        if not decision.approved:
            out.write("declined; nothing was authorised\n")
            continue

        grant = issuer.issue(decision, rendered)
        book.append(
            "grant.issued",
            nonce=grant.nonce, action_hash=grant.action_hash,
            target=grant.target, ttl_seconds=round(grant.deadline - grant.issued_at, 3),
        )

        try:
            spent = issuer.spend(grant, rendered.action_hash, item.target)
            book.append("grant.spent", nonce=spent.grant.nonce)
            registry.require(item.action)
        except Refusal as exc:
            book.append(exc.event, **exc.details, message=exc.message)
            out.write(f"refused: {exc.message}\n")
            exit_code = 3
            continue

        # Unreachable in 0.1.0.0: the registry is empty, so require() above
        # always refuses. Left explicit rather than omitted so the shape of
        # 0.3.0.0 is visible in review.
        book.append("capability.absent", action=item.action)

    book.append("run.finished", exit_code=exit_code)
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
