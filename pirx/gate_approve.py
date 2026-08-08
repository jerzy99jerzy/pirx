"""The approval surface for gated calls: a terminal, deliberately elsewhere.

The gate cannot host its own approval prompt. Its stdin and stdout are the
JSON-RPC pipes to the agent host, and an approval delivered through the
protocol would render inside the trust domain of the party under review
(PT17). So the human sits at a second process, on a terminal the gate does
not own, reading pending proposals from a directory and writing grants to
another.

The shape is the same trust loop the runner has had since 0.1.0.0 - present
the canonical bytes, challenge the reader, take one answer, issue one grant -
with the transport being two directories instead of two function calls.

Does NOT:
  - talk to the gate. It reads files the gate wrote and writes files the gate
    reads. No socket, no signal, no shared lock: the gate polls its own
    directory on the next retry, which is the whole reason the MRTR ticket
    exists.
  - approve in bulk. One pending proposal, one prompt, one decision, and the
    loop ends after the queue is walked once (PT12).
  - delete a pending file after approval. The gate's grant lookup is keyed on
    the action hash, and a pending file left behind is an audit record; the
    operator prunes, per the same reasoning that keeps the spend store from
    expiring anything on its own.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import TextIO

from . import approve as approval
from .errors import Refusal
from .grant import GrantIssuer
from .justification import Justification
from .ledger import Ledger
from .proposal import Proposal, RenderedProposal, prepare
from .types import ActionHash, JustificationRef


def _rendered_from_pending(raw: bytes) -> tuple[str, bytes, str]:
    """Read one pending file: ticket, canonical bytes, action hash.

    The canonical bytes are read as bytes and shown as bytes. Nothing here
    re-renders a proposal from parts - a second rendering path is exactly the
    divergence between shown and hashed that P10 exists to prevent.
    """
    record = json.loads(raw)
    return (
        str(record["ticket"]),
        str(record["canonical"]).encode("utf-8"),
        str(record["action_hash"]),
    )


def approve_pending(
    pending_dir: Path,
    grants_dir: Path,
    ledger: Ledger,
    issuer: GrantIssuer,
    out: TextIO,
    read_line: Callable[[], str],
    clock: Callable[[], float] = time.monotonic,
) -> int:
    """Walk the pending queue once. Returns the number of grants issued."""
    grants_dir.mkdir(parents=True, exist_ok=True)
    issued = 0
    for path in sorted(pending_dir.glob("*.json")):
        ticket, canonical, action_hash = _rendered_from_pending(path.read_bytes())
        if (grants_dir / f"{action_hash}.json").exists():
            continue

        rendered = _reconstruct(canonical, action_hash)
        ledger.append("gate.presented", ticket=ticket, action_hash=action_hash)

        def record_challenge(field: str, hash_: str = action_hash) -> None:
            ledger.append(
                "attention.challenge_issued", action_hash=hash_, field=field
            )
        try:
            decision = approval.decide(
                rendered, age_seconds=0.0, out=out, read_line=read_line,
                clock=clock,
                on_challenge=record_challenge,
            )
        except Refusal as exc:
            ledger.append(exc.event, **exc.details, message=exc.message)
            out.write(f"refused: {exc.message}\n")
            continue

        ledger.append(
            "approval.decided",
            approved=decision.approved, action_hash=decision.action_hash,
            approver_claim=decision.approver_claim,
            authenticated=decision.authenticated,
            challenge_field=decision.attention.challenge_field,
            elapsed_seconds=round(decision.attention.elapsed_seconds, 3),
        )
        if not decision.approved:
            out.write("declined; nothing was authorised\n")
            continue

        try:
            grant = issuer.issue(decision, rendered)
        except Refusal as exc:
            ledger.append(exc.event, **exc.details, message=exc.message)
            out.write(f"refused: {exc.message}\n")
            continue

        (grants_dir / f"{action_hash}.json").write_bytes(grant.to_json())
        ledger.append(
            "grant.issued",
            nonce=str(grant.nonce), action_hash=str(grant.action_hash),
            target=str(grant.target), justification=str(grant.justification),
            ttl_seconds=round(grant.deadline - grant.issued_at, 3),
        )
        out.write(f"granted: {ticket}\n")
        issued += 1
    return issued


def _reconstruct(canonical: bytes, action_hash: str) -> RenderedProposal:
    """Wrap already-canonical bytes for the approval surface.

    The surface needs a `RenderedProposal` for the attention challenge, and
    the challenge reads deterministic fields off the proposal. Those fields
    are parsed back **out of the canonical bytes themselves**, so what the
    challenge asks about and what the human is shown are the same artefact by
    construction. The hash is then recomputed and compared to the one the
    gate recorded: a pending file edited between writing and reading fails
    here rather than being approved.
    """
    fields: dict[str, str] = {}
    for line in canonical.decode("utf-8").splitlines():
        if line.startswith("~~~") or line.startswith("  "):
            continue
        key, _, value = line.partition(": ")
        if key and value:
            fields[key] = value

    justification = Justification(
        schema=fields.get("justification.schema", ""),
        ref=JustificationRef(fields.get("justification.ref", "")),
        digest=fields.get("justification.digest", ""),
    )
    proposal = Proposal(
        action=fields.get("action", ""),
        target=fields.get("target", ""),  # type: ignore[arg-type]
        justification=justification,
        params={},
    )
    rebuilt = prepare(proposal)
    return RenderedProposal(
        proposal=rebuilt.proposal,
        canonical_bytes=canonical,
        action_hash=_checked(canonical, action_hash),
    )


def _checked(canonical: bytes, recorded: str) -> ActionHash:
    from .proposal import action_hash as compute

    computed = compute(canonical)
    if computed != recorded:
        raise ValueError(
            "pending proposal does not hash to the value the gate recorded"
        )
    return computed
