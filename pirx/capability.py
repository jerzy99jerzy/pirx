"""The write. Execution semantics, stated rather than implied.

**At-most-once.** The grant is spent before execution begins, so a crash
between spend and result cannot leave reusable authority. The cost is stated
plainly: an action may silently not happen, and the human must issue a fresh
grant to try again. This is the correct trade for an agent whose thesis is
that authority is scarce; the opposite choice (execute, then spend) buys
at-least-once delivery by making replay possible, which is PT3.

**The ledger records intent before outcome.** `capability.attempt` is written
with the idempotency key *before* the adapter is called; `capability.result`
follows. An attempt with no result is therefore detectable, and
`reconcile.py` turns it into an `outcome_unknown` event on the next run. An
action with no preceding attempt is evidence of tampering (PT9).

**No refund.** A failed execution consumed real authority and left real
evidence. Re-issuing is a human decision made with the ledger in hand, never
an automatic retry (ARCHITECTURE A12).

Does NOT:
  - construct its own authority. The signature takes a `SpentGrant`, whose
    only constructor is the spend function, so "execute without spending" is
    rejected by the type checker rather than caught by a test.
  - choose the adapter. Wiring happens in the runner, where it is visible.
  - read the target system for state. It appends and records.
"""

from __future__ import annotations

from dataclasses import dataclass

from .adapters.jira import AdapterError
from .adapters.protocol import CommentRef, TicketAdapter
from .grant import SpentGrant
from .proposal import RenderedProposal
from .types import ActionHash, TargetId


@dataclass(frozen=True, slots=True)
class ExecutionOutcome:
    action: str
    target: TargetId
    idempotency_key: str
    reference: CommentRef | None
    succeeded: bool
    detail: str


def idempotency_key(action_hash: ActionHash) -> str:
    """Derived from the approved bytes, so a retry of the *same* approved
    action carries the same key and a different action never collides."""
    return action_hash


def comment_body(rendered: RenderedProposal) -> str:
    """What lands in the ticket.

    The canonical proposal bytes are included verbatim. The human approved
    exactly these bytes; posting a prettier summary would make the ticket
    record disagree with the ledger record, and the ledger would be the one
    nobody reads (P10).
    """
    return (
        "Pirx remediation proposal, approved and executed under a "
        "single-use grant.\n\n"
        + rendered.canonical_bytes.decode("utf-8")
    )


def execute_ticket_comment(
    spent: SpentGrant,
    rendered: RenderedProposal,
    adapter: TicketAdapter,
) -> ExecutionOutcome:
    """Perform the one registered capability. Caller records the events."""
    key = idempotency_key(spent.grant.action_hash)
    try:
        reference = adapter.comment(
            spent.grant.target, comment_body(rendered), key
        )
    except AdapterError as exc:
        return ExecutionOutcome(
            action="ticket.comment",
            target=spent.grant.target,
            idempotency_key=key,
            reference=None,
            succeeded=False,
            detail=exc.message,
        )
    return ExecutionOutcome(
        action="ticket.comment",
        target=spent.grant.target,
        idempotency_key=key,
        reference=reference,
        succeeded=True,
        detail=f"comment {reference.comment_id}",
    )
