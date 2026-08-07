"""One run's recording discipline, shared by the runner and the harness.

Every pipeline step goes through here so that *the same code* records events
whether the caller is `cli.run` or an attack case. The harness then asserts
on the ledger the product wrote, not on a ledger the test wrote - which is
the difference between testing the control and testing the test
(ARCHITECTURE A9).

**On catching refusals.** This module catches a `Refusal`, records it, and
**re-raises it unchanged**. That is recording, not suppression: control flow
still terminates at the caller. The scrape enforces the distinction - any
`except Refusal` handler outside the top-level runner must end in a bare
`raise`, and a handler that swallows is a build failure (P11).

Does NOT:
  - decide anything. It records what other modules decided.
  - read the ledger back. Events flow one way.
  - own the clock or the registry; both are injected, so an attack case can
    advance time or supply a test registry without monkeypatching internals.
"""

from __future__ import annotations

from collections.abc import Callable

from .consumer import VerdictBundle, parse
from .errors import Refusal
from .grant import ApprovalDecision, Grant, GrantIssuer, SpentGrant
from .ledger import Ledger
from .proposal import Proposal, RenderedProposal, prepare
from .proposer import ProposalSet, propose
from .registry import Registry
from .types import MAX_PROPOSALS_PER_RUN, ActionHash, TargetId


class Session:
    """Wires the pipeline to one ledger, one clock, one registry."""

    def __init__(
        self,
        ledger: Ledger,
        clock: Callable[[], float],
        registry: Registry,
    ) -> None:
        self.ledger = ledger
        self.clock = clock
        self.registry = registry
        self.issuer = GrantIssuer(clock=clock)

    def _record_refusal(self, exc: Refusal) -> None:
        self.ledger.append(exc.event, **exc.details, message=exc.message)

    def started(self, payload_name: str) -> None:
        self.ledger.append(
            "run.started",
            payload=payload_name,
            registered_actions=list(self.registry.actions()),
            budget=MAX_PROPOSALS_PER_RUN,
        )

    def consume(self, payload: bytes, name: str = "<bytes>") -> VerdictBundle:
        try:
            bundle = parse(payload)
        except Refusal as exc:
            self._record_refusal(exc)
            raise
        self.ledger.append(
            "payload.accepted",
            verdicts=len(bundle.verdicts),
            review_lane=len(bundle.review_lane),
            notices=len(bundle.notices),
        )
        for cve in bundle.collisions:
            self.ledger.append("review_lane.collision", cve_id=cve)
        for cve in bundle.truncated:
            self.ledger.append("prose.truncated", cve_id=cve)
        return bundle

    def propose(
        self, bundle: VerdictBundle, budget: int = MAX_PROPOSALS_PER_RUN
    ) -> ProposalSet:
        result = propose(bundle, budget=budget)
        for item in result.proposals:
            self.ledger.append(
                "proposal.created",
                action=item.action, target=item.target, verdict=item.verdict,
            )
        if result.over_budget:
            self.ledger.append(
                "refusal.budget",
                budget=result.budget,
                excluded=list(result.excluded),
                message="proposal budget exhausted; excluded ids listed",
            )
        return result

    def render(self, item: Proposal) -> RenderedProposal:
        rendered = prepare(item)
        self.ledger.append(
            "proposal.rendered",
            action_hash=rendered.action_hash,
            byte_length=len(rendered.canonical_bytes),
        )
        return rendered

    def decided(self, decision: ApprovalDecision) -> None:
        self.ledger.append(
            "approval.decided",
            approved=decision.approved,
            action_hash=decision.action_hash,
            approver_claim=decision.approver_claim,
            authenticated=decision.authenticated,
        )

    def issue(
        self, decision: ApprovalDecision, rendered: RenderedProposal
    ) -> Grant:
        try:
            grant = self.issuer.issue(decision, rendered)
        except Refusal as exc:
            self._record_refusal(exc)
            raise
        self.ledger.append(
            "grant.issued",
            nonce=grant.nonce, action_hash=grant.action_hash,
            target=grant.target,
            ttl_seconds=round(grant.deadline - grant.issued_at, 3),
        )
        return grant

    def spend(
        self, grant: Grant, action_hash: ActionHash, target: TargetId
    ) -> SpentGrant:
        try:
            spent = self.issuer.spend(grant, action_hash, target)
        except Refusal as exc:
            self._record_refusal(exc)
            raise
        self.ledger.append("grant.spent", nonce=spent.grant.nonce)
        return spent

    def execute(self, spent: SpentGrant, action: str) -> None:
        """0.1.0.0-0.2.0.0: always refuses, because the registry is empty."""
        try:
            self.registry.require(action)
        except Refusal as exc:
            self._record_refusal(exc)
            raise
        self.ledger.append("capability.absent", action=action)

    def finished(self, exit_code: int) -> None:
        self.ledger.append("run.finished", exit_code=exit_code)
