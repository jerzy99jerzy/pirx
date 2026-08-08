"""The grant primitive: issue, verify, spend.

A grant authorises one action, not a session. It is bound to the hash of the
rendered proposal, the target, and the justifying verdict; it expires on the
monotonic clock; it is single-use.

``SpentGrant`` is a distinct type whose only constructor is ``spend``. A
capability's signature takes ``SpentGrant``, so "execute without spending" is
not a bug a test has to catch - it is a program a type checker rejects
(ARCHITECTURE A2).

Since 0.5.0.0, issuance also verifies the decision's ``AttentionEvidence``
(PT15) and counts against a session grant budget, so a grant is unreachable
not only without an approving decision but without a *measurably attentive*
one. The surface refuses first; the issuer refuses again so that a decision
object fabricated in code cannot route around the surface (ARCHITECTURE A17).

Does NOT:
  - persist anything. The spent-set is an in-process ``set`` of nonces, and
    that is the correct mechanism for a single-process run, not a shortcut.
    When approval and execution become separate processes, an HMAC over the
    scope and a durable spend store land **together, in the same version** -
    a stateless-verifiable grant with no durable spend record is replayable
    across restarts (family practice P5, brief settled decisions 1-2).
  - expose a constructor that bypasses an approving decision. ``issue`` takes
    the decision object; there is no other path to a ``Grant``.
  - use the wall clock. Expiry is a monotonic deadline, so it cannot be moved
    by changing the system time, and a serialised grant is meaningless
    outside its process - which conveniently enforces the single-process
    topology the design assumes (ARCHITECTURE A3).
  - refund on failure. A failed execution consumed real authority; re-issuing
    is a human decision made with the ledger in hand (ARCHITECTURE A12).
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass

from .errors import (
    ChallengeFailedRefusal,
    ExpiredGrantRefusal,
    HashMismatchRefusal,
    ReadingFloorRefusal,
    SessionBudgetRefusal,
    SpentGrantRefusal,
    TargetMismatchRefusal,
)
from .proposal import RenderedProposal
from .types import (
    GRANT_TTL_SECONDS,
    MAX_GRANTS_PER_SESSION,
    ActionHash,
    GrantNonce,
    TargetId,
    VerdictId,
)

Clock = Callable[[], float]


@dataclass(frozen=True, slots=True)
class AttentionEvidence:
    """What the approval surface measured about the review itself (PT15).

    Honest limit, stated where the type lives: this evidence demonstrates
    that the approver **operated on the exact hashed bytes** - located a
    field in them and answered within a measured interval. It does not and
    cannot demonstrate comprehension, and no consumer of this type may claim
    otherwise (family practice P7).
    """

    challenge_field: str
    challenge_passed: bool
    elapsed_seconds: float
    floor_seconds: float


@dataclass(frozen=True, slots=True)
class ApprovalDecision:
    """The human's answer. Produced only by the approval surface."""

    approved: bool
    action_hash: ActionHash
    target: TargetId
    approver_claim: str
    #: Measured at the surface, verified again at issuance: a decision object
    #: fabricated around the surface still cannot buy a grant without
    #: evidence (PT15, defence in depth at the type it protects).
    attention: AttentionEvidence
    #: Always False in every planned version: Pirx does not authenticate the
    #: human, and the ledger must not let a reader mistake this for identity.
    authenticated: bool = False


@dataclass(frozen=True, slots=True)
class Grant:
    nonce: GrantNonce
    action_hash: ActionHash
    target: TargetId
    verdict: VerdictId
    issued_at: float
    deadline: float


@dataclass(frozen=True, slots=True)
class SpentGrant:
    """Proof that a grant was verified and consumed. Constructed only by
    ``GrantIssuer.spend``."""

    grant: Grant
    spent_at: float


class GrantIssuer:
    """Issues and spends grants within one process run."""

    def __init__(
        self, clock: Clock, ttl_seconds: float = GRANT_TTL_SECONDS
    ) -> None:
        self._clock = clock
        self._ttl = ttl_seconds
        self._spent: set[GrantNonce] = set()
        self._issued_count = 0

    def issue(
        self, decision: ApprovalDecision, rendered: RenderedProposal
    ) -> Grant:
        if self._issued_count >= MAX_GRANTS_PER_SESSION:
            raise SessionBudgetRefusal(
                "session grant budget exhausted; rotate the session",
                budget=MAX_GRANTS_PER_SESSION,
                issued=self._issued_count,
            )
        if not decision.approved:
            raise ValueError("cannot issue a grant from a declined decision")
        if decision.action_hash != rendered.action_hash:
            raise HashMismatchRefusal(
                "decision does not cover these bytes",
                decided=decision.action_hash, rendered=rendered.action_hash,
            )
        # PT15: the surface already refused inattentive answers; verifying
        # again here means a fabricated decision cannot route around it.
        if not decision.attention.challenge_passed:
            raise ChallengeFailedRefusal(
                "decision carries no passed attention challenge",
                action_hash=decision.action_hash,
                field=decision.attention.challenge_field,
            )
        if decision.attention.elapsed_seconds < decision.attention.floor_seconds:
            raise ReadingFloorRefusal(
                "approval arrived below the reading floor",
                action_hash=decision.action_hash,
                elapsed_seconds=round(decision.attention.elapsed_seconds, 3),
                floor_seconds=round(decision.attention.floor_seconds, 3),
            )
        now = self._clock()
        self._issued_count += 1
        return Grant(
            nonce=GrantNonce(uuid.uuid4().hex),
            action_hash=rendered.action_hash,
            target=rendered.proposal.target,
            verdict=rendered.proposal.verdict,
            issued_at=now,
            deadline=now + self._ttl,
        )

    def spend(
        self, grant: Grant, action_hash: ActionHash, target: TargetId
    ) -> SpentGrant:
        """Total verification, then mark spent **before** returning.

        Order matters: the nonce is burned before the caller can act, so a
        crash mid-action cannot leave reusable authority behind.
        """
        if grant.nonce in self._spent:
            raise SpentGrantRefusal(
                "grant already spent", nonce=grant.nonce,
                action_hash=grant.action_hash,
            )
        if grant.action_hash != action_hash:
            raise HashMismatchRefusal(
                "grant does not cover these bytes", nonce=grant.nonce,
                granted=grant.action_hash, presented=action_hash,
            )
        if grant.target != target:
            raise TargetMismatchRefusal(
                "grant is for another target", nonce=grant.nonce,
                granted=grant.target, presented=target,
            )
        now = self._clock()
        if now > grant.deadline:
            raise ExpiredGrantRefusal(
                "grant expired", nonce=grant.nonce,
                overdue_seconds=round(now - grant.deadline, 3),
            )
        self._spent.add(grant.nonce)
        return SpentGrant(grant=grant, spent_at=now)
