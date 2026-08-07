"""The grant primitive: issue, verify, spend.

A grant authorises one action, not a session. It is bound to the hash of the
rendered proposal, the target, and the justifying verdict; it expires on the
monotonic clock; it is single-use.

``SpentGrant`` is a distinct type whose only constructor is ``spend``. A
capability's signature takes ``SpentGrant``, so "execute without spending" is
not a bug a test has to catch - it is a program a type checker rejects
(ARCHITECTURE A2).

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
    ExpiredGrantRefusal,
    HashMismatchRefusal,
    SpentGrantRefusal,
    TargetMismatchRefusal,
)
from .proposal import RenderedProposal
from .types import GRANT_TTL_SECONDS, ActionHash, GrantNonce, TargetId, VerdictId

Clock = Callable[[], float]


@dataclass(frozen=True, slots=True)
class ApprovalDecision:
    """The human's answer. Produced only by the approval surface."""

    approved: bool
    action_hash: ActionHash
    target: TargetId
    approver_claim: str
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

    def issue(
        self, decision: ApprovalDecision, rendered: RenderedProposal
    ) -> Grant:
        if not decision.approved:
            raise ValueError("cannot issue a grant from a declined decision")
        if decision.action_hash != rendered.action_hash:
            raise HashMismatchRefusal(
                "decision does not cover these bytes",
                decided=decision.action_hash, rendered=rendered.action_hash,
            )
        now = self._clock()
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
