"""The grant primitive: issue, verify, spend.

A grant authorises one action, not a session. It is bound to the hash of the
rendered proposal, the target, and the justification that warrants it; it
expires on the wall clock (0.7.0.0: see below); it is single-use.

``SpentGrant`` is a distinct type whose only constructor is ``spend``. A
capability's signature takes ``SpentGrant``, so "execute without spending" is
not a bug a test has to catch - it is a program a type checker rejects
(ARCHITECTURE A2).

Since 0.5.0.0, issuance also verifies the decision's ``AttentionEvidence``
(PT15) and counts against a session grant budget, so a grant is unreachable
not only without an approving decision but without a *measurably attentive*
one. The surface refuses first; the issuer refuses again so that a decision
object fabricated in code cannot route around the surface (ARCHITECTURE A17).

**0.7.0.0 pays the coupled debt.** The gate splits approval from execution
into separate processes, so the pair the brief has owed since section 9 lands
here **together, in one version**: an HMAC over the canonical scope, and the
durable spend store in ``spendstore.py``. Either alone is unsound - a
stateless-verifiable grant with no durable spend record is replayable across
restarts, and a durable record without a verifiable grant protects nothing
(P5). Two consequences follow and are stated rather than discovered:

  - **Expiry moves to the wall clock.** A monotonic deadline is meaningless
    in another process, and a grant that crosses a process boundary must
    carry a deadline the reader can evaluate. The cost is real and named: an
    operator who moves the system clock backwards extends a grant's life.
    That is a smaller exposure than a grant that cannot be checked at all,
    and it is a threat-model line (PT4's control text says so), not a
    silence.
  - **A grant is now a serialisable artefact.** It is therefore also a thing
    an attacker can copy. The MAC makes forgery hard; the spend store makes
    a copy useless; neither makes the file secret, and nothing in the design
    assumes it is.

Does NOT:
  - hold the key. ``GrantIssuer`` takes key bytes; loading them is the
    runner's job, where it is visible. Nothing under ``model/`` may import
    this module, which the package scrape enforces.
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

import hmac
import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .errors import (
    ChallengeFailedRefusal,
    ExpiredGrantRefusal,
    GrantMacRefusal,
    HashMismatchRefusal,
    MalformedGrantRefusal,
    ReadingFloorRefusal,
    SessionBudgetRefusal,
    TargetMismatchRefusal,
)
from .proposal import RenderedProposal
from .spendstore import SpendStore
from .types import (
    GRANT_TTL_SECONDS,
    MAX_GRANTS_PER_SESSION,
    MIN_GRANT_KEY_BYTES,
    ActionHash,
    GrantNonce,
    JustificationRef,
    TargetId,
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
    """A single-use authorisation, verifiable in a process that did not issue it."""

    nonce: GrantNonce
    action_hash: ActionHash
    target: TargetId
    justification: JustificationRef
    issued_at: float
    deadline: float
    #: HMAC-SHA256 over the canonical scope below. Present from 0.7.0.0,
    #: because a grant now crosses a process boundary and a receiver has no
    #: other way to tell an issued grant from a written one.
    mac: str

    def scope_bytes(self) -> bytes:
        """The canonical, MAC-covered scope. One serialisation, like the
        renderer: what is verified and what is transported cannot diverge."""
        return json.dumps(
            {
                "nonce": str(self.nonce),
                "action_hash": str(self.action_hash),
                "target": str(self.target),
                "justification": str(self.justification),
                "issued_at": round(self.issued_at, 6),
                "deadline": round(self.deadline, 6),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def to_json(self) -> bytes:
        record = json.loads(self.scope_bytes())
        record["mac"] = self.mac
        return json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def from_json(raw: bytes) -> Grant:
        """Parse a transported grant as hostile input.

        Shape only. Whether it was issued by this system is what the MAC
        answers, at spend, in one place.
        """
        try:
            record = json.loads(raw)
        except (ValueError, TypeError) as exc:
            raise MalformedGrantRefusal("grant is not JSON") from exc
        if not isinstance(record, dict):
            raise MalformedGrantRefusal("grant is not an object")
        required = (
            "nonce", "action_hash", "target", "justification",
            "issued_at", "deadline", "mac",
        )
        missing = [key for key in required if key not in record]
        if missing:
            raise MalformedGrantRefusal("grant is missing fields", missing=missing)
        for key in ("nonce", "action_hash", "target", "justification", "mac"):
            if not isinstance(record[key], str):
                raise MalformedGrantRefusal("grant field is not a string", field=key)
        for key in ("issued_at", "deadline"):
            if not isinstance(record[key], int | float) or isinstance(
                record[key], bool
            ):
                raise MalformedGrantRefusal("grant field is not a number", field=key)
        return Grant(
            nonce=GrantNonce(record["nonce"]),
            action_hash=ActionHash(record["action_hash"]),
            target=TargetId(record["target"]),
            justification=JustificationRef(record["justification"]),
            issued_at=float(record["issued_at"]),
            deadline=float(record["deadline"]),
            mac=record["mac"],
        )


@dataclass(frozen=True, slots=True)
class SpentGrant:
    """Proof that a grant was verified and consumed. Constructed only by
    ``GrantIssuer.spend``."""

    grant: Grant
    spent_at: float


def load_key(path: Path) -> bytes:
    """Read the grant key, refusing anything too short to be one.

    A short key is a long key that was never generated properly. This is a
    constant in code, not a configurable minimum (P6).
    """
    key = path.read_bytes().strip()
    if len(key) < MIN_GRANT_KEY_BYTES:
        raise ValueError(
            f"grant key is {len(key)} bytes; {MIN_GRANT_KEY_BYTES} is the minimum"
        )
    return key


class GrantIssuer:
    """Issues, verifies, and spends grants against a durable store."""

    def __init__(
        self,
        clock: Clock,
        key: bytes,
        store: SpendStore,
        ttl_seconds: float = GRANT_TTL_SECONDS,
    ) -> None:
        if len(key) < MIN_GRANT_KEY_BYTES:
            raise ValueError("grant key is shorter than the minimum")
        self._clock = clock
        self._key = key
        self._store = store
        self._ttl = ttl_seconds
        self._issued_count = 0

    def _mac(self, scope: bytes) -> str:
        return hmac.new(self._key, scope, "sha256").hexdigest()

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
        unsigned = Grant(
            nonce=GrantNonce(secrets.token_hex(16)),
            action_hash=rendered.action_hash,
            target=rendered.proposal.target,
            justification=rendered.proposal.justification.ref,
            issued_at=now,
            deadline=now + self._ttl,
            mac="",
        )
        self._issued_count += 1
        return Grant(
            nonce=unsigned.nonce,
            action_hash=unsigned.action_hash,
            target=unsigned.target,
            justification=unsigned.justification,
            issued_at=unsigned.issued_at,
            deadline=unsigned.deadline,
            mac=self._mac(unsigned.scope_bytes()),
        )

    def spend(
        self, grant: Grant, action_hash: ActionHash, target: TargetId
    ) -> SpentGrant:
        """Total verification, then burn the nonce **before** returning.

        Order is load-bearing and reads top to bottom as the argument it is:
        authenticity first (an unverified grant's other fields mean nothing),
        then coverage, then target, then time, then the durable burn. The
        nonce is spent before the caller can act, so a crash mid-action
        cannot leave reusable authority behind.

        Two fields in the scope - ``target`` and ``justification`` - are also
        rendered into the preimage, so ``action_hash`` already binds them and
        a mismatch would fail the coverage check above. ``target`` is
        nonetheless re-checked as an independent, readable assertion.
        ``justification`` is not, deliberately: the caller with a
        ``JustificationRef`` to compare against is the renderer that produced
        the hash, so an independent check here would compare the field to a
        value derived from the same bytes it was hashed from - a tautology
        wearing a control's clothes (review F52, and P7). It stays in the
        scope because removing it from the MAC coverage would be the change
        that needs justifying, not keeping it.
        """
        expected = self._mac(grant.scope_bytes())
        if not hmac.compare_digest(expected, grant.mac):
            raise GrantMacRefusal(
                "grant MAC does not verify", nonce=str(grant.nonce)
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
        self._store.spend(grant.nonce)
        return SpentGrant(grant=grant, spent_at=now)
