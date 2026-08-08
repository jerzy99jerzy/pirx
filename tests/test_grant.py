"""Grant tests: one action, one target, one use, one deadline."""

from __future__ import annotations

import pytest
from conftest import FakeClock

from pirx.approve import challenge_field, reading_floor_seconds
from pirx.errors import (
    ChallengeFailedRefusal,
    ExpiredGrantRefusal,
    HashMismatchRefusal,
    ReadingFloorRefusal,
    SessionBudgetRefusal,
    SpentGrantRefusal,
    TargetMismatchRefusal,
)
from pirx.grant import ApprovalDecision, AttentionEvidence, GrantIssuer, SpentGrant
from pirx.proposal import Proposal, prepare
from pirx.types import (
    GRANT_TTL_SECONDS,
    MAX_GRANTS_PER_SESSION,
    ActionHash,
    TargetId,
    UntrustedProse,
    VerdictId,
)


def rendered(target: str = "ticket:CVE-2026-1001"):
    return prepare(
        Proposal(
            action="ticket.comment",
            target=TargetId(target),
            verdict=VerdictId("cve-digest.verdict/1#CVE-2026-1001"),
            params={"cve_id": "CVE-2026-1001"},
            prose={"triage_note": UntrustedProse("note")},
        )
    )


def attention(
    r, passed: bool = True, elapsed: float | None = None
) -> AttentionEvidence:
    floor = reading_floor_seconds(len(r.canonical_bytes))
    return AttentionEvidence(
        challenge_field=challenge_field(r),
        challenge_passed=passed,
        elapsed_seconds=floor + 1.0 if elapsed is None else elapsed,
        floor_seconds=floor,
    )


def approval(
    r, approved: bool = True, evidence: AttentionEvidence | None = None
) -> ApprovalDecision:
    return ApprovalDecision(
        approved=approved,
        action_hash=r.action_hash,
        target=r.proposal.target,
        approver_claim="tester",
        attention=attention(r) if evidence is None else evidence,
    )


def test_grant_issues_from_an_approving_decision() -> None:
    clock = FakeClock()
    r = rendered()
    grant = GrantIssuer(clock).issue(approval(r), r)
    assert grant.action_hash == r.action_hash
    assert grant.deadline == pytest.approx(clock.now + GRANT_TTL_SECONDS)


def test_declined_decision_cannot_produce_a_grant() -> None:
    r = rendered()
    with pytest.raises(ValueError):
        GrantIssuer(FakeClock()).issue(approval(r, approved=False), r)


def test_decision_for_other_bytes_cannot_produce_a_grant() -> None:
    a, b = rendered(), rendered("ticket:CVE-2026-9999")
    with pytest.raises(HashMismatchRefusal):
        GrantIssuer(FakeClock()).issue(approval(a), b)


def test_spend_returns_a_spent_grant() -> None:
    clock, r = FakeClock(), rendered()
    issuer = GrantIssuer(clock)
    grant = issuer.issue(approval(r), r)
    spent = issuer.spend(grant, r.action_hash, r.proposal.target)
    assert isinstance(spent, SpentGrant)


def test_a_spent_grant_cannot_be_spent_again() -> None:
    clock, r = FakeClock(), rendered()
    issuer = GrantIssuer(clock)
    grant = issuer.issue(approval(r), r)
    issuer.spend(grant, r.action_hash, r.proposal.target)
    with pytest.raises(SpentGrantRefusal) as caught:
        issuer.spend(grant, r.action_hash, r.proposal.target)
    assert caught.value.details["nonce"] == grant.nonce


def test_expired_grant_is_refused_at_spend_time_though_valid_at_issue() -> None:
    clock, r = FakeClock(), rendered()
    issuer = GrantIssuer(clock)
    grant = issuer.issue(approval(r), r)
    clock.advance(GRANT_TTL_SECONDS + 1)
    with pytest.raises(ExpiredGrantRefusal) as caught:
        issuer.spend(grant, r.action_hash, r.proposal.target)
    assert caught.value.details["overdue_seconds"] > 0


def test_grant_for_target_a_is_refused_against_target_b() -> None:
    clock, a = FakeClock(), rendered()
    issuer = GrantIssuer(clock)
    grant = issuer.issue(approval(a), a)
    with pytest.raises(TargetMismatchRefusal):
        issuer.spend(grant, a.action_hash, TargetId("ticket:CVE-2026-9999"))


def test_grant_is_refused_against_altered_bytes() -> None:
    clock, r = FakeClock(), rendered()
    issuer = GrantIssuer(clock)
    grant = issuer.issue(approval(r), r)
    with pytest.raises(HashMismatchRefusal):
        issuer.spend(grant, ActionHash("0" * 64), r.proposal.target)


def test_expiry_check_precedes_nothing_that_could_mask_replay() -> None:
    """A spent grant that is also expired reports the replay, which is the
    stronger signal: expiry is routine, reuse is an attack."""
    clock, r = FakeClock(), rendered()
    issuer = GrantIssuer(clock)
    grant = issuer.issue(approval(r), r)
    issuer.spend(grant, r.action_hash, r.proposal.target)
    clock.advance(GRANT_TTL_SECONDS + 1)
    with pytest.raises(SpentGrantRefusal):
        issuer.spend(grant, r.action_hash, r.proposal.target)


def test_authority_does_not_survive_a_new_issuer() -> None:
    """A fresh process means a fresh spent-set; the grant object is likewise
    gone. This test documents the single-process assumption rather than
    proving cross-process safety, which no in-process mechanism can."""
    clock, r = FakeClock(), rendered()
    first = GrantIssuer(clock)
    grant = first.issue(approval(r), r)
    first.spend(grant, r.action_hash, r.proposal.target)
    second = GrantIssuer(clock)
    # Deliberately shows the residual: an in-memory spent-set is per-process.
    # This is why HMAC grants and a durable spend store are coupled and land
    # together at the first process split (P5).
    assert second.spend(grant, r.action_hash, r.proposal.target).grant is grant

# --- PT15: attention evidence at issuance -----------------------------------


def test_inattentive_decision_cannot_buy_a_grant() -> None:
    """A decision fabricated without a passed challenge is refused at the
    issuer, so the surface is where attention is measured, not the only
    place it is enforced."""
    clock, r = FakeClock(), rendered()
    with pytest.raises(ChallengeFailedRefusal):
        GrantIssuer(clock).issue(
            approval(r, evidence=attention(r, passed=False)), r
        )


def test_below_floor_decision_cannot_buy_a_grant() -> None:
    clock, r = FakeClock(), rendered()
    with pytest.raises(ReadingFloorRefusal):
        GrantIssuer(clock).issue(approval(r, evidence=attention(r, elapsed=0.0)), r)


def test_session_budget_refuses_the_next_issue() -> None:
    """The (N+1)th grant in one session is refused. In the single-run
    topology PT13's proposal budget binds first; this proves the primitive
    the long-lived gate surface will lean on (PT15)."""
    clock = FakeClock()
    issuer = GrantIssuer(clock)
    for n in range(MAX_GRANTS_PER_SESSION):
        r = rendered(target=f"ticket:CVE-2026-{2000 + n}")
        issuer.issue(approval(r), r)
    overflow = rendered(target="ticket:CVE-2026-9999")
    with pytest.raises(SessionBudgetRefusal):
        issuer.issue(approval(overflow), overflow)


def test_a_refused_issue_does_not_consume_session_budget() -> None:
    """Refusals are free: only issued grants count, so an attacker cannot
    exhaust the budget with decisions that never produced authority."""
    clock, r = FakeClock(), rendered()
    issuer = GrantIssuer(clock)
    for _ in range(MAX_GRANTS_PER_SESSION + 5):
        with pytest.raises(ChallengeFailedRefusal):
            issuer.issue(approval(r, evidence=attention(r, passed=False)), r)
    assert issuer.issue(approval(r), r).action_hash == r.action_hash
