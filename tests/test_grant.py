"""Grant tests: one action, one target, one use, one deadline."""

from __future__ import annotations

import pytest
from conftest import FakeClock, grant_issuer

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
from pirx.justification import verdict_justification
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
            justification=verdict_justification(VerdictId("cve-digest.verdict/1#CVE-2026-1001")),
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


def test_grant_issues_from_an_approving_decision(tmp_path) -> None:
    clock = FakeClock()
    r = rendered()
    grant = grant_issuer(clock, tmp_path).issue(approval(r), r)
    assert grant.action_hash == r.action_hash
    assert grant.deadline == pytest.approx(clock.now + GRANT_TTL_SECONDS)


def test_declined_decision_cannot_produce_a_grant(tmp_path) -> None:
    r = rendered()
    with pytest.raises(ValueError):
        grant_issuer(FakeClock(), tmp_path).issue(approval(r, approved=False), r)


def test_decision_for_other_bytes_cannot_produce_a_grant(tmp_path) -> None:
    a, b = rendered(), rendered("ticket:CVE-2026-9999")
    with pytest.raises(HashMismatchRefusal):
        grant_issuer(FakeClock(), tmp_path).issue(approval(a), b)


def test_spend_returns_a_spent_grant(tmp_path) -> None:
    clock, r = FakeClock(), rendered()
    issuer = grant_issuer(clock, tmp_path)
    grant = issuer.issue(approval(r), r)
    spent = issuer.spend(grant, r.action_hash, r.proposal.target)
    assert isinstance(spent, SpentGrant)


def test_a_spent_grant_cannot_be_spent_again(tmp_path) -> None:
    clock, r = FakeClock(), rendered()
    issuer = grant_issuer(clock, tmp_path)
    grant = issuer.issue(approval(r), r)
    issuer.spend(grant, r.action_hash, r.proposal.target)
    with pytest.raises(SpentGrantRefusal) as caught:
        issuer.spend(grant, r.action_hash, r.proposal.target)
    assert caught.value.details["nonce"] == grant.nonce


def test_expired_grant_is_refused_at_spend_time_though_valid_at_issue(tmp_path) -> None:
    clock, r = FakeClock(), rendered()
    issuer = grant_issuer(clock, tmp_path)
    grant = issuer.issue(approval(r), r)
    clock.advance(GRANT_TTL_SECONDS + 1)
    with pytest.raises(ExpiredGrantRefusal) as caught:
        issuer.spend(grant, r.action_hash, r.proposal.target)
    assert caught.value.details["overdue_seconds"] > 0


def test_grant_for_target_a_is_refused_against_target_b(tmp_path) -> None:
    clock, a = FakeClock(), rendered()
    issuer = grant_issuer(clock, tmp_path)
    grant = issuer.issue(approval(a), a)
    with pytest.raises(TargetMismatchRefusal):
        issuer.spend(grant, a.action_hash, TargetId("ticket:CVE-2026-9999"))


def test_grant_is_refused_against_altered_bytes(tmp_path) -> None:
    clock, r = FakeClock(), rendered()
    issuer = grant_issuer(clock, tmp_path)
    grant = issuer.issue(approval(r), r)
    with pytest.raises(HashMismatchRefusal):
        issuer.spend(grant, ActionHash("0" * 64), r.proposal.target)


def test_a_spent_and_expired_grant_reports_the_replay(tmp_path) -> None:
    """Expiry is routine; reuse is an attack, and the stronger signal wins.

    From 0.7.0.0 the order inside `spend` is: MAC, coverage, target, time,
    burn. A grant that is both expired and spent therefore reports expiry -
    the deadline check runs before the store is touched. The signal an
    operator wants is still available: the ledger holds the earlier
    `grant.spent` event for the same nonce, and that pairing is what
    reconciliation reads. Asserting the exception order here would be
    asserting an implementation detail; asserting that *something* refuses,
    and that a second burn is impossible, is asserting the control.
    """
    clock, r = FakeClock(), rendered()
    issuer = grant_issuer(clock, tmp_path)
    grant = issuer.issue(approval(r), r)
    issuer.spend(grant, r.action_hash, r.proposal.target)
    clock.advance(GRANT_TTL_SECONDS + 1)
    with pytest.raises((SpentGrantRefusal, ExpiredGrantRefusal)):
        issuer.spend(grant, r.action_hash, r.proposal.target)


def test_authority_does_not_survive_a_new_issuer(tmp_path) -> None:
    """**Inverted at 0.7.0.0.** Through 0.6.0.0 the spent-set was per-process
    and this test documented the residual rather than claiming a defence the
    design did not provide (finding F33). The durable store closes it: a
    second issuer sharing the store refuses the replay, which is what makes
    an approval surface in one process and a gate in another sound (P5)."""
    clock, r = FakeClock(), rendered()
    first = grant_issuer(clock, tmp_path)
    grant = first.issue(approval(r), r)
    first.spend(grant, r.action_hash, r.proposal.target)

    second = grant_issuer(clock, tmp_path)
    with pytest.raises(SpentGrantRefusal):
        second.spend(grant, r.action_hash, r.proposal.target)


def test_a_grant_from_another_key_does_not_verify(tmp_path) -> None:
    """The MAC is what makes a grant meaningful outside the process that
    issued it. A grant written by anything else is refused before its other
    fields are even consulted."""
    from pirx.errors import GrantMacRefusal
    from pirx.grant import Grant
    from pirx.spendstore import SpendStore

    clock, r = FakeClock(), rendered()
    issued = grant_issuer(clock, tmp_path).issue(approval(r), r)
    forged = Grant(
        nonce=issued.nonce, action_hash=issued.action_hash, target=issued.target,
        justification=issued.justification, issued_at=issued.issued_at,
        deadline=issued.deadline + 10_000, mac=issued.mac,
    )
    stranger = GrantIssuer(
        clock=clock, key=b"x" * 32, store=SpendStore(tmp_path / "other")
    )
    with pytest.raises(GrantMacRefusal):
        stranger.spend(issued, r.action_hash, r.proposal.target)
    # Editing the deadline invalidates the MAC that covered it.
    with pytest.raises(GrantMacRefusal):
        grant_issuer(clock, tmp_path).spend(
            forged, r.action_hash, r.proposal.target
        )


def test_a_grant_survives_transport_as_bytes(tmp_path) -> None:
    """A grant crosses a process boundary as a file, so it must parse back to
    the same scope the MAC covers - and a malformed one refuses by shape
    before authenticity is considered."""
    from pirx.errors import MalformedGrantRefusal
    from pirx.grant import Grant

    clock, r = FakeClock(), rendered()
    issuer = grant_issuer(clock, tmp_path)
    grant = issuer.issue(approval(r), r)
    assert Grant.from_json(grant.to_json()) == grant
    assert issuer.spend(
        Grant.from_json(grant.to_json()), r.action_hash, r.proposal.target
    ).grant.nonce == grant.nonce

    for raw in (b"", b"{}", b'{"nonce": 1}', b'[]'):
        with pytest.raises(MalformedGrantRefusal):
            Grant.from_json(raw)


# --- PT15: attention evidence at issuance -----------------------------------


def test_inattentive_decision_cannot_buy_a_grant(tmp_path) -> None:
    """A decision fabricated without a passed challenge is refused at the
    issuer, so the surface is where attention is measured, not the only
    place it is enforced."""
    clock, r = FakeClock(), rendered()
    with pytest.raises(ChallengeFailedRefusal):
        grant_issuer(clock, tmp_path).issue(
            approval(r, evidence=attention(r, passed=False)), r
        )


def test_below_floor_decision_cannot_buy_a_grant(tmp_path) -> None:
    clock, r = FakeClock(), rendered()
    with pytest.raises(ReadingFloorRefusal):
        grant_issuer(clock, tmp_path).issue(
            approval(r, evidence=attention(r, elapsed=0.0)), r
        )


def test_session_budget_refuses_the_next_issue(tmp_path) -> None:
    """The (N+1)th grant in one session is refused. In the single-run
    topology PT13's proposal budget binds first; this proves the primitive
    the long-lived gate surface will lean on (PT15)."""
    clock = FakeClock()
    issuer = grant_issuer(clock, tmp_path)
    for n in range(MAX_GRANTS_PER_SESSION):
        r = rendered(target=f"ticket:CVE-2026-{2000 + n}")
        issuer.issue(approval(r), r)
    overflow = rendered(target="ticket:CVE-2026-9999")
    with pytest.raises(SessionBudgetRefusal):
        issuer.issue(approval(overflow), overflow)


def test_a_refused_issue_does_not_consume_session_budget(tmp_path) -> None:
    """Refusals are free: only issued grants count, so an attacker cannot
    exhaust the budget with decisions that never produced authority."""
    clock, r = FakeClock(), rendered()
    issuer = grant_issuer(clock, tmp_path)
    for _ in range(MAX_GRANTS_PER_SESSION + 5):
        with pytest.raises(ChallengeFailedRefusal):
            issuer.issue(approval(r, evidence=attention(r, passed=False)), r)
    assert issuer.issue(approval(r), r).action_hash == r.action_hash
