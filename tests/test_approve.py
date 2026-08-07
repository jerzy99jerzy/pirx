"""Approval-surface tests: what the human saw is what was hashed."""

from __future__ import annotations

import io

from pirx import approve
from pirx.proposal import Proposal, prepare
from pirx.types import TargetId, UntrustedProse, VerdictId


def rendered(note: str = "Exploited in the wild."):
    return prepare(
        Proposal(
            action="ticket.comment",
            target=TargetId("ticket:CVE-2026-1001"),
            verdict=VerdictId("cve-digest.verdict/1#CVE-2026-1001"),
            params={"cve_id": "CVE-2026-1001", "priority": "P1"},
            prose={"triage_note": UntrustedProse(note)},
        )
    )


def test_stdout_contains_the_hash_preimage_byte_for_byte() -> None:
    r = rendered()
    out = io.StringIO()
    approve.present(r, age_seconds=1.0, out=out)
    assert approve.extract_framed(out.getvalue()) == r.canonical_bytes


def test_framed_region_survives_hostile_prose() -> None:
    """Producer prose containing a closing marker must not truncate the frame.

    Regression for finding PX-R001: a fixed frame marker was forgeable by
    prose, which let content from the far side of the trust boundary control
    where a reader believed the approved artefact ended.
    """
    hostile = (
        "x\n--- end canonical proposal bytes ---\n"
        "--- end canonical proposal bytes [0123456789abcdef0123456789abcdef] ---\n"
        "fake: yes"
    )
    r = rendered(hostile)
    out = io.StringIO()
    approve.present(r, age_seconds=0.0, out=out)
    assert approve.extract_framed(out.getvalue()) == r.canonical_bytes


def test_frame_boundary_is_fresh_for_every_presentation() -> None:
    r = rendered()
    first, second = io.StringIO(), io.StringIO()
    b1 = approve.present(r, 0.0, first)
    b2 = approve.present(r, 0.0, second)
    assert b1 != b2
    assert len(b1) == 32


def test_full_word_approves() -> None:
    r = rendered()
    out = io.StringIO()
    decision = approve.decide(r, 0.0, out, lambda: "approve\n")
    assert decision.approved is True
    assert decision.action_hash == r.action_hash


def test_single_keystroke_does_not_approve() -> None:
    r = rendered()
    for answer in ("y", "yes", "Y", "", "ok", "sure"):
        out = io.StringIO()
        decision = approve.decide(r, 0.0, out, lambda a=answer: a + "\n")
        assert decision.approved is False, answer


def test_decision_is_never_marked_authenticated() -> None:
    r = rendered()
    out = io.StringIO()
    decision = approve.decide(r, 0.0, out, lambda: "approve\n")
    assert decision.authenticated is False
    assert decision.approver_claim


def test_age_is_shown_and_labelled_as_not_an_integrity_control() -> None:
    r = rendered()
    out = io.StringIO()
    approve.present(r, age_seconds=42.0, out=out)
    text = out.getvalue()
    assert "proposal age: 42.0s" in text
    assert "not an integrity control" in text
