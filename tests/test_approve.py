"""Approval-surface tests: what the human saw is what was hashed."""

from __future__ import annotations

import io

import pytest
from conftest import FakeClock

from pirx import approve
from pirx.errors import ChallengeFailedRefusal, ReadingFloorRefusal
from pirx.proposal import Proposal, prepare
from pirx.types import CHALLENGE_FIELDS, TargetId, UntrustedProse, VerdictId


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


def answers(*lines: str):
    """Scripted approver: yields one line per prompt, in order."""
    queue = iter(lines)
    return lambda: next(queue) + "\n"


def attentive(r, *decision_lines: str, clock: FakeClock | None = None):
    """Drive decide() past the challenge, with the clock past the floor."""
    clock = clock or FakeClock()
    out = io.StringIO()
    field = approve.challenge_field(r)
    transcription = approve.expected_transcription(r, field)
    read = answers(transcription, *decision_lines)

    def timed() -> str:
        # Advance past the floor before each answer, so the measured
        # interval is comfortably above it, like a human's.
        clock.advance(approve.reading_floor_seconds(len(r.canonical_bytes)) + 1)
        return read()

    return approve.decide(r, 0.0, out, timed, clock=clock), out


def test_full_word_approves() -> None:
    r = rendered()
    decision, _ = attentive(r, "approve")
    assert decision.approved is True
    assert decision.action_hash == r.action_hash


def test_single_keystroke_does_not_approve() -> None:
    r = rendered()
    for answer in ("y", "yes", "Y", "", "ok", "sure"):
        decision, _ = attentive(r, answer)
        assert decision.approved is False, answer


def test_decision_is_never_marked_authenticated() -> None:
    r = rendered()
    decision, _ = attentive(r, "approve")
    assert decision.authenticated is False
    assert decision.approver_claim


def test_age_is_shown_and_labelled_as_not_an_integrity_control() -> None:
    r = rendered()
    out = io.StringIO()
    approve.present(r, age_seconds=42.0, out=out)
    text = out.getvalue()
    assert "proposal age: 42.0s" in text
    assert "not an integrity control" in text


# --- PT15: the attention layer at the surface -------------------------------


def test_challenge_field_is_deterministic_and_hash_selected() -> None:
    r = rendered()
    field = approve.challenge_field(r)
    assert field in CHALLENGE_FIELDS
    assert approve.challenge_field(r) == field
    expected = CHALLENGE_FIELDS[int(r.action_hash, 16) % len(CHALLENGE_FIELDS)]
    assert field == expected


def test_wrong_transcription_is_a_typed_refusal_not_a_decline() -> None:
    r = rendered()
    out = io.StringIO()
    with pytest.raises(ChallengeFailedRefusal) as excinfo:
        approve.decide(r, 0.0, out, answers("not-the-value", "approve"),
                       clock=FakeClock())
    assert excinfo.value.details["field"] == approve.challenge_field(r)
    # The event never carries the expected value (PT15).
    assert "expected" not in excinfo.value.details


def test_reflexive_approval_is_refused_below_the_floor() -> None:
    r = rendered()
    out = io.StringIO()
    clock = FakeClock()  # never advanced: the answer is instantaneous
    field = approve.challenge_field(r)
    read = answers(approve.expected_transcription(r, field), "approve")
    with pytest.raises(ReadingFloorRefusal):
        approve.decide(r, 0.0, out, read, clock=clock)


def test_decline_is_not_floor_checked() -> None:
    """Refusing fast is not the threat; an instant decline stands."""
    r = rendered()
    out = io.StringIO()
    clock = FakeClock()
    field = approve.challenge_field(r)
    read = answers(approve.expected_transcription(r, field), "decline")
    decision = approve.decide(r, 0.0, out, read, clock=clock)
    assert decision.approved is False


def test_attention_evidence_is_measured_not_asserted() -> None:
    r = rendered()
    clock = FakeClock()
    decision, _ = attentive(r, "approve", clock=clock)
    evidence = decision.attention
    assert evidence.challenge_passed is True
    assert evidence.challenge_field == approve.challenge_field(r)
    assert evidence.elapsed_seconds >= evidence.floor_seconds
    assert evidence.floor_seconds == approve.reading_floor_seconds(
        len(r.canonical_bytes)
    )


def test_floor_grows_with_byte_length() -> None:
    assert approve.reading_floor_seconds(4096) > approve.reading_floor_seconds(64)


def test_on_challenge_fires_before_the_answer_is_read() -> None:
    """Intent precedes action: the hook runs before read_line is consumed."""
    r = rendered()
    out = io.StringIO()
    order: list[str] = []
    field = approve.challenge_field(r)

    def read() -> str:
        order.append("answered")
        return {0: approve.expected_transcription(r, field), 1: "decline"}[
            len([o for o in order if o == "answered"]) - 1
        ] + "\n"

    approve.decide(
        r, 0.0, out, read, clock=FakeClock(),
        on_challenge=lambda f: order.append(f"challenged:{f}"),
    )
    assert order[0] == f"challenged:{field}"
    assert order[1] == "answered"
