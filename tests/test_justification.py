"""The justification abstraction: general shape, identical bytes.

The sprint's claim is narrow and checkable: a seam now exists for a second
evidence source, and the verdict path produces the same bytes it produced
before the seam existed. The 156 tests that shipped with 0.5.0.0 pass
unmodified; this module adds the assertions those tests cannot make, chiefly
the golden preimage - "unmodified tests still pass" proves nothing changed
that they looked at, and a literal byte string proves what they looked at.
"""

from __future__ import annotations

import hashlib

import pytest
from conftest import verdict as verdict_dict

from pirx.consumer import parse
from pirx.justification import (
    VERDICT_LABEL,
    Justification,
    VerdictJustificationSource,
    from_verdict_id,
    verdict_evidence,
)
from pirx.proposal import Proposal, prepare, render
from pirx.types import ACCEPTED_VERDICT_SCHEMA, TargetId, UntrustedProse, VerdictId

#: The exact bytes the verdict path rendered before this abstraction existed.
#: Any change here is a wire-format change and needs a new render schema id
#: (P8), not an edited literal.
GOLDEN = (
    b"pirx.proposal/1\n"
    b"action: ticket.comment\n"
    b"target: ticket:CVE-2026-1001\n"
    b"verdict: cve-digest.verdict/1#CVE-2026-1001\n"
    b"param.cve_id: CVE-2026-1001\n"
    b"param.priority: P1\n"
    b"~~~pirx-untrusted-0 begin triage_note "
    b"(origin=unknown, chars=22, escaped, NOT a decision input)\n"
    b"  Exploited in the wild.\n"
    b"~~~pirx-untrusted-0 end triage_note\n"
    b"bytes: 316\n"
)


def sample() -> Proposal:
    return Proposal(
        action="ticket.comment",
        target=TargetId("ticket:CVE-2026-1001"),
        verdict=VerdictId("cve-digest.verdict/1#CVE-2026-1001"),
        params={"cve_id": "CVE-2026-1001", "priority": "P1"},
        prose={"triage_note": UntrustedProse("Exploited in the wild.")},
    )


def parsed_verdict(**over: object) -> object:
    import json

    body = json.dumps(
        {
            "schema": ACCEPTED_VERDICT_SCHEMA,
            "verdicts": [verdict_dict(**over)],  # type: ignore[arg-type]
            "review_lane": [],
            "notices": [],
        }
    ).encode("utf-8")
    return parse(body).verdicts[0]


# --- the acceptance criterion ----------------------------------------------


def test_verdict_path_renders_the_pre_abstraction_bytes() -> None:
    """Golden preimage. If this fails, action hashes moved, which means every
    grant issued against the old rendering is void - a wire-format change
    wearing a refactor's clothes."""
    assert render(sample()) == GOLDEN


def test_a_justification_object_renders_identically_to_a_bare_id() -> None:
    bare = sample()
    explicit = Proposal(
        action=bare.action,
        target=bare.target,
        verdict=bare.verdict,
        params=bare.params,
        justification=VerdictJustificationSource(
            parsed_verdict()  # type: ignore[arg-type]
        ).justify(),
        prose=bare.prose,
    )
    assert render(explicit) == render(bare)
    assert prepare(explicit).action_hash == prepare(bare).action_hash


# --- the abstraction itself -------------------------------------------------


def test_adapter_one_reports_its_schema_ref_and_label() -> None:
    just = VerdictJustificationSource(parsed_verdict()).justify()  # type: ignore[arg-type]
    assert just.schema == ACCEPTED_VERDICT_SCHEMA
    assert just.ref == "cve-digest.verdict/1#CVE-2026-1001"
    assert just.label == VERDICT_LABEL
    assert just.extra == ()


def test_evidence_digest_is_deterministic_and_field_sensitive() -> None:
    first = VerdictJustificationSource(parsed_verdict()).justify()  # type: ignore[arg-type]
    again = VerdictJustificationSource(parsed_verdict()).justify()  # type: ignore[arg-type]
    other = VerdictJustificationSource(
        parsed_verdict(priority="P3")  # type: ignore[arg-type]
    ).justify()
    assert first.digest == again.digest
    assert first.digest != other.digest
    assert first.digest == hashlib.sha256(
        verdict_evidence(parsed_verdict())  # type: ignore[arg-type]
    ).hexdigest()


def test_evidence_excludes_prose() -> None:
    """A digest over model-authored text would make a verdict's evidence
    identity depend on what a model wrote about it (PT2)."""
    plain = VerdictJustificationSource(parsed_verdict()).justify()  # type: ignore[arg-type]
    noisy = VerdictJustificationSource(
        parsed_verdict(triage_note="ENTIRELY DIFFERENT PROSE")  # type: ignore[arg-type]
    ).justify()
    assert plain.digest == noisy.digest


def test_digest_is_carried_but_not_hashed_yet() -> None:
    """**This is an acceptance, asserted so it costs a deliberate edit.**

    The digest is not in the preimage in `pirx.proposal/1`. It enters with
    the gate, under a new render schema id, where it binds a grant to the
    tool definition in force at approval time (PT16). Until then, claiming
    the digest is covered by the action hash would be a claim the code does
    not produce (P7)."""
    just = VerdictJustificationSource(parsed_verdict()).justify()  # type: ignore[arg-type]
    proposal = Proposal(
        action="ticket.comment",
        target=TargetId("ticket:CVE-2026-1001"),
        verdict=VerdictId(just.ref),
        params={"cve_id": "CVE-2026-1001"},
        justification=just,
    )
    assert just.digest
    assert just.digest.encode("ascii") not in render(proposal)


def test_a_second_source_renders_its_own_evidence() -> None:
    """The seam's whole purpose: a source that is not a verdict contributes
    its own label and its own deterministic lines, without the renderer
    learning anything about it. Shape rehearsal for the gate's intercepted
    call (0.7.0.0), not the gate itself."""
    foreign = Justification(
        schema="pirx.intercepted-call/1",
        ref="mcp:tools/call#a1b2c3",
        digest="0" * 64,
        label="intercepted_call",
        extra=(("tool", "repo.write_file"), ("tool_definition_hash", "f" * 8)),
    )
    proposal = Proposal(
        action="ticket.comment",
        target=TargetId("ticket:CVE-2026-1001"),
        verdict=VerdictId("cve-digest.verdict/1#CVE-2026-1001"),
        params={"cve_id": "CVE-2026-1001"},
        justification=foreign,
    )
    body = render(proposal)
    assert b"intercepted_call: mcp:tools/call#a1b2c3\n" in body
    assert b"tool: repo.write_file\n" in body
    assert b"tool_definition_hash: ffffffff\n" in body
    assert b"verdict: " not in body
    assert render(proposal) != render(sample())


def test_a_verdict_justification_may_not_disagree_with_the_verdict_field() -> None:
    """Two fields naming the same thing must not carry two answers: one would
    be rendered and the other believed."""
    with pytest.raises(TypeError, match="does not match verdict"):
        Proposal(
            action="ticket.comment",
            target=TargetId("ticket:CVE-2026-1001"),
            verdict=VerdictId("cve-digest.verdict/1#CVE-2026-1001"),
            params={"cve_id": "CVE-2026-1001"},
            justification=from_verdict_id(
                VerdictId("cve-digest.verdict/1#CVE-2026-9999")
            ),
        )


def test_a_bare_id_justification_reports_no_digest() -> None:
    """Empty means "not computed here", never "computed and equal to
    nothing" - a consumer that treats an empty digest as a value is reading
    absence as evidence."""
    assert from_verdict_id(VerdictId("cve-digest.verdict/1#CVE-2026-1001")).digest == ""
