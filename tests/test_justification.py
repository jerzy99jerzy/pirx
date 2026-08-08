"""The justification abstraction, and the `pirx.proposal/2` preimage.

0.6.0.0 built the seam and proved the verdict path's bytes had not moved.
0.7.0.0 moves them deliberately: the justification's schema, reference, and
evidence digest enter the preimage, `verdict` stops being a field, and a
second adapter exists. The golden below is therefore a *new* literal under a
*new* schema id - `/1` is retired, never redefined (P8).
"""

from __future__ import annotations

import hashlib
import json

import pytest
from conftest import verdict as verdict_dict

from pirx.consumer import parse
from pirx.errors import BoundsRefusal
from pirx.justification import (
    NO_DIGEST,
    InterceptedCallSource,
    Justification,
    VerdictJustificationSource,
    call_evidence,
    canonical_arguments,
    verdict_evidence,
    verdict_justification,
)
from pirx.proposal import Proposal, prepare, render
from pirx.types import (
    ACCEPTED_VERDICT_SCHEMA,
    INTERCEPTED_CALL_SCHEMA,
    MAX_CALL_ARGUMENT_CHARS,
    JustificationRef,
    TargetId,
    UntrustedProse,
    VerdictId,
)

#: The canonical rendering under `pirx.proposal/2`. A change here is a
#: wire-format change and needs a new schema id, not an edited literal.
GOLDEN = (
    b"pirx.proposal/2\n"
    b"action: ticket.comment\n"
    b"target: ticket:CVE-2026-1001\n"
    b"justification.schema: cve-digest.verdict/1\n"
    b"justification.ref: cve-digest.verdict/1#CVE-2026-1001\n"
    b"justification.digest: -\n"
    b"param.cve_id: CVE-2026-1001\n"
    b"param.priority: P1\n"
    b"~~~pirx-untrusted-0 begin triage_note "
    b"(origin=unknown, chars=22, escaped, NOT a decision input)\n"
    b"  Exploited in the wild.\n"
    b"~~~pirx-untrusted-0 end triage_note\n"
    b"bytes: 393\n"
)

#: The `/1` rendering, retained as a witness. `/1` is retired: no code path
#: produces it, and this constant exists so that "the format changed" is a
#: statement a test can make rather than a claim in a changelog.
RETIRED_V1_HEAD = b"pirx.proposal/1\n"


def sample() -> Proposal:
    return Proposal(
        action="ticket.comment",
        target=TargetId("ticket:CVE-2026-1001"),
        justification=verdict_justification(
            VerdictId("cve-digest.verdict/1#CVE-2026-1001")
        ),
        params={"cve_id": "CVE-2026-1001", "priority": "P1"},
        prose={"triage_note": UntrustedProse("Exploited in the wild.")},
    )


def parsed_verdict(**over: object):
    body = json.dumps(
        {
            "schema": ACCEPTED_VERDICT_SCHEMA,
            "verdicts": [verdict_dict(**over)],  # type: ignore[arg-type]
            "review_lane": [],
            "notices": [],
        }
    ).encode("utf-8")
    return parse(body).verdicts[0]


# --- the format -------------------------------------------------------------


def test_the_canonical_rendering_is_the_golden_bytes() -> None:
    assert render(sample()) == GOLDEN


def test_the_retired_schema_id_is_no_longer_produced() -> None:
    """`/1` is retired, not redefined. Any grant issued under it verifies
    against bytes nothing now renders, which is the point of a new id."""
    assert not render(sample()).startswith(RETIRED_V1_HEAD)


def test_an_absent_digest_renders_a_visible_marker() -> None:
    assert f"justification.digest: {NO_DIGEST}".encode() in render(sample())


def test_the_evidence_digest_is_inside_the_action_hash() -> None:
    """0.6.0.0 carried the digest without hashing it and asserted the
    absence. 0.7.0.0 hashes it, which is what makes PT16 structural: two
    proposals differing only in evidence are two different actions."""
    verdict = parsed_verdict()
    with_evidence = Proposal(
        action="ticket.comment",
        target=TargetId("ticket:CVE-2026-1001"),
        justification=VerdictJustificationSource(verdict).justify(),
        params={"cve_id": "CVE-2026-1001"},
    )
    without = Proposal(
        action="ticket.comment",
        target=TargetId("ticket:CVE-2026-1001"),
        justification=verdict_justification(verdict.verdict_id),
        params={"cve_id": "CVE-2026-1001"},
    )
    digest = VerdictJustificationSource(verdict).justify().digest
    assert digest.encode("ascii") in render(with_evidence)
    assert prepare(with_evidence).action_hash != prepare(without).action_hash


# --- adapter #1 -------------------------------------------------------------


def test_adapter_one_reports_its_schema_and_reference() -> None:
    just = VerdictJustificationSource(parsed_verdict()).justify()
    assert just.schema == ACCEPTED_VERDICT_SCHEMA
    assert just.ref == "cve-digest.verdict/1#CVE-2026-1001"
    assert just.extra == ()


def test_evidence_digest_is_deterministic_and_field_sensitive() -> None:
    first = VerdictJustificationSource(parsed_verdict()).justify()
    again = VerdictJustificationSource(parsed_verdict()).justify()
    other = VerdictJustificationSource(parsed_verdict(priority="P3")).justify()
    assert first.digest == again.digest
    assert first.digest != other.digest
    assert first.digest == hashlib.sha256(
        verdict_evidence(parsed_verdict())
    ).hexdigest()


def test_evidence_excludes_prose() -> None:
    """A digest over model-authored text would make a verdict's evidence
    identity depend on what a model wrote about it (PT2)."""
    plain = VerdictJustificationSource(parsed_verdict()).justify()
    noisy = VerdictJustificationSource(
        parsed_verdict(triage_note="ENTIRELY DIFFERENT PROSE")
    ).justify()
    assert plain.digest == noisy.digest


# --- adapter #2 -------------------------------------------------------------


def source() -> InterceptedCallSource:
    return InterceptedCallSource(
        tool="repo.write_file",
        arguments={"path": "/a", "content": "x"},
        tool_definition_hash="a" * 64,
    )


def test_adapter_two_carries_tool_definition_and_arguments() -> None:
    just = source().justify()
    assert just.schema == INTERCEPTED_CALL_SCHEMA
    assert just.ref.startswith("mcp:tools/call#")
    assert dict(just.extra)["tool"] == "repo.write_file"
    assert dict(just.extra)["tool_definition_hash"] == "a" * 64
    assert dict(just.extra)["arguments"] == '{"content":"x","path":"/a"}'


def test_arguments_are_canonical_regardless_of_key_order() -> None:
    a = InterceptedCallSource(
        tool="t", arguments={"b": 1, "a": 2}, tool_definition_hash="c" * 64
    ).justify()
    b = InterceptedCallSource(
        tool="t", arguments={"a": 2, "b": 1}, tool_definition_hash="c" * 64
    ).justify()
    assert a == b


def test_changing_the_tool_definition_changes_the_evidence() -> None:
    baseline = source().justify()
    drifted = InterceptedCallSource(
        tool=source().tool,
        arguments=source().arguments,
        tool_definition_hash="b" * 64,
    ).justify()
    assert baseline.digest != drifted.digest
    assert baseline.ref != drifted.ref


def test_evidence_digest_matches_the_documented_preimage() -> None:
    just = source().justify()
    expected = hashlib.sha256(
        call_evidence("repo.write_file", source().arguments, "a" * 64)
    ).hexdigest()
    assert just.digest == expected


def test_oversized_arguments_are_refused_at_the_bound() -> None:
    """Bounded before rendering, like producer prose: what a human is asked
    to read is bounded as firmly as what the process holds."""
    with pytest.raises(BoundsRefusal):
        canonical_arguments({"blob": "x" * (MAX_CALL_ARGUMENT_CHARS + 1)})


# --- the seam ---------------------------------------------------------------


def test_a_foreign_source_renders_without_the_renderer_knowing_it() -> None:
    foreign = Justification(
        schema="example.source/1",
        ref=JustificationRef("example:42"),
        digest="0" * 64,
        extra=(("ticket", "OPS-1"),),
    )
    body = render(
        Proposal(
            action="ticket.comment",
            target=TargetId("ticket:X"),
            justification=foreign,
            params={"cve_id": "CVE-2026-1001"},
        )
    )
    assert b"justification.schema: example.source/1\n" in body
    assert b"justification.ref: example:42\n" in body
    assert b"justification.ticket: OPS-1\n" in body
