"""Consumer tests: the payload is hostile input until proven typed."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import bundle, verdict

from pirx import consumer, proposer
from pirx.errors import BoundsRefusal, EnumRefusal, MalformedIdRefusal, SchemaRefusal
from pirx.justification import verdict_evidence
from pirx.model.client import verdict_prompt
from pirx.types import MAX_PROSE_CHARS


def test_accepted_schema_parses() -> None:
    parsed = consumer.parse(bundle())
    assert len(parsed.verdicts) == 1
    assert parsed.verdicts[0].cve_id == "CVE-2026-1001"


def test_other_schema_id_is_refused_not_coerced() -> None:
    with pytest.raises(SchemaRefusal) as caught:
        consumer.parse(bundle(schema="cve-digest.verdict/2"))
    assert caught.value.details["found"] == "cve-digest.verdict/2"


def test_non_json_payload_is_refused() -> None:
    with pytest.raises(SchemaRefusal):
        consumer.parse(b"\xff\xfe not json")


@pytest.mark.parametrize("bad", ["CVE-26-1", "cve-2026-1001", "CVE-2026-", "", "1001"])
def test_malformed_cve_id_is_refused(bad: str) -> None:
    with pytest.raises(MalformedIdRefusal):
        consumer.parse(bundle([verdict(cve=bad)]))


@pytest.mark.parametrize(
    ("field", "value"),
    [("priority", "P0"), ("estate_state", "maybe"), ("vex_status", "unknown")],
)
def test_unenumerated_values_are_refused(field: str, value: str) -> None:
    with pytest.raises(EnumRefusal):
        consumer.parse(bundle([verdict(**{field: value})]))


@pytest.mark.parametrize(
    ("field", "value"),
    [("epss", 1.5), ("epss", -0.1), ("score", -0.1), ("cvss", 11.0)],
)
def test_out_of_range_numbers_are_refused(field: str, value: float) -> None:
    with pytest.raises(BoundsRefusal):
        consumer.parse(bundle([verdict(**{field: value})]))


def test_cvss_pending_forbids_a_cvss_value() -> None:
    with pytest.raises(BoundsRefusal):
        consumer.parse(bundle([verdict(cvss_pending=True, cvss=9.8)]))


def test_nvd_url_outside_expected_origin_is_refused() -> None:
    with pytest.raises(BoundsRefusal):
        consumer.parse(bundle([verdict(nvd_url="https://attacker.example/x")]))


def test_oversized_prose_is_truncated_at_parse_time() -> None:
    huge = "A" * 50_000
    parsed = consumer.parse(bundle([verdict(triage_note=huge)]))
    note = parsed.verdicts[0].triage_note.text
    assert len(note) == MAX_PROSE_CHARS
    assert parsed.truncated == ("CVE-2026-1001",)


def test_review_lane_wins_on_collision_and_collision_is_reported() -> None:
    payload = bundle([verdict("CVE-2026-1001")], lane=["CVE-2026-1001"])
    parsed = consumer.parse(payload)
    assert parsed.verdicts == ()
    assert parsed.collisions == ("CVE-2026-1001",)
    assert parsed.review_lane == ("CVE-2026-1001",)


def test_review_lane_entries_may_be_objects_or_bare_ids() -> None:
    body = json.loads(bundle().decode())
    body["review_lane"] = [{"cve_id": "CVE-2026-2002"}]
    parsed = consumer.parse(json.dumps(body).encode())
    assert parsed.review_lane == ("CVE-2026-2002",)


def test_prose_never_becomes_a_plain_string() -> None:
    parsed = consumer.parse(bundle())
    with pytest.raises(TypeError):
        f"{parsed.verdicts[0].triage_note}"


# --- the contract as the producer emits it (F62, F63, 0.7.4.0) --------------

#: Built by cve-digest's own `verdict.build_verdicts` at commit 786efcd
#: (0.7.18.0) from synthetic scored inputs, then carried into this tree by
#: hand. Never fetched: nothing in this repository reads the other one
#: (FAMILY section 1). Refused whole before 0.7.4.0, for two independent
#: reasons, while every hand-written fixture passed.
PRODUCER_FIXTURE = (
    Path(__file__).parent / "fixtures" / "verdict-1.cve-digest-0.7.18.0.json"
)


def test_a_payload_the_producer_emitted_is_accepted() -> None:
    parsed = consumer.parse(PRODUCER_FIXTURE.read_bytes())
    by_id = {v.cve_id: v for v in parsed.verdicts}
    assert len(by_id) == 3
    kev = by_id["CVE-2026-10001"]
    assert kev.vex_status == "none"
    assert kev.score > 100.0
    pending = by_id["CVE-2026-10002"]
    assert pending.epss_pending is True
    assert b"epss: pending\n" in verdict_evidence(pending)


def test_the_no_statement_vex_value_is_accepted() -> None:
    parsed = consumer.parse(bundle([verdict(vex_status="none")]))
    assert parsed.verdicts[0].vex_status == "none"


def test_kev_scores_above_one_hundred_are_accepted() -> None:
    parsed = consumer.parse(bundle([verdict(score=109.1)]))
    assert parsed.verdicts[0].score == 109.1


@pytest.mark.parametrize(
    ("field", "literal"),
    [("score", "Infinity"), ("score", "NaN"), ("epss", "NaN"), ("cvss", "-Infinity")],
)
def test_non_finite_numbers_are_refused(field: str, literal: str) -> None:
    """JSON parsing admits these literals. With no ceiling on `score`, only
    an explicit finiteness check keeps `Infinity` out of the rendered bytes."""
    raw = bundle([verdict(**{field: 0.5})])
    raw = raw.replace(f'"{field}": 0.5'.encode(), f'"{field}": {literal}'.encode())
    assert literal.encode() in raw
    with pytest.raises(BoundsRefusal):
        consumer.parse(raw)


def test_an_absent_epss_pending_reads_as_a_published_score() -> None:
    parsed = consumer.parse(bundle([verdict()]))
    assert parsed.verdicts[0].epss_pending is False
    assert b"epss: 0.87421\n" in verdict_evidence(parsed.verdicts[0])


@pytest.mark.parametrize("value", ["true", 1, None])
def test_a_non_boolean_epss_pending_is_refused(value: object) -> None:
    with pytest.raises(BoundsRefusal):
        consumer.parse(bundle([verdict(epss_pending=value)]))


def test_epss_pending_forbids_a_nonzero_epss() -> None:
    with pytest.raises(BoundsRefusal):
        consumer.parse(bundle([verdict(epss=0.3, epss_pending=True)]))


def test_a_pending_epss_never_reaches_the_approver_as_a_number() -> None:
    parsed = consumer.parse(bundle([verdict(epss=0.0, epss_pending=True)]))
    evidence = verdict_evidence(parsed.verdicts[0])
    assert b"epss: pending\n" in evidence
    assert b"epss: 0.00000" not in evidence
    params = proposer.propose(parsed, budget=1).proposals[0].params
    assert params["epss"] == "pending"
    assert json.loads(verdict_prompt(parsed.verdicts[0]))["epss"] is None


def test_unknown_keys_are_ignored_and_never_rendered() -> None:
    """The producer adds fields under `verdict/1` and relies on consumers
    ignoring them. That tolerance is load-bearing, so it is stated here."""
    marker = "UNKNOWN-KEY-MARKER-7f3a"
    parsed = consumer.parse(
        bundle(
            [
                verdict(
                    epss_percentile=0.97,
                    tickets=[{"system": "jira", "key": "SEC-1", "url": marker}],
                    zz_future_field=marker,
                )
            ]
        )
    )
    evidence = verdict_evidence(parsed.verdicts[0])
    assert marker.encode() not in evidence
    assert b"percentile" not in evidence
    params = proposer.propose(parsed, budget=1).proposals[0].params
    assert marker not in "".join(params.values())
