"""Consumer tests: the payload is hostile input until proven typed."""

from __future__ import annotations

import json

import pytest
from conftest import bundle, verdict

from pirx import consumer
from pirx.errors import BoundsRefusal, EnumRefusal, MalformedIdRefusal, SchemaRefusal
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
    [("epss", 1.5), ("epss", -0.1), ("score", 101.0), ("cvss", 11.0)],
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
