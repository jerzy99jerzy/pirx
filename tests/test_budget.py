"""Budget tests (PT13): order-preserving, named exclusions, no silent truncation."""

from __future__ import annotations

from conftest import bundle, verdict

from pirx import consumer, proposer


def payload(n: int) -> bytes:
    return bundle([verdict(f"CVE-2026-{1000 + i}") for i in range(n)])


def test_within_budget_proposes_everything() -> None:
    result = proposer.propose(consumer.parse(payload(3)), budget=10)
    assert len(result.proposals) == 3
    assert result.excluded == ()
    assert result.over_budget is False


def test_over_budget_keeps_the_head_of_the_ranking() -> None:
    parsed = consumer.parse(payload(12))
    result = proposer.propose(parsed, budget=4)
    assert len(result.proposals) == 4
    kept = [p.params["cve_id"] for p in result.proposals]
    assert kept == [v.cve_id for v in parsed.verdicts[:4]]


def test_exclusions_are_named_not_counted() -> None:
    parsed = consumer.parse(payload(12))
    result = proposer.propose(parsed, budget=4)
    assert list(result.excluded) == [v.cve_id for v in parsed.verdicts[4:]]
    assert len(result.excluded) == 8


def test_a_high_priority_item_cannot_be_starved_by_a_low_one() -> None:
    items = [verdict("CVE-2026-1000", priority="P1", score=99.0)]
    items += [
        verdict(f"CVE-2026-{2000 + i}", priority="P3", score=1.0) for i in range(9)
    ]
    result = proposer.propose(consumer.parse(bundle(items)), budget=1)
    assert result.proposals[0].params["cve_id"] == "CVE-2026-1000"


def test_zero_budget_proposes_nothing_and_names_all() -> None:
    result = proposer.propose(consumer.parse(payload(3)), budget=0)
    assert result.proposals == ()
    assert len(result.excluded) == 3


def test_proposer_is_deterministic() -> None:
    parsed = consumer.parse(payload(5))
    assert proposer.propose(parsed).proposals == proposer.propose(parsed).proposals


def test_review_lane_items_produce_no_proposals() -> None:
    parsed = consumer.parse(
        bundle([verdict("CVE-2026-1000"), verdict("CVE-2026-1001")],
               lane=["CVE-2026-1001"])
    )
    ids = [p.params["cve_id"] for p in proposer.propose(parsed).proposals]
    assert ids == ["CVE-2026-1000"]
