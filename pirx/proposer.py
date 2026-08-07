"""Deterministic verdict-to-proposal mapping, with the proposal budget.

Same bundle in, byte-identical proposals out. There is no clock, no
randomness, no environment read, and no model in this module (settled
decision 4): the model arrives at 0.4.0.0, and until then PT2 has nothing in
the loop to attack.

The budget (PT13) is enforced **before rendering**, consumed in the producer's
ranking order, so overflow can only ever drop the tail of the ranking - never
a P1 in favour of a P3. Which ids were excluded is carried on the refusal, so
the audit trail covers what was *not* proposed as well as what was.

Does NOT:
  - read ``UntrustedProse`` for anything except carrying it into the display
    section of a proposal. No keyword matching, no intent extraction.
  - re-rank. Priority arrives in the verdict and is never recomputed; the
    ordering used here is the order the producer emitted, with ``score`` as a
    stable tie-break on equal position only because the producer's own order
    is authoritative and a stable sort preserves it.
  - consult the registry. A proposal for an unregistered action is legal to
    build and to show; the refusal happens at spend.
"""

from __future__ import annotations

from dataclasses import dataclass

from .consumer import Verdict, VerdictBundle
from .proposal import Proposal
from .registry import KNOWN_INTENTS
from .types import MAX_PROPOSALS_PER_RUN, CveId, TargetId, UntrustedProse

#: The single intent this version's deterministic mapping emits.
DEFAULT_INTENT = KNOWN_INTENTS[0]


@dataclass(frozen=True, slots=True)
class ProposalSet:
    proposals: tuple[Proposal, ...]
    excluded: tuple[CveId, ...]
    budget: int

    @property
    def over_budget(self) -> bool:
        return bool(self.excluded)


def _target_for(verdict: Verdict) -> TargetId:
    """Deterministic target id derived from verdict fields only.

    In 0.1.0.0 there is no ticketing adapter, so the target is the
    coordination-layer identifier the verdict itself names. Prose is not
    consulted; the value is derived from the CVE id alone.
    """
    return TargetId(f"ticket:{verdict.cve_id}")


def propose(
    bundle: VerdictBundle, budget: int = MAX_PROPOSALS_PER_RUN
) -> ProposalSet:
    """Map a bundle to at most ``budget`` proposals, in ranking order."""
    if budget < 0:
        raise ValueError("budget must not be negative")

    eligible = bundle.verdicts  # review lane already removed by the consumer
    kept = eligible[:budget]
    dropped = eligible[budget:]

    proposals = tuple(
        Proposal(
            action=DEFAULT_INTENT,
            target=_target_for(verdict),
            verdict=verdict.verdict_id,
            params={
                "cve_id": verdict.cve_id,
                "priority": verdict.priority,
                "in_kev": "true" if verdict.in_kev else "false",
                "epss": f"{verdict.epss:.5f}",
                "cvss": "pending" if verdict.cvss is None else f"{verdict.cvss:.1f}",
                "estate_state": verdict.estate_state,
                "vex_status": verdict.vex_status,
                "score": f"{verdict.score:.2f}",
                "nvd_url": verdict.nvd_url,
            },
            prose={
                "triage_note": UntrustedProse(verdict.triage_note.text),
                "recommended_action": UntrustedProse(
                    verdict.recommended_action.text
                ),
            },
        )
        for verdict in kept
    )

    return ProposalSet(
        proposals=proposals,
        excluded=tuple(v.cve_id for v in dropped),
        budget=budget,
    )
