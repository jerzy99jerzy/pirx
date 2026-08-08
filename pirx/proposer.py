"""Deterministic verdict-to-proposal mapping, with the proposal budget.

Two modes, and the human always knows which one produced what they are
reading.

**Deterministic** (the default, and the only mode through 0.3.0.0): same
bundle in, byte-identical proposals out. No clock, no randomness, no
environment read, no model.

**Model-assisted** (0.4.0.0, opt-in): a model selects the action *by name
from the registry* and writes a rationale. It supplies no parameters, no
target, and no authority; its text lands inside the renderer's untrusted
fence, labelled with its origin. If it returns anything outside its contract
the run refuses - it does not fall back to the deterministic mapping, because
a silent downgrade would make "a model chose this" and "code chose this"
indistinguishable on the approval screen.

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
from .errors import ModelRefusal
from .justification import VerdictJustificationSource
from .model.protocol import ProposalModel
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


def _selection(
    verdict: Verdict, model: ProposalModel | None
) -> tuple[str, dict[str, UntrustedProse], dict[str, str]]:
    """Action name plus the prose block and its origin labels."""
    prose: dict[str, UntrustedProse] = {
        "triage_note": UntrustedProse(verdict.triage_note.text),
        "recommended_action": UntrustedProse(verdict.recommended_action.text),
    }
    origin = {"triage_note": "producer", "recommended_action": "producer"}
    if model is None:
        return DEFAULT_INTENT, prose, origin

    chosen = model.propose(verdict)
    # The client already refused anything outside the registry; this is the
    # second, independent check, because a selection reaching a proposal
    # unvalidated is the one failure this whole module exists to prevent.
    if chosen.action not in KNOWN_INTENTS:
        raise ModelRefusal(
            "model selection escaped validation",
            cve_id=verdict.cve_id, named=str(chosen.action)[:100],
        )
    prose["model_rationale"] = UntrustedProse(chosen.rationale)
    origin["model_rationale"] = "pirx-model"
    return chosen.action, prose, origin


def propose(
    bundle: VerdictBundle,
    budget: int = MAX_PROPOSALS_PER_RUN,
    model: ProposalModel | None = None,
) -> ProposalSet:
    """Map a bundle to at most ``budget`` proposals, in ranking order."""
    if budget < 0:
        raise ValueError("budget must not be negative")

    eligible = bundle.verdicts  # review lane already removed by the consumer
    kept = eligible[:budget]
    dropped = eligible[budget:]

    selections = [_selection(verdict, model) for verdict in kept]

    proposals = tuple(
        Proposal(
            action=action,
            target=_target_for(verdict),
            verdict=verdict.verdict_id,
            # Adapter #1. The proposer holds the verdict object, so it can
            # supply the computed evidence digest that a bare id cannot
            # (0.6.0.0).
            justification=VerdictJustificationSource(verdict).justify(),
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
            prose=prose,
            prose_origin=origin,
        )
        for verdict, (action, prose, origin) in zip(kept, selections, strict=True)
    )

    return ProposalSet(
        proposals=proposals,
        excluded=tuple(v.cve_id for v in dropped),
        budget=budget,
    )
