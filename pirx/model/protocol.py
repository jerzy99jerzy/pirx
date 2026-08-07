"""What a model is allowed to return, as a type.

The shape is deliberately tiny. A richer interface - free-form action names,
parameter suggestions, confidence scores that something might threshold on -
would be a larger attack surface for no gain the thesis recognises.

Does NOT:
  - carry parameters. Action parameters come from deterministic verdict
    fields, and no field a model produces is ever one (PT2).
  - carry a confidence, score, or priority. A number a model produces that
    something later compares against a threshold is an autonomy dial with
    extra steps.
  - carry a target. Targets are derived deterministically from the verdict.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ..consumer import Verdict


@dataclass(frozen=True, slots=True)
class ModelProposal:
    """A selection plus a rationale. Nothing else crosses the boundary."""

    #: Must already exist in the registry. Validated on arrival; an unknown
    #: value is a refusal, never a new capability.
    action: str
    #: Free text for a human to read inside the renderer's untrusted fence.
    rationale: str


class ProposalModel(Protocol):
    def propose(self, verdict: Verdict) -> ModelProposal: ...
