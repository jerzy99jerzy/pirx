"""Why an action is warranted, as a type the renderer and the grant can carry.

Through 0.5.0.0 the answer was always "because a `cve-digest.verdict/1` item
said so", and `Proposal.verdict` held that answer directly. The gate
(0.7.0.0) intercepts an MCP `tools/call`, which has no verdict: the
justification is the intercepted request itself. Rather than special-case a
second shape inside the renderer later, the *shape of an answer* becomes a
type now, while there is exactly one implementation and the existing suite
can prove nothing moved.

A `Justification` carries four things:

  - ``schema`` - the contract id of the source that produced it. Never
    repurposed; a breaking change to a source is a new id (P8).
  - ``ref`` - the identifier a human reads and the action hash covers.
  - ``digest`` - SHA-256 over the source's own canonical evidence bytes.
  - ``label`` plus ``extra`` - how the source appears in the rendered
    proposal, so the renderer owns ordering, escaping, and hashing while the
    source owns what its evidence is called.

**The digest is carried and not yet hashed, deliberately.** Adding it to the
preimage would change every action hash in the verdict path, which is a wire
format change and therefore a new render schema id, not a silent edit. It
enters the preimage as `pirx.proposal/2` with the gate, where it does real
work (binding a grant to the tool definition in force at approval time,
PT16). Until then a test asserts its absence from the preimage, so "carried,
not hashed" is an executable claim rather than a comment (P7, and the same
discipline PT14's acceptance uses).

Does NOT:
  - decide anything. A justification explains; it never selects an action,
    a target, or a parameter.
  - carry prose. Model or producer text travels as ``UntrustedProse`` in the
    proposal's fenced section, and a justification's fields are all
    deterministic (PT2).
  - authenticate its source. Whether the evidence is genuine is the
    consumer's validation problem (PT1) and, for origin, PT14's named
    acceptance.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Protocol

from .consumer import Verdict
from .types import ACCEPTED_VERDICT_SCHEMA, VerdictId

#: Render label used by the verdict adapter. Fixed as a constant because
#: changing it changes every action hash in the verdict path, which is a
#: wire-format change and must look like one at the call site.
VERDICT_LABEL = "verdict"


@dataclass(frozen=True, slots=True)
class Justification:
    """One source's answer to "why is this action warranted?"."""

    schema: str
    ref: str
    digest: str
    label: str
    #: Additional deterministic ``key: value`` lines the source contributes
    #: to the rendering, in the order given. Empty for the verdict adapter,
    #: which is what keeps `pirx.proposal/1` byte-identical.
    extra: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    def render_lines(self) -> tuple[str, ...]:
        """The source's contribution to the canonical preimage."""
        return (f"{self.label}: {self.ref}",) + tuple(
            f"{key}: {value}" for key, value in self.extra
        )


class JustificationSource(Protocol):
    """Anything that can explain why an action is warranted.

    One implementation today (`VerdictJustificationSource`); the gate's
    intercepted-call source is the second, and the protocol exists so that
    landing it is an addition rather than a rewrite of the renderer.
    """

    def justify(self) -> Justification: ...


def verdict_evidence(verdict: Verdict) -> bytes:
    """Canonical evidence bytes for a verdict: deterministic fields only.

    Prose is excluded, not by oversight: a digest over model-authored text
    would make the evidence identity of a verdict depend on what a model
    wrote about it, and PT2 exists to keep prose out of every position where
    it could influence anything.
    """
    lines = [
        f"schema: {ACCEPTED_VERDICT_SCHEMA}",
        f"cve_id: {verdict.cve_id}",
        f"priority: {verdict.priority}",
        f"in_kev: {'true' if verdict.in_kev else 'false'}",
        f"epss: {verdict.epss:.5f}",
        f"cvss: {'pending' if verdict.cvss is None else f'{verdict.cvss:.1f}'}",
        f"cvss_pending: {'true' if verdict.cvss_pending else 'false'}",
        f"estate_state: {verdict.estate_state}",
        f"vex_status: {verdict.vex_status}",
        f"score: {verdict.score:.5f}",
        f"nvd_url: {verdict.nvd_url}",
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


@dataclass(frozen=True, slots=True)
class VerdictJustificationSource:
    """Adapter #1: a `cve-digest.verdict/1` item.

    Renders exactly the line the verdict path has rendered since 0.1.0.0, so
    every action hash produced before this module existed is still produced
    after it. That is the sprint's acceptance criterion, and
    `test_justification.py` holds it as golden bytes rather than as a claim.
    """

    verdict: Verdict

    def justify(self) -> Justification:
        return Justification(
            schema=ACCEPTED_VERDICT_SCHEMA,
            ref=str(self.verdict.verdict_id),
            digest=hashlib.sha256(verdict_evidence(self.verdict)).hexdigest(),
            label=VERDICT_LABEL,
        )


def from_verdict_id(verdict_id: VerdictId) -> Justification:
    """A justification for a proposal built from an id alone.

    The path a `Proposal` takes when constructed with `verdict=` and no
    source object - which every caller through 0.5.0.0 does, and which the
    tests still do. The digest is empty because there is no evidence object
    to hash: an empty digest means "not computed here", never "computed and
    equal to nothing", and the type's consumers must treat it as absent.
    """
    return Justification(
        schema=ACCEPTED_VERDICT_SCHEMA,
        ref=str(verdict_id),
        digest="",
        label=VERDICT_LABEL,
    )
