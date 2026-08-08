"""Why an action is warranted, as a type the renderer and the grant carry.

Through 0.5.0.0 the answer was always "because a `cve-digest.verdict/1` item
said so", and `Proposal.verdict` held it directly. 0.6.0.0 made the *shape*
of an answer a type while there was still one implementation. 0.7.0.0 lands
the second implementation - an intercepted MCP `tools/call` - and with it the
consequence the earlier versions deferred: `verdict` is gone as a field,
because a field named `verdict` holding `mcp:tools/call#a1b2c3` is a lie in
the type system that propagates into the grant and into the ledger an auditor
reads (review finding F43).

A `Justification` carries four things, all of them in the hash preimage from
`pirx.proposal/2`:

  - ``schema`` - the contract id of the source. Never repurposed (P8).
  - ``ref`` - the identifier a human reads.
  - ``digest`` - SHA-256 over the source's own canonical evidence bytes, or
    empty when the proposal was built from a reference with no evidence
    object behind it. Empty means "not computed here", never "computed and
    equal to nothing".
  - ``extra`` - additional deterministic lines the source contributes, in the
    order it gives them. For the intercepted call these carry the tool name,
    the canonical arguments, and the hash of the tool definition in force at
    approval time, which is what makes a mid-approval definition swap a hash
    mismatch rather than a policy question (PT16).

Does NOT:
  - decide anything. A justification explains; it never selects an action, a
    target, or a parameter.
  - carry prose. Model or producer text travels as ``UntrustedProse`` in the
    proposal's fenced section (PT2). A source that wants to explain itself in
    sentences is refused here, not accommodated.
  - authenticate its source. Whether the evidence is genuine is the
    consumer's validation problem (PT1) and, for origin, PT14's acceptance.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Protocol

from .consumer import Verdict
from .errors import BoundsRefusal
from .types import (
    ACCEPTED_VERDICT_SCHEMA,
    INTERCEPTED_CALL_SCHEMA,
    MAX_CALL_ARGUMENT_CHARS,
    JustificationRef,
    VerdictId,
)

#: Field prefix in the rendered preimage. One prefix for every source, so a
#: reader who has seen one proposal can read a proposal from a source that did
#: not exist when they learned the format.
RENDER_PREFIX = "justification"

#: Printed where a digest is absent. A visible marker rather than an empty
#: value: a blank after a colon reads as a rendering bug, and a human should
#: not have to decide whether they are looking at one.
NO_DIGEST = "-"


@dataclass(frozen=True, slots=True)
class Justification:
    """One source's answer to "why is this action warranted?"."""

    schema: str
    ref: JustificationRef
    digest: str
    extra: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    def render_lines(self) -> tuple[str, ...]:
        """This source's contribution to the canonical preimage."""
        head = (
            f"{RENDER_PREFIX}.schema: {self.schema}",
            f"{RENDER_PREFIX}.ref: {self.ref}",
            f"{RENDER_PREFIX}.digest: {self.digest or NO_DIGEST}",
        )
        return head + tuple(
            f"{RENDER_PREFIX}.{key}: {value}" for key, value in self.extra
        )


class JustificationSource(Protocol):
    """Anything that can explain why an action is warranted."""

    def justify(self) -> Justification: ...


# --- Adapter #1: a cve-digest verdict ---------------------------------------


def verdict_evidence(verdict: Verdict) -> bytes:
    """Canonical evidence bytes for a verdict: deterministic fields only.

    Prose is excluded, not by oversight: a digest over model-authored text
    would make the evidence identity of a verdict depend on what a model wrote
    about it, and PT2 keeps prose out of every position where it could
    influence anything.
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
    """Adapter #1: a `cve-digest.verdict/1` item."""

    verdict: Verdict

    def justify(self) -> Justification:
        return Justification(
            schema=ACCEPTED_VERDICT_SCHEMA,
            ref=JustificationRef(str(self.verdict.verdict_id)),
            digest=hashlib.sha256(verdict_evidence(self.verdict)).hexdigest(),
        )


def verdict_justification(verdict_id: VerdictId) -> Justification:
    """A justification built from a verdict id with no evidence object.

    Used where a caller holds the id but not the parsed verdict. The digest is
    empty and renders as a visible marker, so a reader can tell "no evidence
    was hashed here" from "evidence was hashed and matched".
    """
    return Justification(
        schema=ACCEPTED_VERDICT_SCHEMA,
        ref=JustificationRef(str(verdict_id)),
        digest="",
    )


# --- Adapter #2: an intercepted MCP tool call -------------------------------


def canonical_arguments(arguments: dict[str, Any]) -> str:
    """One serialisation of a call's arguments: sorted keys, compact.

    The same string is hashed and shown, so an argument set that renders one
    way and executes another is not representable (P10, at the gate).
    """
    text = json.dumps(arguments, sort_keys=True, separators=(",", ":"))
    if len(text) > MAX_CALL_ARGUMENT_CHARS:
        raise BoundsRefusal(
            "intercepted call arguments exceed the render bound",
            chars=len(text),
            bound=MAX_CALL_ARGUMENT_CHARS,
        )
    return text


def call_evidence(
    tool: str, arguments: dict[str, Any], tool_definition_hash: str
) -> bytes:
    """Canonical evidence bytes for an intercepted call."""
    lines = [
        f"schema: {INTERCEPTED_CALL_SCHEMA}",
        f"tool: {tool}",
        f"tool_definition_hash: {tool_definition_hash}",
        f"arguments: {canonical_arguments(arguments)}",
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


@dataclass(frozen=True, slots=True)
class InterceptedCallSource:
    """Adapter #2: the `tools/call` request the gate is holding.

    The evidence *is* the request: there is no upstream ranking, no verdict,
    and nothing that ordered this action except the agent that asked for it.
    Naming that plainly is the point - a human approving a gated call is
    approving an agent's request, and the rendering says so rather than
    dressing the request up as a finding.

    ``tool_definition_hash`` enters the justification and therefore the action
    hash, so a tool whose definition changes between approval and execution
    invalidates every outstanding grant against it by construction rather than
    by policy (PT16).
    """

    tool: str
    arguments: dict[str, Any]
    tool_definition_hash: str

    def justify(self) -> Justification:
        evidence = call_evidence(self.tool, self.arguments, self.tool_definition_hash)
        digest = hashlib.sha256(evidence).hexdigest()
        return Justification(
            schema=INTERCEPTED_CALL_SCHEMA,
            ref=JustificationRef(f"mcp:tools/call#{digest[:16]}"),
            digest=digest,
            extra=(
                ("tool", self.tool),
                ("tool_definition_hash", self.tool_definition_hash),
                ("arguments", canonical_arguments(self.arguments)),
            ),
        )
