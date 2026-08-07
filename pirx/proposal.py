"""The ``Proposal`` type and the canonical renderer.

Rendering is one pure function. The bytes it returns are simultaneously what a
human reads and what the action hash covers, so "what was shown" and "what was
hashed" cannot diverge (PT6, family practice P10).

Format, deliberately plain text rather than JSON so a human reads it without a
tool:

  - one field per line, ``key: value``, fixed order;
  - producer prose escaped to a single line and indented two spaces under a
    header that states its declared length, so prose cannot forge a field
    line even if it contains newlines and colons;
  - a trailing ``bytes:`` marker giving the length of everything above it, so
    truncation of the display is visible to the reader.

Does NOT:
  - render differently for display and for hashing. There is exactly one
    output; the hash function takes the bytes, never the object, so a second
    serialisation cannot drift into existence.
  - accept prose in any parameter position. ``params`` is a mapping of
    deterministic values only; the constructor rejects ``UntrustedProse``
    there outright (PT2).
  - decide anything. Ordering, budget, and action selection happen upstream.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field

from .types import (
    PROPOSAL_RENDER_SCHEMA,
    ActionHash,
    TargetId,
    UntrustedProse,
    VerdictId,
)

_ESCAPES = {
    ord("\\"): "\\\\",
    ord("\n"): "\\n",
    ord("\r"): "\\r",
    ord("\t"): "\\t",
}


def escape_prose(text: str) -> str:
    """Collapse producer prose to one printable line.

    Newlines become literal ``\\n``; control characters become ``\\xNN``.
    After this, prose cannot introduce a line that looks like a field.
    """
    out: list[str] = []
    for ch in text:
        code = ord(ch)
        if code in _ESCAPES:
            out.append(_ESCAPES[code])
        elif code < 0x20 or code == 0x7F:
            out.append(f"\\x{code:02x}")
        else:
            out.append(ch)
    return "".join(out)


@dataclass(frozen=True, slots=True)
class Proposal:
    action: str
    target: TargetId
    verdict: VerdictId
    params: Mapping[str, str]
    prose: Mapping[str, UntrustedProse] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for key, value in self.params.items():
            if isinstance(value, UntrustedProse):
                raise TypeError(
                    f"param {key!r} holds producer prose; action parameters "
                    "come from deterministic fields only (PT2)"
                )
            if not isinstance(value, str):
                raise TypeError(f"param {key!r} is not a string")


@dataclass(frozen=True, slots=True)
class RenderedProposal:
    proposal: Proposal
    canonical_bytes: bytes
    action_hash: ActionHash


def render(proposal: Proposal) -> bytes:
    """The single canonical serialisation. Pure; same input, same bytes."""
    lines: list[str] = [
        PROPOSAL_RENDER_SCHEMA,
        f"action: {proposal.action}",
        f"target: {proposal.target}",
        f"verdict: {proposal.verdict}",
    ]
    for key in sorted(proposal.params):
        lines.append(f"param.{key}: {proposal.params[key]}")
    for key in sorted(proposal.prose):
        escaped = escape_prose(proposal.prose[key].text)
        lines.append(f"prose.{key} (chars={len(escaped)}, escaped, untrusted):")
        lines.append(f"  {escaped}")
    body = ("\n".join(lines) + "\n").encode("utf-8")
    return body + f"bytes: {len(body)}\n".encode()


def action_hash(canonical: bytes) -> ActionHash:
    """SHA-256 over the rendered bytes. Takes bytes, never the object."""
    return ActionHash(hashlib.sha256(canonical).hexdigest())


def prepare(proposal: Proposal) -> RenderedProposal:
    canonical = render(proposal)
    return RenderedProposal(
        proposal=proposal,
        canonical_bytes=canonical,
        action_hash=action_hash(canonical),
    )
