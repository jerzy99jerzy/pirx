"""The ``Proposal`` type and the canonical renderer.

Rendering is one pure function. The bytes it returns are simultaneously what a
human reads and what the action hash covers, so "what was shown" and "what was
hashed" cannot diverge (PT6, family practice P10).

Format, deliberately plain text rather than JSON so a human reads it without a
tool:

  - one field per line, ``key: value``, fixed order;
  - untrusted prose enclosed in a fence, labelled with its origin and its
    declared length, escaped to a single line so it cannot forge a field
    line even if it contains newlines and colons;
  - a trailing ``bytes:`` marker giving the length of everything above it, so
    truncation of the display is visible to the reader.

**The fence** (0.4.0.0, the entry condition for admitting a model). Escaping
already prevented prose from creating its own line. The fence adds the thing
escaping cannot: an unambiguous, labelled boundary telling a reader where
text authored on the far side of the trust boundary begins and ends. Its tag
is chosen deterministically as the shortest ``~~~pirx-untrusted-N`` not
occurring in the enclosed text, so it is unforgeable by content and identical
for identical input - the frame lesson from the approval surface, applied
inside the hash preimage where a random boundary would destroy determinism.
The enclosed line is indented, so no content line can even begin with the
fence base: unambiguous to a parser by the tag, and unambiguous to a human by
the indent.

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

from .justification import Justification
from .types import (
    PROPOSAL_RENDER_SCHEMA,
    ActionHash,
    TargetId,
    UntrustedProse,
)

#: Fence tag base. `N` increments until the tag is absent from the text, so
#: prose containing the base string cannot close its own fence.
FENCE_BASE = "~~~pirx-untrusted-"

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


def prose_fence(text: str) -> str:
    """Shortest fence tag not present in ``text``. Deterministic."""
    index = 0
    while f"{FENCE_BASE}{index}" in text:
        index += 1
    return f"{FENCE_BASE}{index}"


@dataclass(frozen=True, slots=True)
class Proposal:
    action: str
    target: TargetId
    #: Why this action is warranted, in the form the renderer prints and the
    #: action hash covers. Required: there is no proposal without a reason,
    #: and from 0.7.0.0 the reason is not assumed to be a verdict (F43).
    justification: Justification
    params: Mapping[str, str]
    prose: Mapping[str, UntrustedProse] = field(default_factory=dict)
    #: Where each prose field came from, shown to the human inside the fence.
    #: "producer" is Rappaport's summary; "pirx-model" is this project's own
    #: model. A reader should never have to guess which mind wrote a sentence
    #: they are being asked to act on.
    prose_origin: Mapping[str, str] = field(default_factory=dict)

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
    ]
    # The source owns what its evidence is called and what it contributes;
    # the renderer owns order, escaping, and the hash (ARCHITECTURE A18).
    lines.extend(proposal.justification.render_lines())
    for key in sorted(proposal.params):
        lines.append(f"param.{key}: {proposal.params[key]}")
    for key in sorted(proposal.prose):
        escaped = escape_prose(proposal.prose[key].text)
        fence = prose_fence(escaped)
        lines.append(
            f"{fence} begin {key} "
            f"(origin={proposal.prose_origin.get(key, 'unknown')}, "
            f"chars={len(escaped)}, escaped, NOT a decision input)"
        )
        # Two-space indent so an enclosed line can never *begin* with the
        # fence base. The incrementing tag already made the block
        # machine-unambiguous; this makes it unambiguous to a human scanning
        # the terminal, which is the reader the fence exists for.
        lines.append(f"  {escaped}")
        lines.append(f"{fence} end {key}")
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
