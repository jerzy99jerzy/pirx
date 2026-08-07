"""The approval surface. A terminal, because it cannot claim UI affordances
it does not have.

What this module writes to stdout contains the canonical bytes **verbatim**,
between two documented frame markers. A test captures stdout and compares the
framed region byte-for-byte against the hash preimage, so the claim "the human
saw what was hashed" is measured rather than argued (PT6, family practice P7).

The proposal age is printed and labelled. Grant expiry (PT4) starts at issue,
which happens *after* the human decides, so a human returning to a terminal
hours later is approving a stale proposal rather than spending a stale grant.
The age line is a decision-quality aid, not an integrity control, and the
output says so in those terms.

Does NOT:
  - summarise, colour, reorder, elide, or wrap. Any of those would make the
    displayed bytes differ from the hashed bytes.
  - accept a single keystroke. The token is the full word ``approve``,
    because a habituated ``y`` is approval fatigue in miniature (PT13,
    ARCHITECTURE A6).
  - offer a bulk affordance. One proposal, one prompt, one decision (PT12).
  - authenticate the approver. ``approver_claim`` is taken from the process
    environment and carried with ``authenticated: false``.
"""

from __future__ import annotations

import getpass
import re
import secrets
from collections.abc import Callable
from typing import TextIO

from .grant import ApprovalDecision
from .proposal import RenderedProposal

# The frame boundary is random per presentation, MIME-style. A fixed marker is
# forgeable: producer prose containing the closing token would make a reader
# believe the artefact ended before it did, which is PT6 by content rather
# than by divergence. Prose cannot predict 128 bits generated after it exists.
FRAME_OPEN_TEMPLATE = (
    "--- begin canonical proposal bytes [{b}] (these are the hashed bytes) ---"
)
FRAME_CLOSE_TEMPLATE = "--- end canonical proposal bytes [{b}] ---"
_OPEN_PATTERN = re.compile(
    r"^--- begin canonical proposal bytes \[([0-9a-f]{32})\] .*---$", re.MULTILINE
)

APPROVE_TOKEN = "approve"
DECLINE_TOKEN = "decline"


def approver_claim() -> str:
    """Unauthenticated identity claim from the environment."""
    try:
        return getpass.getuser()
    except Exception:  # pragma: no cover - environment dependent
        return "unknown"


def present(
    rendered: RenderedProposal, age_seconds: float, out: TextIO
) -> str:
    """Write the frame. The canonical bytes appear inside it, unmodified.

    Returns the frame boundary, which is fresh for every presentation.
    """
    boundary = secrets.token_hex(16)
    out.write(FRAME_OPEN_TEMPLATE.format(b=boundary) + "\n")
    out.write(rendered.canonical_bytes.decode("utf-8"))
    out.write(FRAME_CLOSE_TEMPLATE.format(b=boundary) + "\n")
    out.write(f"action hash: {rendered.action_hash}\n")
    out.write(f"target: {rendered.proposal.target}\n")
    out.write(
        f"proposal age: {age_seconds:.1f}s "
        "(decision aid; not covered by the hash, not an integrity control)\n"
    )
    out.write(
        f"type '{APPROVE_TOKEN}' or '{DECLINE_TOKEN}' "
        "(no single-key shortcut, by design): "
    )
    out.flush()
    return boundary


def decide(
    rendered: RenderedProposal,
    age_seconds: float,
    out: TextIO,
    read_line: Callable[[], str],
) -> ApprovalDecision:
    """Present once, read one answer. Anything but the approve token declines."""
    present(rendered, age_seconds, out)
    answer = read_line().strip().lower()
    out.write("\n")
    return ApprovalDecision(
        approved=answer == APPROVE_TOKEN,
        action_hash=rendered.action_hash,
        target=rendered.proposal.target,
        approver_claim=approver_claim(),
        authenticated=False,
    )


def extract_framed(stdout_text: str) -> bytes:
    """Recover the framed canonical bytes from captured output.

    The boundary is read from the **first** opening line, which the surface
    wrote before any producer prose reached the stream. Prose appearing later
    cannot name that boundary, so a forged closing marker cannot truncate the
    extracted region.

    Ships in the module rather than in the test so the frame contract has one
    definition; the test asserts against the hash preimage, not against this
    function's idea of the frame.
    """
    match = _OPEN_PATTERN.search(stdout_text)
    if match is None:
        raise ValueError("no canonical frame in output")
    boundary = match.group(1)
    start = match.end() + 1
    close = FRAME_CLOSE_TEMPLATE.format(b=boundary)
    end = stdout_text.index(close, start)
    return stdout_text[start:end].encode("utf-8")
