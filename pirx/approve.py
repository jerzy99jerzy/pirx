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

**The attention layer (0.5.0.0, PT15).** Between the frame and the decision
sits a content-derived challenge: the approver transcribes one deterministic
field, selected by the action hash from ``CHALLENGE_FIELDS``, so the field
cannot be predicted before the canonical bytes exist and a cached answer from
another proposal fails unless the values happen to coincide. An approving
answer arriving faster than a floor derived from the byte length is refused.
Both refusals are typed events; both are re-verified at grant issuance, so
this surface is where attention is *measured*, not the only place it is
*enforced*.

Does NOT:
  - summarise, colour, reorder, elide, or wrap. Any of those would make the
    displayed bytes differ from the hashed bytes.
  - accept a single keystroke. The token is the full word ``approve``,
    because a habituated ``y`` is approval fatigue in miniature (PT13,
    ARCHITECTURE A6).
  - offer a bulk affordance. One proposal, one prompt, one decision (PT12).
  - authenticate the approver. ``approver_claim`` is taken from the process
    environment and carried with ``authenticated: false``.
  - claim comprehension. The challenge proves the approver located content
    in the exact hashed bytes; "understood" is a claim no measurement here
    supports, and the wording throughout says "read", deliberately (P7).
  - challenge prose. Only deterministic fields are challengeable; making a
    human transcribe producer prose would hand untrusted text an expected
    value on this side of the fence (PT2).
  - floor-check a decline. Refusing fast is not the threat.
"""

from __future__ import annotations

import getpass
import re
import secrets
import time
from collections.abc import Callable
from typing import TextIO

from .errors import ChallengeFailedRefusal, ReadingFloorRefusal
from .grant import ApprovalDecision, AttentionEvidence
from .proposal import RenderedProposal
from .types import (
    CHALLENGE_FIELDS,
    READING_FLOOR_BASE_SECONDS,
    READING_FLOOR_SECONDS_PER_KIB,
)

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
    out.flush()
    return boundary


def reading_floor_seconds(byte_length: int) -> float:
    """Floor for an approving answer, from the length of the hashed bytes.

    A lower bound that catches reflexive approval; deliberately far below an
    honest reading time, because a floor dressed up as proof of reading would
    be theatre (PT15, P7).
    """
    return READING_FLOOR_BASE_SECONDS + READING_FLOOR_SECONDS_PER_KIB * (
        byte_length / 1024
    )


def challenge_field(rendered: RenderedProposal) -> str:
    """The field the approver must transcribe, selected by the action hash.

    Deterministic per proposal, unpredictable before the canonical bytes
    exist: the hash covers the bytes, so nothing upstream can steer which
    field will be challenged without changing what the human is shown.
    """
    return CHALLENGE_FIELDS[int(rendered.action_hash, 16) % len(CHALLENGE_FIELDS)]


def expected_transcription(rendered: RenderedProposal, field: str) -> str:
    """The value the approver must transcribe, as the rendering prints it.

    ``justification`` resolves to the reference line rather than the whole
    object: it is the identifier a human can locate by eye in the frame, and
    asking someone to retype a 64-character digest would train them to copy
    and paste, which is the habit the challenge exists to break.
    """
    if field == "justification":
        return str(rendered.proposal.justification.ref)
    return str(getattr(rendered.proposal, field))


def decide(
    rendered: RenderedProposal,
    age_seconds: float,
    out: TextIO,
    read_line: Callable[[], str],
    clock: Callable[[], float] = time.monotonic,
    on_challenge: Callable[[str], None] | None = None,
) -> ApprovalDecision:
    """Present, challenge, read one answer. Anything but the token declines.

    ``on_challenge`` is called with the challenged field name after the
    prompt is written and **before** the human answers, so a caller can
    record intent ahead of the action (the ledger discipline PT9 rests on).

    Raises ``ChallengeFailedRefusal`` when the transcription does not match
    the rendered bytes, and ``ReadingFloorRefusal`` when an *approving*
    answer arrives below the floor. Both leave no decision behind: the
    proposal must be presented again from the top.
    """
    presented_at = clock()
    present(rendered, age_seconds, out)

    field = challenge_field(rendered)
    out.write(
        f"attention challenge - transcribe the value of '{field}' "
        "exactly as rendered above: "
    )
    out.flush()
    if on_challenge is not None:
        on_challenge(field)
    transcription = read_line().strip()
    if transcription != expected_transcription(rendered, field):
        out.write("\n")
        raise ChallengeFailedRefusal(
            "transcription does not match the rendered bytes",
            action_hash=rendered.action_hash,
            field=field,
        )

    out.write(
        f"type '{APPROVE_TOKEN}' or '{DECLINE_TOKEN}' "
        "(no single-key shortcut, by design): "
    )
    out.flush()
    answer = read_line().strip().lower()
    out.write("\n")

    approved = answer == APPROVE_TOKEN
    elapsed = clock() - presented_at
    floor = reading_floor_seconds(len(rendered.canonical_bytes))
    if approved and elapsed < floor:
        raise ReadingFloorRefusal(
            "approval arrived below the reading floor",
            action_hash=rendered.action_hash,
            elapsed_seconds=round(elapsed, 3),
            floor_seconds=round(floor, 3),
        )
    return ApprovalDecision(
        approved=approved,
        action_hash=rendered.action_hash,
        target=rendered.proposal.target,
        approver_claim=approver_claim(),
        attention=AttentionEvidence(
            challenge_field=field,
            challenge_passed=True,
            elapsed_seconds=elapsed,
            floor_seconds=floor,
        ),
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
