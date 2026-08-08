"""Identifier types, the untrusted-prose wrapper, and security constants.

Does NOT:
  - define any behaviour. This module is deliberately inert so that every
    other module can import it without creating a cycle.
  - expose any of the constants below as configuration. A limit that exists
    for a security reason is a constant in code (family practice P6); a
    configurable limit is a disabled limit on the day someone is in a hurry.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import NewType

# --- Identifier types -------------------------------------------------------
# Distinct NewType wrappers cost nothing at runtime and let a type checker
# refuse the whole class of "target id checked against verdict id" bugs at the
# desk instead of in the harness. (ARCHITECTURE A1.)

CveId = NewType("CveId", str)
VerdictId = NewType("VerdictId", str)
TargetId = NewType("TargetId", str)
ActionHash = NewType("ActionHash", str)
GrantNonce = NewType("GrantNonce", str)
#: The identifier a justification names. Distinct from VerdictId because a
#: verdict id is one possible value and the type must not imply it is the
#: only one (0.7.0.0, review finding F43).
JustificationRef = NewType("JustificationRef", str)


# --- Untrusted prose --------------------------------------------------------


@dataclass(frozen=True, slots=True)
class UntrustedProse:
    """Model-authored text from the far side of a trust boundary.

    Wrapping producer prose in its own type is how PT2 is enforced in every
    module at once: a function that takes a ``str`` parameter cannot be handed
    an ``UntrustedProse`` by accident, so prose cannot reach an action
    parameter without a deliberate, visible ``.text`` access that a reviewer
    will see.

    Does NOT:
      - carry any parsed meaning. There is no ``.keywords``, no ``.intent``,
        no ``.suggested_action``. Prose is display material and hash input,
        never a decision input.
      - guarantee its content is safe to render raw. Escaping happens in the
        renderer, which is the only module that turns anything into bytes for
        a human.
    """

    text: str

    def __str__(self) -> str:  # pragma: no cover - defensive
        raise TypeError(
            "UntrustedProse must not be interpolated implicitly; "
            "use .text at an explicit, reviewable call site"
        )


# --- Security constants -----------------------------------------------------

#: Longest producer prose field retained. Truncation happens at parse time,
#: not at render time, so nothing downstream ever holds the oversized value.
MAX_PROSE_CHARS = 2_000

#: Hard proposal budget per run (PT13). Consumed in the producer's ranking
#: order, so overflow can only ever drop the tail of the ranking.
MAX_PROPOSALS_PER_RUN = 10

#: Grant lifetime, measured on the monotonic clock (PT4).
GRANT_TTL_SECONDS = 300.0

#: Reading floor (PT15): minimum seconds between presenting the canonical
#: bytes and an *approving* answer, derived from byte length. Chosen to catch
#: reflexive approval, not to prove reading - a floor high enough to prove
#: reading would be theatre, and the honest claim is the lower bound only.
#: Declining is never floor-checked: refusing fast is not the threat.
READING_FLOOR_BASE_SECONDS = 2.0
READING_FLOOR_SECONDS_PER_KIB = 2.0

#: Session grant budget (PT15): grants issued by one issuer before it refuses.
#: In the single-run topology the PT13 proposal budget (10) binds first, so
#: this constant's bite arrives with a long-lived approval surface (the gate,
#: 0.7.0.0). The primitive ships and is attacked now, per family practice P3.
MAX_GRANTS_PER_SESSION = 20

#: Attention-challenge field pool (PT15). The field the approver must
#: transcribe is selected from this tuple by the action hash, so it cannot be
#: predicted before the canonical bytes exist. Every entry names a
#: deterministic ``Proposal`` attribute that the renderer prints verbatim;
#: prose is never challengeable, because transcribing untrusted prose would
#: put producer text into the approver's hands as an expected value (PT2).
CHALLENGE_FIELDS: tuple[str, ...] = ("target", "justification", "action")

#: Canonical schema id this version consumes. Any other value is refused,
#: never coerced (PT1).
ACCEPTED_VERDICT_SCHEMA = "cve-digest.verdict/1"

#: Ledger chain genesis preimages. Documented and fixed so a verifier can
#: distinguish a fresh ledger from one whose head was replaced (PT9). The /2
#: sentinel arrives with 0.7.0.0, where event fields stop saying "verdict"
#: and start saying "justification". `/1` is not redefined and stays
#: verifiable: an auditor's query against field names is a consumer of this
#: format, and a hash chain nobody can still verify is not an audit trail.
#: Current ledger format id, carried in `run.started` so a reader does not
#: have to infer it from a sentinel.
LEDGER_SCHEMA = "pirx.ledger/2"
LEDGER_GENESIS_SENTINEL_V1 = b"pirx.ledger/1 genesis"
LEDGER_GENESIS_SENTINEL = b"pirx.ledger/2 genesis"

#: Wire format id for the canonical proposal rendering. Bumped to /2 at
#: 0.7.0.0: the justification's schema, reference, and evidence digest enter
#: the preimage, so every action hash changes. A new id, never a redefinition
#: of /1 (P8).
PROPOSAL_RENDER_SCHEMA = "pirx.proposal/2"


# --- Gate constants (0.7.0.0) -----------------------------------------------

#: Justification schema for an intercepted MCP tool call.
INTERCEPTED_CALL_SCHEMA = "pirx.intercepted-call/1"

#: MCP protocol revisions this gate parses. An unknown revision is refused,
#: never best-effort parsed: the gate reads a request in order to decide
#: whether a human must approve it, and a version it does not understand is a
#: request whose meaning it cannot establish (PT1 discipline, transport tier).
SUPPORTED_MCP_PROTOCOL_VERSIONS: tuple[str, ...] = ("2026-07-28",)

#: Longest canonical argument JSON retained from an intercepted call. Bounds
#: what a human is asked to read as much as what the process holds.
MAX_CALL_ARGUMENT_CHARS = 4_000

#: Environment variable naming the file that holds the grant HMAC key. The
#: key is read by the approval surface and by the gate; nothing under
#: `model/` may reach either, which the import scrape enforces.
GRANT_KEY_ENV = "PIRX_GRANT_KEY_FILE"

#: Minimum accepted key length. A short key is a long key that was never
#: generated properly, and this is a constant rather than a warning.
MIN_GRANT_KEY_BYTES = 32
