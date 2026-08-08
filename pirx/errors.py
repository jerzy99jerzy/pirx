"""The refusal taxonomy. One class per reason, each mapping 1:1 to a ledger
event name.

Every guardrail that declines to proceed raises one of these, and the runner
records it. The rule that makes this a module rather than a file of
boilerplate: **catching one of these anywhere except the top-level runner is
forbidden**, because a caught and suppressed refusal is a warning wearing a
refusal's name (family practice P11).

Does NOT:
  - define a warning type. There is no warning in this codebase. A condition
    that lets execution continue is not a control, so it does not get a name
    here.
  - carry remediation advice. A refusal says what happened and why; what to
    do about it is a human's call with the ledger in front of them.
"""

from __future__ import annotations

from typing import Any


class Refusal(Exception):
    """Base of every declined operation.

    ``event`` is the ledger event name; ``details`` are the structured fields
    the event carries. Subclasses set ``event`` and populate ``details``.
    """

    event: str = "refusal.unspecified"

    def __init__(self, message: str, **details: Any) -> None:
        super().__init__(message)
        self.message = message
        self.details: dict[str, Any] = details


# --- Consumer (PT1, PT11) ---------------------------------------------------


class SchemaRefusal(Refusal):
    event = "refusal.schema"


class BoundsRefusal(Refusal):
    event = "refusal.bounds"


class MalformedIdRefusal(Refusal):
    event = "refusal.malformed_id"


class EnumRefusal(Refusal):
    event = "refusal.enum"


# --- Proposer (PT13) --------------------------------------------------------


class BudgetRefusal(Refusal):
    event = "refusal.budget"


# --- Grant (PT3, PT4, PT5, PT6) ---------------------------------------------


class HashMismatchRefusal(Refusal):
    event = "refusal.hash_mismatch"


class TargetMismatchRefusal(Refusal):
    event = "refusal.target_mismatch"


class ExpiredGrantRefusal(Refusal):
    event = "refusal.expired_grant"


class SpentGrantRefusal(Refusal):
    event = "refusal.spent_grant"


class DeclinedRefusal(Refusal):
    event = "refusal.declined"


# --- Attention (PT15) -------------------------------------------------------


class ChallengeFailedRefusal(Refusal):
    """The approver's transcription does not match the rendered bytes.

    The event names the challenged field, never the expected value: the value
    is on the approver's screen inside the canonical frame, and a ledger that
    repeats it would teach a reader that the answer lives in the ledger.
    """

    event = "refusal.challenge_failed"


class ReadingFloorRefusal(Refusal):
    event = "refusal.reading_floor"


class SessionBudgetRefusal(Refusal):
    event = "refusal.session_budget"


# --- Grant transport (0.7.0.0) ----------------------------------------------


class MalformedGrantRefusal(Refusal):
    """A transported grant whose shape is wrong.

    Distinct from a MAC failure: shape is checked before authenticity so that
    a malformed file cannot reach the comparison at all, and so the ledger
    distinguishes "someone wrote junk here" from "someone forged a grant".
    """

    event = "refusal.malformed_grant"


class GrantMacRefusal(Refusal):
    event = "refusal.grant_mac"


# --- Gate transport (0.7.0.0) -----------------------------------------------


class ProtocolRefusal(Refusal):
    """A JSON-RPC message the gate cannot establish the meaning of."""

    event = "refusal.protocol"


class UnsupportedProtocolVersionRefusal(Refusal):
    event = "refusal.protocol_version"


class HeaderMismatchRefusal(Refusal):
    """Routing headers disagree with the body (PT20).

    Refused rather than normalised: the body is what gets hashed, shown, and
    executed, so a header that says something else is either a bug in a
    client or an attempt to have the gate reason about one message while
    forwarding another.
    """

    event = "refusal.header_mismatch"


class ToolDefinitionDriftRefusal(Refusal):
    event = "refusal.tool_definition_drift"


# --- Registry (PT7) ---------------------------------------------------------


class UnregisteredActionRefusal(Refusal):
    event = "refusal.unregistered_action"


class AdapterUnavailableRefusal(Refusal):
    """A registered capability with no adapter wired, or an unhealthy one.

    Refusing here rather than at import time means a clone with no
    credentials runs the whole loop and stops at the write, which is the
    safe default and also the honest demonstration.
    """

    event = "refusal.adapter_unavailable"


# --- Model boundary (PT2) ---------------------------------------------------


class ModelRefusal(Refusal):
    """The model returned something outside its contract, or not at all.

    A refusal, not a fallback: silently reverting to the deterministic
    proposer would hide from the approving human which mind produced what
    they are reading.
    """

    event = "refusal.model"


# --- Ledger (PT9) -----------------------------------------------------------


class LedgerChainRefusal(Refusal):
    event = "refusal.ledger_chain"
