"""The gate: a tools/call is forwarded only under a bound, attentive grant.

Placement, and why it is this shape. The gate sits between an agent host and
a downstream MCP server. A call naming a tool in the **gated registry** is
held: the gate renders a canonical proposal from the request itself (adapter
#2), writes it where the approval surface will find it, and answers the
caller with a Multi Round-Trip Request poll ticket. When a human has approved
those exact bytes on Pirx's own surface, a grant appears in the grant
directory; the next retry verifies it, spends it durably, and forwards the
**original request bytes** unaltered.

Three rules that are the whole design, stated before the code:

1. **The body is authoritative.** Gating decisions and the justification
   derive from the parsed body, never from routing headers (PT20). What is
   hashed is what is forwarded: the gate re-emits the bytes it received
   rather than a re-serialisation of its own understanding of them.
2. **MRTR is a poll ticket, never an approval channel.** The gate may tell
   the caller "approval is pending, retry", correlated by an opaque id in
   ``requestState``. It must never place the rendered proposal, the attention
   challenge, or any field capable of carrying an approval token into
   ``inputRequests``, and it must never read ``inputResponses`` as evidence
   of approval. MRTR renders in the calling agent's host - the trust domain
   of the party under review - so an approval delivered through it would be
   PT6 one layer up (PT17).
3. **The gate cannot prevent its own bypass, and says so.** An agent host
   that launches the downstream server directly reaches it without passing
   here. Prevention lives in the environment: downstream credentials held
   only in the gate's environment, and the identity launcher's attributable
   process. What the gate provides is evidence - a forwarded action with no
   grant event has no ledger trail, which is what makes bypass detectable
   (PT18).

Does NOT:
  - implement a policy engine. The gated registry is a reviewed-in-code
    tuple. There is no risk score, no rule language, no "this DELETE looks
    fine". That market is taken and it is not what this project sells.
  - inspect payloads for injection or PII. Adjacent products do that.
  - auto-approve anything, ever, including on retry storms. The pass-through
    lane is *ungated*, which is a registry decision reviewed like code, not
    an approval that was skipped.
  - hold state between calls. The gate keeps no session; a pending proposal
    is a file, and the ticket that names it is opaque to the caller.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..errors import Refusal, ToolDefinitionDriftRefusal
from ..grant import Grant, GrantIssuer, SpentGrant
from ..justification import InterceptedCallSource
from ..ledger import Ledger
from ..proposal import Proposal, RenderedProposal, prepare
from ..types import TargetId
from .protocol import Request, parse_request

#: Forwarded downstream, unaltered. Injected so tests drive the gate without
#: a subprocess and so the transport stays visible at the wiring site.
Transport = Callable[[bytes], bytes]

#: The action name a gated tool call proposes. One name, in code: the gate
#: does not invent an action vocabulary from tool names, because a name
#: derived from an untrusted catalogue is a name an attacker chooses.
GATED_ACTION = "mcp.tool_call"


@dataclass(frozen=True, slots=True)
class GatedTool:
    """One tool the gate holds for approval. Reviewed like code."""

    tool: str
    #: Fingerprint of the tool definition this entry was reviewed against.
    #: A downstream definition that no longer matches is drift, refused
    #: rather than re-approved silently (PT16).
    definition_hash: str


class GatedRegistry:
    """The gated write surface, as data. Never loaded from configuration."""

    def __init__(self, entries: tuple[GatedTool, ...] = ()) -> None:
        self._entries = {entry.tool: entry for entry in entries}

    def __contains__(self, tool: object) -> bool:
        return tool in self._entries

    def tools(self) -> tuple[str, ...]:
        return tuple(sorted(self._entries))

    def require(self, tool: str, observed_hash: str) -> GatedTool:
        entry = self._entries[tool]
        if entry.definition_hash != observed_hash:
            raise ToolDefinitionDriftRefusal(
                "tool definition changed since it was reviewed",
                tool=tool, reviewed=entry.definition_hash[:16],
                observed=observed_hash[:16],
            )
        return entry


#: Empty in 0.7.0.0, exactly as the capability registry was empty in
#: 0.1.0.0: the machinery ships and is attacked before it guards anything
#: (P3). An operator registers a tool by editing code and reviewing the
#: change, having pinned the definition hash they reviewed.
PRODUCTION_GATED_REGISTRY = GatedRegistry()


@dataclass(frozen=True, slots=True)
class PendingProposal:
    """A rendered proposal waiting for a human, as a file on disk."""

    ticket: str
    action_hash: str
    canonical_bytes: bytes

    def to_json(self) -> bytes:
        return json.dumps(
            {
                "ticket": self.ticket,
                "action_hash": self.action_hash,
                "canonical": self.canonical_bytes.decode("utf-8"),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")


class Gate:
    """One gate: one registry, one ledger, one grant directory."""

    def __init__(
        self,
        registry: GatedRegistry,
        ledger: Ledger,
        issuer: GrantIssuer,
        transport: Transport,
        pending_dir: Path,
        grants_dir: Path,
        definition_hashes: dict[str, str] | None = None,
    ) -> None:
        self.registry = registry
        self.ledger = ledger
        self.issuer = issuer
        self.transport = transport
        self.pending_dir = pending_dir
        self.grants_dir = grants_dir
        self.pending_dir.mkdir(parents=True, exist_ok=True)
        self.grants_dir.mkdir(parents=True, exist_ok=True)
        #: Fingerprints the gate computed itself from `tools/list`. Never a
        #: cached catalogue supplied by a client (PT16).
        self.definition_hashes = definition_hashes or {}

    # --- proposal construction ---------------------------------------------

    def proposal_for(self, request: Request) -> RenderedProposal:
        """Build the canonical proposal for a gated call.

        The target is the tool: one grant, one tool, one argument set. A
        grant for `repo.write_file` with these arguments cannot be spent on
        the same tool with different ones, because the arguments are inside
        the justification and therefore inside the hash (PT5 at the gate).
        """
        tool = request.tool or ""
        observed = self.definition_hashes.get(tool, "")
        entry = self.registry.require(tool, observed)
        justification = InterceptedCallSource(
            tool=entry.tool,
            arguments=request.arguments,
            tool_definition_hash=entry.definition_hash,
        ).justify()
        return prepare(
            Proposal(
                action=GATED_ACTION,
                target=TargetId(f"mcp:{entry.tool}"),
                justification=justification,
                params={
                    "tool": entry.tool,
                    "client_claim": request.client_claim,
                    "protocol_version": request.protocol_version,
                },
            )
        )

    # --- the pending queue --------------------------------------------------

    def _ticket_for(self, rendered: RenderedProposal) -> str:
        """Opaque to the caller, deterministic for the gate.

        Derived from the action hash rather than randomly, so a client that
        retries an identical call polls the same ticket instead of flooding
        the queue with duplicates - and so a ticket reveals nothing about the
        proposal it names beyond the fact that one exists.
        """
        return str(rendered.action_hash)[:32]

    def record_pending(self, rendered: RenderedProposal) -> PendingProposal:
        pending = PendingProposal(
            ticket=self._ticket_for(rendered),
            action_hash=str(rendered.action_hash),
            canonical_bytes=rendered.canonical_bytes,
        )
        path = self.pending_dir / f"{pending.ticket}.json"
        if not path.exists():
            path.write_bytes(pending.to_json())
            self.ledger.append(
                "gate.pending",
                ticket=pending.ticket,
                action_hash=pending.action_hash,
                byte_length=len(pending.canonical_bytes),
            )
        return pending

    def find_grant(self, rendered: RenderedProposal) -> Grant | None:
        """Look for a grant covering exactly these bytes.

        Reads by filename, which is the action hash: the gate never searches
        for "a grant that might do", and a grant for another proposal is not
        found rather than considered and rejected.
        """
        path = self.grants_dir / f"{rendered.action_hash}.json"
        if not path.exists():
            return None
        return Grant.from_json(path.read_bytes())

    # --- the data path ------------------------------------------------------

    def handle(self, raw: bytes, headers: dict[str, str] | None = None) -> bytes:
        """One request in, one response out. Never raises a Refusal at the
        caller: a refusal becomes a JSON-RPC error, recorded first."""
        try:
            request = parse_request(raw, headers)
        except Refusal as exc:
            self._record_refusal(exc)
            return _error(None, -32020, exc.message)

        if not request.is_tool_call or request.tool not in self.registry:
            self.ledger.append(
                "gate.forwarded_ungated",
                method=request.method,
                tool=request.tool,
                client_claim=request.client_claim,
            )
            return self.transport(raw)

        try:
            rendered = self.proposal_for(request)
        except Refusal as exc:
            self._record_refusal(exc)
            return _error(request.id, -32020, exc.message)

        pending = self.record_pending(rendered)
        grant = self.find_grant(rendered)
        if grant is None:
            self.ledger.append(
                "gate.awaiting_approval",
                ticket=pending.ticket, action_hash=pending.action_hash,
            )
            return _input_required(request.id, pending.ticket)

        try:
            spent = self.spend(grant, rendered)
        except Refusal as exc:
            self._record_refusal(exc)
            return _error(request.id, -32020, exc.message)

        self.ledger.append(
            "gate.forwarded_granted",
            ticket=pending.ticket,
            action_hash=pending.action_hash,
            nonce=str(spent.grant.nonce),
            tool=request.tool,
        )
        # The bytes as received, not a re-serialisation: what the human
        # approved is what the downstream server sees.
        return self.transport(raw)

    def spend(self, grant: Grant, rendered: RenderedProposal) -> SpentGrant:
        return self.issuer.spend(
            grant, rendered.action_hash, rendered.proposal.target
        )

    def _record_refusal(self, exc: Refusal) -> None:
        self.ledger.append(exc.event, **exc.details, message=exc.message)


def _error(request_id: Any, code: int, message: str) -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": code, "message": message},
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _input_required(request_id: Any, ticket: str) -> bytes:
    """The MRTR poll ticket (PT17).

    Carries the ticket and nothing else. No proposal bytes, no challenge, no
    field a client could fill with an approval - the client learns only that
    a human decision is outstanding and that retrying is how it finds out.
    """
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "resultType": "input_required",
                "inputRequests": [
                    {
                        "type": "notice",
                        "message": (
                            "pirx: human approval pending out-of-band; "
                            "retry this request to learn the outcome"
                        ),
                    }
                ],
                "requestState": {"pirx.ticket": ticket},
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
