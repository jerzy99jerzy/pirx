"""MCP messages, parsed as hostile input.

The gate reads a request in order to decide whether a human must approve it.
That makes every field in the request an input to a security decision, and
this module is the consumer discipline of `consumer.py` applied one tier
down: shape validated, versions enumerated, nothing coerced, nothing guessed.

Written against specification revision **2026-07-28**, read at source. Three
properties of that revision shape this module:

  - **Statelessness.** The `initialize`/`initialized` handshake and the
    `Mcp-Session-Id` header are gone; each request carries its own protocol
    version in ``_meta``. There is no session for authority to accumulate in,
    which suits a design whose thesis is that authority does not accumulate.
  - **Header-based routing.** Streamable HTTP requests carry ``Mcp-Method``
    and ``Mcp-Name`` so gateways can route without parsing bodies. This gate
    parses the body anyway and refuses any disagreement (PT20): the body is
    what gets hashed, shown, and executed, so a routing header that says
    something else is either a client bug or an attempt to have the gate
    reason about one message while forwarding another.
  - **Multi Round-Trip Requests.** A server may answer with
    ``resultType: "input_required"`` and the client retries with responses
    attached. The gate uses this as a *poll ticket* only - see ``gate.py``.

Does NOT:
  - implement MCP. It parses the subset a gate must understand and passes
    everything else through untouched. A gate that re-serialised messages
    would be a gate that changes what it forwards.
  - trust ``_meta``. Client identity there is a claim, carried into the
    ledger as one and never used as authorisation (the same discipline
    ``approver_claim`` gets).
  - normalise. An unknown protocol version, a malformed body, or a header
    mismatch is a typed refusal, never a best-effort parse.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from ..errors import (
    HeaderMismatchRefusal,
    ProtocolRefusal,
    UnsupportedProtocolVersionRefusal,
)
from ..types import SUPPORTED_MCP_PROTOCOL_VERSIONS

#: Routing headers required on Streamable HTTP POSTs by the 2026-07-28
#: revision. Present on stdio only if a bridge added them; absent is fine,
#: disagreeing is not.
METHOD_HEADER = "Mcp-Method"
NAME_HEADER = "Mcp-Name"
VERSION_HEADER = "MCP-Protocol-Version"

#: `_meta` key carrying the protocol version, per the 2026-07-28 revision.
META_VERSION_KEY = "io.modelcontextprotocol/protocolVersion"
META_CLIENT_KEY = "io.modelcontextprotocol/clientInfo"

TOOLS_CALL = "tools/call"


@dataclass(frozen=True, slots=True)
class Request:
    """A parsed JSON-RPC request the gate may reason about."""

    id: Any
    method: str
    tool: str | None
    arguments: dict[str, Any]
    protocol_version: str
    client_claim: str
    raw: bytes
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def is_tool_call(self) -> bool:
        return self.method == TOOLS_CALL

    def digest(self) -> str:
        """SHA-256 over the bytes as received. Identity of what arrived, not
        of what the gate understood it to mean."""
        return hashlib.sha256(self.raw).hexdigest()


def _headers_lower(headers: dict[str, str] | None) -> dict[str, str]:
    return {key.lower(): value for key, value in (headers or {}).items()}


def parse_request(raw: bytes, headers: dict[str, str] | None = None) -> Request:
    """Parse one JSON-RPC request. Total: it returns a Request or refuses."""
    try:
        message = json.loads(raw)
    except (ValueError, TypeError) as exc:
        raise ProtocolRefusal("request is not JSON") from exc
    if not isinstance(message, dict):
        raise ProtocolRefusal("request is not a JSON-RPC object")
    if message.get("jsonrpc") != "2.0":
        raise ProtocolRefusal(
            "unsupported jsonrpc version", declared=str(message.get("jsonrpc"))[:20]
        )
    method = message.get("method")
    if not isinstance(method, str) or not method:
        raise ProtocolRefusal("request has no method")

    params = message.get("params")
    params = params if isinstance(params, dict) else {}
    meta = params.get("_meta")
    meta = meta if isinstance(meta, dict) else {}

    version = meta.get(META_VERSION_KEY)
    header_version = _headers_lower(headers).get(VERSION_HEADER.lower())
    declared = version if isinstance(version, str) else header_version
    if declared is None:
        raise UnsupportedProtocolVersionRefusal(
            "request declares no protocol version", method=method
        )
    if declared not in SUPPORTED_MCP_PROTOCOL_VERSIONS:
        raise UnsupportedProtocolVersionRefusal(
            "unsupported protocol version",
            declared=declared[:40],
            supported=list(SUPPORTED_MCP_PROTOCOL_VERSIONS),
        )

    tool: str | None = None
    arguments: dict[str, Any] = {}
    if method == TOOLS_CALL:
        name = params.get("name")
        if not isinstance(name, str) or not name:
            raise ProtocolRefusal("tools/call names no tool")
        tool = name
        raw_arguments = params.get("arguments", {})
        if not isinstance(raw_arguments, dict):
            raise ProtocolRefusal("tools/call arguments are not an object", tool=tool)
        arguments = raw_arguments

    _check_headers(headers, method, tool)

    client = meta.get(META_CLIENT_KEY)
    claim = "unknown"
    if isinstance(client, dict) and isinstance(client.get("name"), str):
        claim = str(client["name"])[:120]

    return Request(
        id=message.get("id"),
        method=method,
        tool=tool,
        arguments=arguments,
        protocol_version=declared,
        client_claim=claim,
        raw=raw,
        meta=meta,
    )


def _check_headers(
    headers: dict[str, str] | None, method: str, tool: str | None
) -> None:
    """PT20: routing headers may not disagree with the body.

    Absent headers are fine - stdio has none. Present and different is a
    refusal, because the gate would otherwise be able to gate on one value
    and forward another.
    """
    lowered = _headers_lower(headers)
    declared_method = lowered.get(METHOD_HEADER.lower())
    if declared_method is not None and declared_method != method:
        raise HeaderMismatchRefusal(
            "routing header disagrees with the body method",
            header=declared_method[:60], body=method,
        )
    declared_name = lowered.get(NAME_HEADER.lower())
    if declared_name is not None and tool is not None and declared_name != tool:
        raise HeaderMismatchRefusal(
            "routing header disagrees with the body tool name",
            header=declared_name[:60], body=tool,
        )


def tool_definition_hash(definition: dict[str, Any]) -> str:
    """Fingerprint one tool definition from `tools/list`.

    Canonical JSON with sorted keys, so a definition that differs only in key
    order fingerprints the same and a definition that differs in substance
    does not. The gate computes this itself and never trusts a cached
    catalogue: the 2026-07-28 revision made list results cacheable with
    ``ttlMs`` and ``cacheScope``, and a gate is precisely the shared
    intermediary that caching talks about (PT16).
    """
    canonical = json.dumps(definition, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
