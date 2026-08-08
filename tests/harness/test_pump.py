"""Attacks and framing tests for the stdio pump: A44-A47.

The pump is transport, so these test the properties a transport can break
without the gate noticing: frames that arrive split or doubled, a frame large
enough to be an attack, a downstream that dies, and the one rule that makes
the whole stdio contract work - stdout carries protocol and nothing else.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

from conftest import FakeClock, grant_issuer

from pirx import ledger
from pirx.mcp.gate import Gate, GatedRegistry, GatedTool
from pirx.mcp.protocol import tool_definition_hash
from pirx.mcp.pump import MAX_FRAME_BYTES, DownstreamGone, pump

VERSION = "2026-07-28"
TOOL = "repo.write_file"
DEFINITION: dict[str, Any] = {"name": TOOL, "description": "Write a file"}
DEFINITION_HASH = tool_definition_hash(DEFINITION)


def frame(tool: str = TOOL, ident: int = 1) -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": ident,
            "method": "tools/call",
            "params": {
                "name": tool,
                "arguments": {"path": "/a"},
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": VERSION,
                    "io.modelcontextprotocol/clientInfo": {"name": "agent"},
                },
            },
        }
    ).encode("utf-8")


def build(
    tmp_path: Path, gated: bool = True, transport: Any = None
) -> tuple[Gate, list[bytes]]:
    forwarded: list[bytes] = []

    def default_transport(raw: bytes) -> bytes:
        forwarded.append(raw)
        return b'{"id":1,"jsonrpc":"2.0","result":{"resultType":"complete"}}'

    registry = GatedRegistry(
        (GatedTool(tool=TOOL, definition_hash=DEFINITION_HASH),) if gated else ()
    )
    gate = Gate(
        registry=registry,
        ledger=ledger.Ledger(tmp_path / "ledger.jsonl"),
        issuer=grant_issuer(FakeClock(), tmp_path),
        transport=transport or default_transport,
        pending_dir=tmp_path / "pending",
        grants_dir=tmp_path / "grants",
        definition_hashes={TOOL: DEFINITION_HASH},
    )
    return gate, forwarded


def run(gate: Gate, data: bytes) -> tuple[int, bytes, bytes]:
    out, err = io.BytesIO(), io.BytesIO()
    code = pump(gate, io.BytesIO(data), out, err)
    return code, out.getvalue(), err.getvalue()


def events(tmp_path: Path) -> list[str]:
    path = tmp_path / "ledger.jsonl"
    if not path.exists():
        return []
    return [json.loads(line)["event"] for line in path.read_text().splitlines()]


# --- A44: framing ------------------------------------------------------------


def test_a44_two_frames_in_one_read_are_two_calls(tmp_path: Path) -> None:
    """A client that writes both frames before the pump reads must not have
    them treated as one message, and must not have the second dropped."""
    gate, forwarded = build(tmp_path, gated=False)
    code, out, _ = run(gate, frame(ident=1) + b"\n" + frame(ident=2) + b"\n")

    assert code == 0
    assert len(out.splitlines()) == 2
    assert len(forwarded) == 2


def test_a44b_a_frame_with_no_trailing_newline_is_still_read(
    tmp_path: Path,
) -> None:
    gate, forwarded = build(tmp_path, gated=False)
    code, out, _ = run(gate, frame())
    assert code == 0
    assert len(forwarded) == 1
    assert out.endswith(b"\n"), "the pump must terminate what it writes"


def test_a44c_blank_lines_are_skipped_not_parsed(tmp_path: Path) -> None:
    """A stray newline is not a message. Parsing it would produce a refusal
    event for something no peer sent, and a ledger full of phantom refusals
    is a ledger nobody reads."""
    gate, forwarded = build(tmp_path, gated=False)
    code, out, _ = run(gate, b"\n\n" + frame() + b"\n\n")
    assert code == 0
    assert len(forwarded) == 1
    assert len(out.splitlines()) == 1


# --- A45: oversized frames ---------------------------------------------------


def test_a45_an_oversized_frame_is_refused_before_parsing(
    tmp_path: Path,
) -> None:
    """A frame past the bound is a peer that stopped speaking the protocol.
    Refused without being parsed, so a memory-exhaustion attempt never reaches
    a JSON decoder, and nothing is forwarded."""
    gate, forwarded = build(tmp_path, gated=False)
    huge = b'{"jsonrpc":"2.0","padding":"' + b"x" * (MAX_FRAME_BYTES + 10) + b'"}'
    code, out, err = run(gate, huge + b"\n")

    assert code == 0
    assert forwarded == []
    assert b"frame too large" in out
    assert b"pirx-gate" in err
    assert "gate.oversized_frame" in events(tmp_path)


def test_a45b_the_pump_keeps_serving_after_an_oversized_frame(
    tmp_path: Path,
) -> None:
    """One bad frame must not end the session: a peer that recovers should be
    able to keep talking, and a pump that exited would turn a bounds check
    into a denial of service against the honest caller."""
    gate, forwarded = build(tmp_path, gated=False)
    huge = b"x" * (MAX_FRAME_BYTES + 10)
    code, out, _ = run(gate, huge + b"\n" + frame() + b"\n")

    assert code == 0
    assert len(forwarded) == 1
    # Exactly two replies: the refusal, and the honest frame that followed.
    # Three would mean the oversized line's tail was read as its own frame -
    # the smuggling path F55 closed, where a crafted message hides behind
    # padding and rides in on the bounds check instead of being refused.
    assert len(out.splitlines()) == 2


def test_a45c_padding_cannot_smuggle_a_frame_behind_the_bound(
    tmp_path: Path,
) -> None:
    """The attack A45b's fix exists for, stated directly: a valid call
    appended to an oversized line must not execute. It is part of the
    refused line, not a message of its own."""
    gate, forwarded = build(tmp_path, gated=False)
    smuggled = b"x" * (MAX_FRAME_BYTES + 10) + frame()
    code, out, _ = run(gate, smuggled + b"\n")

    assert code == 0
    assert forwarded == [], "a frame hidden behind padding was executed"
    assert len(out.splitlines()) == 1


# --- A46: the downstream dies ------------------------------------------------


def test_a46_a_dead_downstream_ends_the_pump_without_faking_a_result(
    tmp_path: Path,
) -> None:
    """A downstream that closed its pipe is not a refusal and must not be
    reported as one: a JSON-RPC error would tell the caller a decision was
    made. The pump records the fact and exits."""

    def dead(raw: bytes) -> bytes:
        raise DownstreamGone("downstream server closed its output")

    gate, _ = build(tmp_path, gated=False, transport=dead)
    code, out, err = run(gate, frame() + b"\n")

    assert code == 74
    assert out == b"", "nothing may be written to stdout for a dead downstream"
    assert b"pirx-gate" in err
    assert "gate.downstream_gone" in events(tmp_path)


# --- A47: stdout carries protocol only ---------------------------------------


def test_a47_stdout_is_protocol_only(tmp_path: Path) -> None:
    """Every byte the pump writes to stdout must parse as JSON-RPC. A single
    diagnostic line there corrupts the stream for the agent host, which is
    why diagnostics go to stderr."""
    gate, _ = build(tmp_path, gated=True)
    code, out, err = run(gate, frame() + b"\n" + b"not json\n")

    assert code == 0
    for line in out.splitlines():
        message = json.loads(line)
        assert message["jsonrpc"] == "2.0"
        assert "result" in message or "error" in message


def test_a47b_a_held_call_answers_with_a_ticket_and_forwards_nothing(
    tmp_path: Path,
) -> None:
    """The gate's hold, through the real loop: the answer is an MRTR ticket
    on stdout and the downstream sees nothing."""
    gate, forwarded = build(tmp_path, gated=True)
    code, out, _ = run(gate, frame() + b"\n")

    reply = json.loads(out.splitlines()[0])
    assert reply["result"]["resultType"] == "input_required"
    assert forwarded == []
    assert "gate.awaiting_approval" in events(tmp_path)


def test_a47c_an_ungated_call_is_forwarded_byte_identical(
    tmp_path: Path,
) -> None:
    """What the downstream receives is what the client sent - not the pump's
    re-encoding of it (ARCHITECTURE A20)."""
    gate, forwarded = build(tmp_path, gated=False)
    sent = frame()
    run(gate, sent + b"\n")
    assert forwarded == [sent]
