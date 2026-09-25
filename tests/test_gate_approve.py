"""The approval surface for gated calls, walked end to end.

Until 0.7.6.0 nothing in the suite drove `approve_pending`: the gate's attacks
wrote grant files directly, so the walk's order of events and the way it
writes a grant were unmeasured. F65 made both matter.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest
from conftest import FakeClock, grant_issuer

from pirx import approve, ledger
from pirx.gate_approve import approve_pending
from pirx.grant import Grant
from pirx.mcp.gate import Gate, GatedRegistry, GatedTool
from pirx.mcp.protocol import parse_request, tool_definition_hash
from pirx.proposal import RenderedProposal

TOOL = "repo.write_file"
DEFINITION: dict[str, Any] = {"name": TOOL, "description": "Write a file"}
DEFINITION_HASH = tool_definition_hash(DEFINITION)
WALK = ["gate.presented", "attention.challenge_issued", "approval.decided",
        "grant.issued"]


def call() -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": TOOL,
                "arguments": {"path": "/a"},
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientInfo": {"name": "agent"},
                },
            },
        }
    ).encode("utf-8")


def held(tmp_path: Path) -> tuple[Gate, RenderedProposal, FakeClock]:
    """A gate that has held one call, so one proposal is pending."""
    clock = FakeClock()
    gate = Gate(
        registry=GatedRegistry(
            (GatedTool(tool=TOOL, definition_hash=DEFINITION_HASH),)
        ),
        ledger=ledger.Ledger(tmp_path / "ledger.jsonl"),
        issuer=grant_issuer(clock, tmp_path),
        transport=lambda raw: b'{"id":1,"jsonrpc":"2.0","result":{}}',
        pending_dir=tmp_path / "pending",
        grants_dir=tmp_path / "grants",
        definition_hashes={TOOL: DEFINITION_HASH},
    )
    gate.handle(call())
    return gate, gate.proposal_for(parse_request(call())), clock


def walk(gate: Gate, rendered: RenderedProposal, clock: FakeClock) -> int:
    """One attentive approval: the right transcription, above the floor."""
    field = approve.challenge_field(rendered)
    lines = iter([approve.expected_transcription(rendered, field),
                  approve.APPROVE_TOKEN])
    floor = approve.reading_floor_seconds(len(rendered.canonical_bytes))

    def read() -> str:
        clock.advance(floor + 1)
        return next(lines) + "\n"

    return approve_pending(
        gate.pending_dir, gate.grants_dir, gate.ledger, gate.issuer,
        io.StringIO(), read, clock=clock,
    )


def events(tmp_path: Path) -> list[str]:
    lines = (tmp_path / "ledger.jsonl").read_text().splitlines()
    return [json.loads(line)["event"] for line in lines]


def test_an_approving_walk_records_then_writes_one_whole_grant(
    tmp_path: Path,
) -> None:
    """The four walk events in order, then a grant file that parses, covers
    these bytes, and has no staging file left beside it."""
    gate, rendered, clock = held(tmp_path)

    assert walk(gate, rendered, clock) == 1

    assert [e for e in events(tmp_path) if e in WALK] == WALK
    path = gate.grants_dir / f"{rendered.action_hash}.json"
    assert Grant.from_json(path.read_bytes()).action_hash == rendered.action_hash
    assert [p.name for p in gate.grants_dir.iterdir()] == [path.name]


def test_a_failed_grant_write_leaves_a_record_and_no_authority(
    tmp_path: Path,
) -> None:
    """F65's ordering, measured. The staging name is occupied by a directory,
    so the write fails after the grant exists in memory. What must remain is
    `grant.issued` and no grant file: a record without authority, never the
    reverse. A walk that wrote first would leave no record; a walk that wrote
    in place would leave a file."""
    gate, rendered, clock = held(tmp_path)
    gate.grants_dir.mkdir(parents=True, exist_ok=True)
    (gate.grants_dir / f".{rendered.action_hash}.json.tmp").mkdir()

    with pytest.raises(OSError):
        walk(gate, rendered, clock)

    assert "grant.issued" in events(tmp_path)
    assert not (gate.grants_dir / f"{rendered.action_hash}.json").exists()
