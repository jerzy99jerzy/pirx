"""The stdio pump: the process an agent host launches instead of the server.

`Gate` decides; this module is the plumbing that lets a decision reach a real
pair of programs. It spawns the downstream MCP server as a child, reads
newline-delimited JSON-RPC frames from its own stdin, hands each to the gate,
and writes the answer to its own stdout.

**This module is why `pirx-gate` is a process rather than a class.** 0.7.0.0
shipped the whole decision path and no way to run it; the documentation said
otherwise and was wrong (review finding F54). Everything here is transport,
and it stays thin on purpose: a pump that starts making decisions is a second
place where authority is reasoned about.

Framing. One JSON object per line, newline-terminated, on both sides. The
2026-07-28 revision's stdio transport is line-delimited JSON-RPC, and a frame
containing a raw newline is not representable - the canonical serialisations
this project already uses (`json.dumps` with no indent) never emit one.

Does NOT:
  - re-serialise a forwarded frame. The bytes the gate returns are the bytes
    written, so what a human approved is what the downstream server reads
    (ARCHITECTURE A20).
  - reorder, batch, or coalesce. One frame in, one frame out, in order. A
    pump that pipelined would let a second call overtake a held one.
  - write anything but protocol to stdout. Diagnostics go to stderr, which is
    where the specification points stdio servers and where an operator can
    read them without corrupting the stream.
  - restart the child. A downstream server that dies stays dead and the pump
    exits; a supervisor that silently respawned it would hide the crash the
    ledger is supposed to make visible.
  - decide anything. Every branch here is "which pipe does this go to".
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import BinaryIO

from ..errors import Refusal
from ..grant import GrantIssuer, load_key
from ..ledger import Ledger
from ..spendstore import SpendStore
from ..types import GRANT_KEY_ENV
from .gate import PRODUCTION_GATED_REGISTRY, Gate, GatedRegistry

#: Longest frame the pump will read. A line longer than this is a peer that
#: has stopped speaking the protocol, not a large legitimate call: the gate
#: already bounds intercepted arguments far below it (MAX_CALL_ARGUMENT_CHARS),
#: so anything here is either a bug upstream or an attempt to exhaust memory
#: before any parser sees it. A constant, per P6.
MAX_FRAME_BYTES = 1_000_000


class DownstreamProcess:
    """The MCP server the agent host meant to talk to, as a child process."""

    def __init__(self, command: Sequence[str]) -> None:
        if not command:
            raise ValueError("no downstream command given")
        self.command = list(command)
        self._proc = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            # stderr is deliberately inherited: the child's diagnostics reach
            # the operator's terminal instead of being swallowed by the pump.
            stderr=None,
        )

    def send(self, frame: bytes) -> bytes:
        """Write one frame, read one frame. Synchronous by design.

        The gate holds a call until a human decides, so there is nothing to
        gain from concurrency here and something to lose: an asynchronous pump
        could let an ungated call overtake a gated one and land first, which
        would make the ledger's order stop matching what happened.
        """
        stdin, stdout = self._proc.stdin, self._proc.stdout
        if stdin is None or stdout is None:  # pragma: no cover - Popen contract
            raise RuntimeError("downstream pipes are not open")
        stdin.write(frame.rstrip(b"\n") + b"\n")
        stdin.flush()
        reply: bytes = stdout.readline()
        if not reply:
            raise DownstreamGone("downstream server closed its output")
        return reply.rstrip(b"\n")

    def close(self) -> None:
        if self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:  # pragma: no cover - slow child
                self._proc.kill()

    @property
    def pid(self) -> int:
        return self._proc.pid


class DownstreamGone(RuntimeError):
    """The child exited or closed its pipe.

    Not a `Refusal`: nothing was refused. The pump reports and exits rather
    than converting a dead downstream into a protocol error that would look,
    to the caller, like a decision.
    """


def build_gate(
    gate_dir: Path,
    downstream: DownstreamProcess,
    registry: GatedRegistry | None = None,
    definition_hashes: dict[str, str] | None = None,
) -> Gate:
    """Wire a gate for this process. The issuer is built here, visibly.

    The key file is mandatory: the gate verifies grants that another process
    issued, and an ephemeral key would produce authority nothing can check.
    `pirx run` may generate one because it approves and executes in the same
    process; the gate may not.
    """
    configured = os.environ.get(GRANT_KEY_ENV)
    if configured is None:
        raise SystemExit(
            f"{GRANT_KEY_ENV} must name a key file. The gate verifies grants "
            "issued by `pirx gate-approve` in another process; without a "
            "shared key there is nothing to verify."
        )
    return Gate(
        registry=registry if registry is not None else PRODUCTION_GATED_REGISTRY,
        ledger=Ledger(gate_dir / "ledger.jsonl"),
        issuer=GrantIssuer(
            clock=time.monotonic,
            key=load_key(Path(configured)),
            store=SpendStore(gate_dir / "spent"),
        ),
        transport=downstream.send,
        pending_dir=gate_dir / "pending",
        grants_dir=gate_dir / "grants",
        definition_hashes=definition_hashes or {},
    )


def pump(
    gate: Gate,
    stdin: BinaryIO,
    stdout: BinaryIO,
    stderr: BinaryIO,
) -> int:
    """Read frames until stdin closes. Returns the process exit code.

    Split from `main` so the loop is testable with pipes rather than with a
    real agent host: the harness drives this directly (A44-A47).
    """
    while True:
        line = stdin.readline(MAX_FRAME_BYTES + 1)
        if not line:
            return 0
        frame = line.rstrip(b"\n")
        if not frame:
            continue
        if len(frame) > MAX_FRAME_BYTES:
            # Drain the rest of the line before continuing. `readline` with a
            # size cap stops mid-line, so without this the tail is read as a
            # *new* frame - which would let a peer hide a crafted message
            # behind a megabyte of padding and have the bounds check smuggle
            # it in rather than refuse it. Found by A45b (review F55).
            discarded = len(frame)
            while not line.endswith(b"\n"):
                line = stdin.readline(MAX_FRAME_BYTES + 1)
                if not line:
                    break
                discarded += len(line)
            stderr.write(
                b"pirx-gate: frame exceeds the maximum; refusing to parse\n"
            )
            stderr.flush()
            gate.ledger.append("gate.oversized_frame", bytes=discarded)
            stdout.write(_oversized_error() + b"\n")
            stdout.flush()
            continue

        try:
            reply = gate.handle(frame)
        except DownstreamGone as exc:
            stderr.write(f"pirx-gate: {exc}\n".encode())
            stderr.flush()
            gate.ledger.append("gate.downstream_gone", message=str(exc))
            return 74
        except Refusal as exc:  # pragma: no cover - gate.handle catches its own
            gate.ledger.append(exc.event, **exc.details, message=exc.message)
            return 3

        stdout.write(reply.rstrip(b"\n") + b"\n")
        stdout.flush()


def _oversized_error() -> bytes:
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32020, "message": "frame too large"},
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


USAGE = (
    "usage:\n"
    "  pirx-gate <gate-dir> -- <downstream-command> [args...]\n"
    "\n"
    "Launched by an agent host in place of the downstream MCP server.\n"
    "Speaks line-delimited JSON-RPC on stdin/stdout; the downstream server\n"
    "runs as a child. Requires PIRX_GRANT_KEY_FILE, shared with the\n"
    "`pirx gate-approve` process that a human uses to issue grants.\n"
    "\n"
    "The gated registry ships empty: with no tool registered, every call is\n"
    "forwarded and recorded as ungated. That is the intended first run.\n"
)


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if "--" not in args or len(args) < 3:
        sys.stderr.write(USAGE)
        return 64
    split = args.index("--")
    gate_dir = Path(args[0]) if split > 0 else None
    command = args[split + 1 :]
    if gate_dir is None or not command:
        sys.stderr.write(USAGE)
        return 64

    gate_dir.mkdir(parents=True, exist_ok=True)
    downstream = DownstreamProcess(command)
    try:
        gate = build_gate(gate_dir, downstream)
    except SystemExit as exc:
        downstream.close()
        sys.stderr.write(f"{exc}\n")
        return 78

    # Process identity, recorded before the first frame: an auditor reading
    # this ledger later needs to know which process wrote it (PT19). The PID
    # is recorded for correlation and is explicitly not an identity claim -
    # PIDs are reused, and nothing here authenticates the executable.
    gate.ledger.append(
        "gate.started",
        pid=os.getpid(),
        executable=sys.executable,
        downstream=command,
        downstream_pid=downstream.pid,
        gated_tools=list(gate.registry.tools()),
        authenticated=False,
    )
    try:
        return pump(gate, sys.stdin.buffer, sys.stdout.buffer, sys.stderr.buffer)
    finally:
        downstream.close()
        gate.ledger.append("gate.stopped")


if __name__ == "__main__":  # pragma: no cover - process entry
    raise SystemExit(main())
