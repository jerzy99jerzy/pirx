"""The top-level runner. One invocation, one payload, one process.

Recording lives in `session.py`; this module owns argument handling, the
human-facing output, and the exit status. It is the **only** module that
catches a `Refusal` without re-raising it - everywhere else, a caught refusal
must be re-raised, and the scrape enforces that (P11).

Flow, and the ledger event at each step:

    parse            -> run.started, payload.accepted / refusal.*
    propose          -> proposal.created (per item), refusal.budget
    render + present -> proposal.rendered, approval.decided
    issue            -> grant.issued
    spend            -> grant.spent / refusal.*
    execute          -> refusal.unregistered_action  (0.1.0.0: always)

In 0.1.0.0 and 0.2.0.0 the last step always refuses, because the registry is
empty. That is the version's demonstration, not its limitation: a human can
watch the whole loop run and end in a typed refusal with nothing written.

Does NOT:
  - retry, resume, or reconcile. Execution semantics arrive with the first
    capability at 0.3.0.0.
  - suppress a refusal. Every caught refusal is recorded and re-surfaced in
    the exit status.
"""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TextIO

from . import approve as approval
from .adapters.jira import JiraAdapter, JiraCredentials, UrllibTransport
from .adapters.protocol import TicketAdapter
from .errors import Refusal
from .ledger import Ledger
from .model.client import AnthropicProposalModel, ModelCredentials
from .model.client import UrllibTransport as ModelTransport
from .model.protocol import ProposalModel
from .reconcile import reconcile
from .registry import PRODUCTION_REGISTRY, Registry
from .session import Session


def run(
    payload_path: Path,
    ledger_path: Path,
    out: TextIO,
    read_line: Callable[[], str],
    registry: Registry = PRODUCTION_REGISTRY,
    clock: Callable[[], float] = time.monotonic,
    adapter: TicketAdapter | None = None,
    model: ProposalModel | None = None,
) -> int:
    session = Session(
        Ledger(ledger_path), clock=clock, registry=registry,
        adapter=adapter, model=model,
    )
    session.started(str(payload_path))

    try:
        bundle = session.consume(payload_path.read_bytes(), str(payload_path))
    except Refusal as exc:
        out.write(f"refused: {exc.message}\n")
        session.finished(2)
        return 2

    try:
        proposals = session.propose(bundle)
    except Refusal as exc:
        # A model refusal lands here. The ledger already holds the event via
        # the session; this path exists so the run still ends honestly - with
        # run.finished and an exit status - instead of a traceback (F23).
        out.write(f"refused: {exc.message}\n")
        session.finished(2)
        return 2
    if proposals.over_budget:
        out.write(
            f"budget {proposals.budget} exhausted; "
            f"{len(proposals.excluded)} verdict(s) not proposed\n"
        )

    exit_code = 0
    for item in proposals.proposals:
        created_at = clock()
        rendered = session.render(item)

        decision = approval.decide(
            rendered, age_seconds=clock() - created_at, out=out, read_line=read_line
        )
        session.decided(decision)
        if not decision.approved:
            out.write("declined; nothing was authorised\n")
            continue

        try:
            grant = session.issue(decision, rendered)
            spent = session.spend(grant, rendered.action_hash, item.target)
            outcome = session.execute(spent, rendered)
            if outcome.succeeded:
                out.write(f"executed: {outcome.detail}\n")
            else:
                out.write(f"target system refused: {outcome.detail}\n")
                exit_code = 4
        except Refusal as exc:
            out.write(f"refused: {exc.message}\n")
            exit_code = 3
            continue

    session.finished(exit_code)
    return exit_code


USAGE = (
    "usage:\n"
    "  pirx run <verdict.json> [ledger.jsonl]\n"
    "  pirx reconcile <ledger.jsonl>\n"
    "\n"
    "Credentials come from the environment:\n"
    "  PIRX_JIRA_BASE_URL, PIRX_JIRA_EMAIL, PIRX_JIRA_TOKEN  (the write)\n"
    "  PIRX_ANTHROPIC_API_KEY                                (optional model)\n"
    "With no ticket credentials the run stops at the write with a typed\n"
    "refusal and nothing is written anywhere. With no model key the proposer\n"
    "is deterministic; either way the mode is recorded in the ledger.\n"
)


def model_from_environment() -> ProposalModel | None:
    """Opt-in, and only when fully configured.

    Absent the key, the proposer stays deterministic. There is no partial
    model mode and no automatic enablement: which mind wrote the rationale a
    human is about to approve should never depend on an environment variable
    someone forgot was set - so the run records the mode in the ledger either
    way.
    """
    key = os.environ.get("PIRX_ANTHROPIC_API_KEY")
    if not key:
        return None
    return AnthropicProposalModel(ModelCredentials(api_key=key), ModelTransport())


def adapter_from_environment() -> TicketAdapter | None:
    """Wire an adapter only if fully configured. No partial credentials, no
    prompting, no discovery - an adapter that assembles itself from whatever
    it can find is a write path nobody reviewed."""
    base = os.environ.get("PIRX_JIRA_BASE_URL")
    email = os.environ.get("PIRX_JIRA_EMAIL")
    token = os.environ.get("PIRX_JIRA_TOKEN")
    if not (base and email and token):
        return None
    return JiraAdapter(
        JiraCredentials(base_url=base, email=email, api_token=token),
        UrllibTransport(),
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        sys.stderr.write(USAGE)
        return 64

    command, rest = args[0], args[1:]

    if command == "reconcile":
        if len(rest) != 1:
            sys.stderr.write(USAGE)
            return 64
        adapter = adapter_from_environment()
        if adapter is None:
            sys.stderr.write("reconcile needs a configured adapter\n")
            return 78
        for line in reconcile(Path(rest[0]), adapter):
            sys.stdout.write(line + "\n")
        return 0

    if command == "run":
        if len(rest) not in (1, 2):
            sys.stderr.write(USAGE)
            return 64
        payload = Path(rest[0])
        book = Path(rest[1]) if len(rest) == 2 else Path("pirx-ledger.jsonl")
        return run(
            payload, book, sys.stdout, sys.stdin.readline,
            adapter=adapter_from_environment(),
            model=model_from_environment(),
        )

    sys.stderr.write(USAGE)
    return 64


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
