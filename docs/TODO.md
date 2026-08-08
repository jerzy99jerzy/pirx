# TODO

```
Document:  docs/TODO.md, version 1.4
Scope:     small, non-scope-bearing work - documentation, tooling, ergonomics.
           Anything that changes what Pirx does, or accepts a risk, belongs in
           the brief's deferral table (section 9) with an owning version, not
           here.
```

Every row names an owner, per family practice P12: an unowned item is a
decision that will be re-argued later. "Next docs PR" is a legitimate owner;
"someday" is not, and a row that cannot be given an owner is rejected rather
than parked.

| # | Item | Owner | State |
|---|---|---|---|
| T1 | Convert README's pipeline diagram from ASCII art to Mermaid | 0.4.0.0 | **done** |
| T2 | Same for README's Rappaport-to-Pirx flow diagram | 0.4.0.0 | **done** |
| T3 | Split `gh pr create` from `gh pr checks --watch`; record `--auto` as the answer to a not-yet-mergeable PR and `--admin` as forbidden | 0.4.0.0 | **done** |
| T4 | Contract test for the Jira adapter against a recorded response corpus | when a Jira schema change breaks production unnoticed | open, trigger-owned (review F15) |
| T5 | Paginate `find_comment` | first observed false negative from reconciliation, or first adapter with a smaller page size | open, trigger-owned (F30) |
| T6 | Vendor the real WORKFLOW.md, or leave section 8 as the convention record | exchange entry PX-0001 | open (F32) |
| T7 | Confirm or strike the five `[cve-digest: confirm]` provenance lines in FAMILY.md | exchange entry PX-0001 | open (F35) |
| T8 | `pirx verify <ledger>` subcommand, report including the fatigue signal derived from attention events | 0.8.0.0 | open, re-owned from 0.5.0.0 (brief v1.4: 0.5.0.0 is single-purpose attentive approval; the report is worth shipping once it can carry the PT15 signal) |
| T9 | `pirx/__init__.py` docstring still describes 0.4.0.0 as the current version | 0.7.0.0 | **done** - rewritten in the feature commit, not the bump commit |
| T10 | `ruff target-version` and `mypy python_version` say 3.12 while the brief and CI say 3.14 | next tooling PR | open - the checkers are lenient about a language level the project does not run on; decide whether to raise both or record the divergence with a reason |
| T11 | Confirm `docs-audit` is a required status check on `main` | 0.6.0.0 push | **done** - all four contexts required (`ruff`, `mypy`, `pytest`, `docs-audit`), verified against the API |
| T12 | `docs/MERGE-PROCEDURE.md` v1.0 lists three required checks; the protection requires four | next docs PR | open - the document is stale, the setting is correct |
| T13 | Windows identity launcher | first version running the gate on Windows | open - research done (`docs/IDENTITY-WINDOWS.md`); code deliberately not written ahead of it |
| T14 | Prune strategy for the pending queue and the spend store | first operator complaint about directory size | open, trigger-owned - neither expires anything on its own, and an automatic prune of a spend record is a replay window with a timer |
| T15 | Streamable HTTP transport for the gate (stdio-only today) | 0.9.x | open - carries the explicit stdlib-only decision; if stdlib cannot carry it honestly, the constraint is amended with reasons, not worked around |

## Rejected

Items considered and deliberately not kept, so they do not return:

- **Automating pin refreshes for CI actions.** A bot that rewrites the
  pipeline is the thing SHA pinning defends against (review F6).
- **Automating the mutation runs.** A mutation-testing tool over the whole
  suite is scope with a version owner, not a TODO row; until it has one, the
  runs stay deliberate and manual (review F9).
