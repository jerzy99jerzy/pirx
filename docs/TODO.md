# TODO

```
Document:  docs/TODO.md, version 1.3
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
| T9 | `pirx/__init__.py` docstring still describes 0.4.0.0 as the current version | next docs PR | open (noticed during the 0.5.0.0 push; excluded from the bump commit on purpose, since a bump commit carries versions only) |
| T10 | `ruff target-version` and `mypy python_version` say 3.12 while the brief and CI say 3.14 | next tooling PR | open - the checkers are lenient about a language level the project does not run on; decide whether to raise both or record the divergence with a reason |
| T11 | Confirm `docs-audit` is a required status check on `main`, not merely a job that runs | next tooling PR | open - `gh api .../branches/main/protection --jq '.required_status_checks.contexts'`; a green job that cannot block a merge is not a gate |

## Rejected

Items considered and deliberately not kept, so they do not return:

- **Automating pin refreshes for CI actions.** A bot that rewrites the
  pipeline is the thing SHA pinning defends against (review F6).
- **Automating the mutation runs.** A mutation-testing tool over the whole
  suite is scope with a version owner, not a TODO row; until it has one, the
  runs stay deliberate and manual (review F9).
