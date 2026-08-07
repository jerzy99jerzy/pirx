# TODO

```
Document:  docs/TODO.md, version 1.1
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

## Rejected

Items considered and deliberately not kept, so they do not return:

- **Automating pin refreshes for CI actions.** A bot that rewrites the
  pipeline is the thing SHA pinning defends against (review F6).
- **Automating the mutation runs.** A mutation-testing tool over the whole
  suite is scope with a version owner, not a TODO row; until it has one, the
  runs stay deliberate and manual (review F9).
