# TODO

```
Document:  docs/TODO.md, version 2.1
Scope:     small, non-scope-bearing work - documentation, tooling, ergonomics.
           Anything that changes what Pirx does, or accepts a risk, belongs in
           the brief's deferral table (section 9) with an owning version, not
           here.
Format:    checklist, matching cve-digest's TODO.md - open items carry their
           owner in bold, done items carry the version that closed them
```

Status legend: `[ ]` open, `[~]` in progress, `[x]` done (kept briefly for
continuity, then moved to the version's review). Matches cve-digest's legend
so a reader crossing between the repositories does not re-learn the marks.

Every item names an owner, per family practice P12: an unowned item is a
decision that will be re-argued later. "Next docs PR" is a legitimate owner;
"someday" is not, and an item that cannot be given an owner is rejected
rather than parked.

## Open

- [ ] **0.8.0.0** `pirx verify` grows a report including the fatigue signal
  derived from attention events. Re-owned from 0.5.0.0: that version is
  single-purpose attentive approval, and the report is worth shipping once it
  can carry the PT15 signal rather than a bare record count.
  - The 0.7.0.0 local test produced the first real sample: `elapsed_seconds`
    90.4 against a floor of 3.7. That number measures presence at the
    terminal, not attention, so the signal has to be built on the lower tail
    and the shape of the distribution, never on raw elapsed values.
- [ ] **next tooling PR** `ruff target-version` and `mypy python_version` say
  `py312` while the brief, `requires-python`, and CI all say 3.14. The
  checkers are currently lenient about a language level the project does not
  run on. Decide whether to raise both or to record the divergence with a
  reason; either is fine, silence is not.
- [ ] **next tooling PR** `docs_audit.py` gained no check from brief v1.7's
  finding: 0.7.2.0 shipped, was reviewed, and appeared in README's plan while
  the brief's version plan had no row for it. A cross-check - every version
  README marks shipped has a row in the brief's section 6 table - would have
  caught it. Decide whether it is worth a sixth invariant or whether this
  class of drift stays a human read at review time; either is fine, silence
  is not.
- [ ] **next docs PR** `docs/MERGE-PROCEDURE.md` v1.0 lists three required
  status checks. The protection on `main` requires four - `ruff`, `mypy`,
  `pytest`, `docs-audit` - verified against the API during the 0.6.0.0 push.
  The document is stale; the setting is correct.
- [~] **exchange entry PX-0001** carried to cve-digest 2026-08-08. Resolved
  on the way: all five `[cve-digest: confirm]` provenance lines (four
  confirmed in code, P11's attribution struck as an over-interpretation), and
  WORKFLOW.md confirmed to exist upstream at 1.6. **Two decisions now sit with
  cve-digest**: whether to adopt the `Trigger-owned` TODO subsection, and how
  to resolve FAMILY.md's canonical home (see below). Awaiting the mirror's
  disposition.
- [ ] **PX-0001 item 5, owner's decision** FAMILY.md declared cve-digest its
  canonical home; no FAMILY.md exists there, and no `docs/exchange/` either.
  The header no longer asserts it. Resolve by creating the canonical copy
  upstream (recommended) or by naming Pirx the home - either is fine, the
  previous state was not.
- [ ] **PX-0001 item 6, owner's decision** Vendor cve-digest's WORKFLOW.md
  (confirmed at doc version 1.6) verbatim with the version pinned, or state in
  brief section 8 that Pirx deliberately does not carry it (F32).
- [ ] **first version running the gate on Windows** The Windows identity
  launcher. Research is done and shipped as `docs/IDENTITY-WINDOWS.md`; the
  code is deliberately not written ahead of it, because the research
  established that the macOS strength claim does not transfer and an artefact
  written first would have carried a README promising it (PT19).

### Trigger-owned

Open items whose owner is a condition rather than a version. The condition is
the commitment: it is what makes these deferrals rather than intentions.

- [ ] **when a Jira schema change breaks production unnoticed** Contract test
  for the Jira adapter against a recorded response corpus (F15).
- [ ] **first observed false negative from reconciliation, or first adapter
  with a smaller page size** Paginate `find_comment` (F30).
- [ ] **first operator complaint about directory size** A prune strategy for
  the pending queue and the spend store. Neither expires anything on its own
  today, and that is deliberate: an automatic prune of a spend record is a
  replay window with a timer on it.

## Moved out

Items that turned out to be scope rather than housekeeping, with where they
went. Kept as a short list so a reader does not conclude an item was dropped.

- **0.9.x streamable HTTP transport** -> brief v1.7, version plan row 0.9.0.0.
  It changes what Pirx does and fires PT14's trigger, which is exactly what
  this document's header excludes.

## Done recently

- [x] **0.7.0.0** `pirx/__init__.py` described 0.4.0.0 as the current
  version, four versions late. Rewritten in the feature commit, not the bump
  commit - a bump commit carries version strings only, or it does not survive
  rebase merge as a bump (F17).
- [x] **0.6.0.0 push** Confirmed `docs-audit` is a required status check on
  `main` and not merely a job that runs. All four contexts are required, read
  from `gh api .../branches/main/protection` rather than from what
  `gh pr checks` renders (F22).
- [x] **0.4.0.0** Split `gh pr create` from `gh pr checks --watch`, and
  recorded `--auto` as the answer to a not-yet-mergeable PR with `--admin`
  named as forbidden.
  - Chaining the two races GitHub: at PR creation the check runs may not
    exist yet, so `--watch` returns immediately with nothing to watch.
- [x] **0.4.0.0** Converted README's pipeline diagram and the
  Rappaport-to-Pirx flow from ASCII art to Mermaid, with explicit
  `classDef default` dark styling.

## Rejected

Items considered and deliberately not kept, so they do not return:

- **Automating pin refreshes for CI actions.** A bot that rewrites the
  pipeline is the thing SHA pinning defends against (F6).
- **Automating the mutation runs.** A mutation-testing tool over the whole
  suite is scope with a version owner, not a TODO item; until it has one, the
  runs stay deliberate and manual (F9).
