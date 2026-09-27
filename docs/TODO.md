# TODO

```
Document:  docs/TODO.md, version 2.8
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
  - F66: `approval.decided` has two shapes. The runner records
    `challenge_passed` and `floor_seconds`; `gate-approve` records neither.
    The report reads both surfaces, so the shapes align in the version that
    builds it, and the manual says so until then.
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
- [ ] **the next change to `Session`'s constructor** Drop the stored `clock`:
  nothing reads it, and since 0.7.5.0 the issuer owns the only clock a grant
  depends on, so a reader who sees it may assume otherwise.
- [ ] **first operator complaint about directory size** A prune strategy for
  the pending queue and the spend store. Neither expires anything on its own
  today, and that is deliberate: an automatic prune of a spend record is a
  replay window with a timer on it.
- [ ] **the next FAMILY.md amendment, for any reason** Two things to carry
  with it or drop with a reason. The B2 named-trigger amendment
  `docs/PIRX-GATE-DESIGN.md` records as travelling to FAMILY's canonical
  home: B2 is defined nowhere in this tree, so the session starts by finding
  what it names. And FAMILY.md 3.3 saying that an entry's `origin:` line is
  written once, and names a version the tree declared: PX-0001's read
  0.7.0.1, a version never declared (the tree went from 0.7.0.0 to 0.7.0.2),
  and moved to 0.7.2.2 in the carry commit.
- [ ] **the next version that changes `pirx/consumer.py`** Pin the
  payload-level half of the unknown-key tolerance. `consumer.parse` reads
  top-level keys with `.get`, so an unknown key beside `verdicts` is ignored
  by construction, but only the verdict-level half has a test. cve-digest's
  accepted PX-0003 rule covers the whole payload.

## Moved out

Items that turned out to be scope rather than housekeeping, with where they
went. Kept as a short list so a reader does not conclude an item was dropped.

- **0.9.x streamable HTTP transport** -> brief v1.7, version plan row 0.9.0.0.
  It changes what Pirx does and fires PT14's trigger, which is exactly what
  this document's header excludes.

## Done recently

- [x] **0.7.6.1** The cve-digest crossing. Mirrors of PX-0001, PX-0002 and
  PX-0003 landed in cve-digest 0.7.18.1 (tag `v0.7.18.1`): PX-0001 applied,
  PX-0002 accepted with `docs/exchange/` landing ahead of FAMILY.md, PX-0003
  accepted as option 1. The consumers note FAMILY.md 3.4 asks the producer
  for is owned by cve-digest's `TODO.md`, with the FAMILY.md landing.
  MERGE-PROCEDURE 1.3 lists `*.patch` in the transfer check and says what a
  second paste of the tag block does.

- [x] **0.7.6.0** F65: a grant file is input. The gate refuses and answers an
  unparseable one and keeps serving; `gate-approve` records `grant.issued`
  before writing the grant whole; harness A49-A49b; the approval walk driven
  end to end for the first time. Six mutants, five killed; the survivor is
  the read race, closed by construction and stated as such.

- [x] **0.7.5.1** F64: rows for A44-A47c, and the catalogue and its badge
  at 61. The documents reconciled with the code in the same pass: README's
  measured claims, harness counts, and deferral list; ARCHITECTURE 2.4 with
  the two-writer ledger (5E); THREAT-MODEL 1.1 (header, PT8, PT10);
  MERGE-PROCEDURE 1.2; CONTRACT 1.2; MANUAL 2.3; every Mermaid diagram
  checked against the path it draws.

- [x] **0.7.5.0** F60: grant deadlines on the wall clock through one
  production constructor, a spend clock reading before issuance refused
  (`refusal.grant_not_yet_valid`), PT4 resolved and PT21 added, harness A48.
  Seven mutants, seven killed.

- [x] **0.7.4.0** F62: the consumer accepts what the producer emits -
  `vex_status: "none"`, KEV scores above 100.0 - tested against a payload
  cve-digest's own emitter produced, carried by hand. Non-finite numbers are
  refused explicitly now that `score` has no ceiling.
- [x] **0.7.4.0** F63: `epss_pending` read, validated, and rendered as
  `pending`; the model prompt gets `null`, as it does for a pending CVSS.
  Unknown-key tolerance pinned by a test. Evidence bytes for a published
  score unchanged, held as golden bytes. Nine mutants, nine killed.

- [x] **0.7.3.1** Three "either is fine, silence is not" decisions, taken:
  FAMILY.md's canonical home recorded as cve-digest, where that repository
  had already decided it (FAMILY.md 1.2, PX-0002); WORKFLOW.md deliberately
  not vendored (brief v1.9 section 8, F32 closed); `ruff target-version` and
  `mypy python_version` raised to 3.14 to match what the project runs on.
- [x] **0.7.3.1** `docs/MERGE-PROCEDURE.md` 1.1: four required checks, not
  three; the topology step is a checklist line, not a habit; command blocks
  zsh-safe and split per P13.
- [x] **0.7.3.1** `docs_audit.py` check 8: every version README marks shipped
  has a row in brief section 6. Replays the 0.7.2.0 drift in a test.

- [x] **0.7.3.0** Two writers on one gate ledger (F59). `pirx verify` refused
  a chain produced by the manual's own two-terminal procedure; appends now
  take an exclusive `flock` and chain from disk. Killed by mutation.
- [x] **0.7.3.0** F61: the session grant budget's claimed long-lived approval
  surface does not exist - `gate-approve` walks the queue once and exits, so
  the budget bounds a walk. Corrected in `types.py`, no behaviour change.

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
