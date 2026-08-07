# Pirx - architecture assumptions, sprints 0.1.0.0 through 0.3.0.0

```
Document:   docs/ARCHITECTURE.md, version 1.2
Refers to:  PIRX-PROJECT-BRIEF.md v1.2 (thesis, threat model PT1-PT14,
            version plan), FAMILY.md v1.0 (practices P1-P13)
Covers:     sprint 0.1.0.0 (trust loop), 0.2.0.0 (hostile-agent harness),
            0.3.0.0 (first capability)
Authority:  implementation level only. Where this document appears to
            conflict with the brief or a threat-model row, the brief wins
            and the conflict is a finding (FAMILY.md section 4). Settled
            decisions from brief section 9 are restated here, not reopened.
```

This document turns the brief's five-component architecture into concrete
module contracts, type shapes, event schemas, and per-sprint boundaries. It is
deliberately descriptive: a reader should be able to disagree with a decision
here *before* the code exists, which is the only time disagreement is cheap.

---

## 1. System shape

### 1.1 One process, one run, one payload

For all three sprints, Pirx is a single Python process invoked by a human:

```
pirx run path/to/verdict.json
```

One invocation consumes one `cve-digest.verdict/1` payload, walks it through
the pipeline below, and exits. Nothing survives the process except the ledger
file and (from 0.3.0.0) whatever a granted capability wrote to the target
system. There is no daemon, no queue consumer, no scheduler. This is not a
placeholder for a service; it is the topology that makes brief section 9's
settled decision - grant integrity by object identity - *correct* rather than
merely acceptable. The day this stops being one process is the day the HMAC
and persistent spend store land together (settled decision 2).

### 1.2 The pipeline and its trust zones

```mermaid
flowchart LR
    subgraph Z1["Zone: hostile input"]
        V["verdict.json"]
    end
    subgraph Z2["Zone: typed, validated"]
        C["consumer"] --> PS["proposer"] --> PP["proposal"]
    end
    subgraph Z3["Zone: human judgement"]
        RN["renderer"] --> AP["approve CLI"]
    end
    subgraph Z4["Zone: authority"]
        G["grant"] --> CAP["capability"]
    end
    V --> C
    AP --> G
    CAP --> T["target system<br/>(0.3.0.0+)"]
    L[("ledger")]
    PP -.-> L
    AP -.-> L
    G -.-> L
    CAP -.-> L
    classDef default fill:#161b22,stroke:#7d8590,color:#e6edf3
    style L fill:#0b1f2e,stroke:#34d0ff,color:#a9e7ff
```

Four zones, and the boundaries between them are the architecture:

- **Hostile input -> typed.** The consumer is the only module that ever sees
  raw JSON. Everything downstream receives frozen dataclasses. Malformed data
  cannot exist past this boundary because the types that represent it cannot
  be constructed from invalid values (parse, don't validate).
- **Typed -> human judgement.** The renderer is the only module that produces
  bytes for human eyes, and those bytes are the hash preimage. No other module
  formats anything for display (P10).
- **Human judgement -> authority.** A grant is constructed exclusively from an
  explicit approval decision plus the rendered bytes' hash. There is no other
  constructor path, enforced by the grant issuer taking the approval decision
  object as a required argument.
- **Everything -> ledger.** Dotted lines: every zone emits events, no zone
  reads them back to make decisions. The ledger is write-only from the
  pipeline's perspective; its only reader is the chain verifier and the
  auditor (P11 - refusals are events; the ledger is the deliverable).

### 1.3 Time

Two clocks, two jobs, never mixed:

- **Monotonic clock** (`time.monotonic()`): all security decisions, meaning
  grant expiry (PT4). Deadlines are stored as monotonic instants, which is
  possible only because grants never cross a process boundary in these
  sprints - a monotonic value is meaningless outside its process, and that
  constraint conveniently *enforces* the single-process assumption: a grant
  cannot even be serialised meaningfully.
- **Wall clock** (`datetime.now(UTC)`): ledger timestamps, for audit
  readability and SIEM correlation. Explicitly not a security input; a skewed
  wall clock makes the audit trail harder to read, never a grant valid.

---

## 2. Types and data flow

All pipeline types are frozen dataclasses. Mutability is reserved for exactly
two places: the ledger's append cursor and the grant module's spent-set.
Everything else is constructed once, at a zone boundary, and never modified.

Identifier discipline: `CveId`, `VerdictId`, `TargetId`, `ActionHash`,
`GrantNonce` are distinct `NewType` wrappers over `str`/`bytes`. This costs
nothing at runtime and lets mypy refuse the entire class of "grant for target
A checked against verdict id" bugs at the desk instead of in the harness.

The flow, with the type produced at each step:

| Step | Module | Consumes | Produces |
|---|---|---|---|
| parse | consumer | raw bytes | `VerdictBundle` (verdicts, review lane, notices) |
| propose | proposer | `VerdictBundle` | `tuple[Proposal, ...]` within budget, `BudgetRefusal` event for overflow |
| render | proposal | `Proposal` | `RenderedProposal` (canonical bytes + `ActionHash`) |
| decide | approve | `RenderedProposal` | `ApprovalDecision` (approved / declined, with proposal age) |
| issue | grant | `ApprovalDecision` + `RenderedProposal` | `Grant` |
| spend | grant | `Grant` + `ActionHash` + `TargetId` | `SpentGrant` or typed refusal |
| execute | capability (0.3.0.0) | `SpentGrant` + registry entry | `ExecutionOutcome` |

`SpentGrant` existing as a distinct type from `Grant` is deliberate: a
capability's signature takes `SpentGrant`, so "execute without spending" is
not a bug a test catches but a program mypy rejects. The spend function is the
only constructor.

---

## 3. Module contracts, sprint 0.1.0.0

Each module below carries its negative-space register (P2) inline, because
that register becomes the module docstring verbatim.

### 3.1 `consumer.py`

**Does:** parses payload bytes to `VerdictBundle`. Refuses unknown schema ids
(PT1), out-of-range scores, malformed CVE ids (regex against the official
format), unenumerated priorities, and any field exceeding its documented
bound. Truncates `triage_note` at parse time - 0.1.0.0 sets the bound as a
constant (P6). Resolves `review_lane` collisions: a `cve_id` present in both
lists survives only in the review lane (PT11), and the collision itself is a
ledger event, because a producer emitting contradictions is worth knowing
about even when handled.

**Does not:** interpret prose. `triage_note` and `recommended_action` pass
through as opaque display strings typed `UntrustedProse` - a wrapper whose
purpose is that no other module can accidentally pass it where a parameter is
expected (PT2 at the type level). Does not authenticate origin (PT14,
accepted). Does not log payload contents beyond ids and counts - verdicts may
describe unpatched estate, and the ledger is SIEM-bound, not a vault.

### 3.2 `proposer.py`

**Does:** maps each actionable verdict to at most one `Proposal`,
deterministically, in the producer's ranking order. Enforces the proposal
budget (P6, PT13) *before* rendering: position in the ranking decides, the
refusal event names every excluded id. In 0.1.0.0 the mapping targets a
registry with zero entries, so the honest output of this module in the first
sprint is an empty tuple plus correct budget behaviour - and that is testable
behaviour, not a stub.

**Does not:** contain a model (settled decision 4). Does not read
`UntrustedProse`. Does not consult the ledger, the environment, or anything
except the `VerdictBundle` - determinism here means "same bundle, same
proposals, byte-identical", and there is a test asserting exactly that by
running the mapping twice.

### 3.3 `proposal.py`

**Does:** defines `Proposal` (action name, `TargetId`, parameters drawn only
from deterministic verdict fields, justifying `VerdictId`) and the canonical
renderer. Rendering is one pure function: stable field order, explicit
lengths, UTF-8, LF line endings, escaping applied to any embedded
`UntrustedProse`, and a trailing length marker so truncation is visible.
`ActionHash` is SHA-256 over exactly these bytes. One function produces the
bytes; the hash function takes the bytes, not the proposal - so there is no
second serialisation that could drift (PT6, P10).

**Does not:** render differently for display vs hashing (there is only one
output). Does not accept free-form action names - the action field is an enum
over registry keys, and an action absent from the registry fails at
construction, which is PT2's "cannot be named into existence" as a type
constraint rather than a runtime check.

### 3.4 `approve.py`

**Does:** writes the canonical bytes to stdout unmodified, prints the proposal
age (decision-quality aid, labelled as such in the output itself), reads a
single explicit token (`approve` / `decline` - not `y`, because a habituated
keystroke is PT13's failure mode in miniature), and emits an
`ApprovalDecision` event either way. Declines are first-class events with the
same detail as approvals.

**Does not:** summarise, colour, reorder, or elide. The test for this module
captures stdout and compares it byte-for-byte with the hash preimage - the
CLI's honesty is measured, not asserted (P7). Does not loop over proposals
with any bulk affordance; each proposal is a separate prompt (PT12).

### 3.5 `grant.py`

**Does:** issues `Grant` (scope: `ActionHash`, `TargetId`, `VerdictId`;
issued-at and deadline on the monotonic clock; `GrantNonce` from `uuid4`;
single-use) only from an approving `ApprovalDecision`. Verifies totally at
spend: hash match, target match, deadline not passed, nonce not in the
spent-set - every failure a distinct refusal type and event (P11, PT3-PT5).
Marks spent *before* returning `SpentGrant`.

**Does not:** persist anything. The spent-set is an in-process `set` of
nonces, and that is the *correct* mechanism for this topology, not a shortcut
(settled decisions 1-2 restated: object identity now; HMAC plus durable spend
store together at the first process split, either both or neither, P5). Does
not expose a constructor that bypasses the approval argument.

### 3.6 `registry.py`

**Does:** maps action names to capability entries. In 0.1.0.0 the mapping is
empty and the module's main export is the enum of registered names (also
empty) that `proposal.py` builds its action type from.

**Does not:** load entries from configuration, plugins, or entry points -
registration is a code change reviewed like one (P6 applied to capability
surface). This is the module the import-allowlist scrape (PT7) treats as the
root of the write world from 0.3.0.0 on.

### 3.7 `ledger.py`

**Does:** appends structured events as JSONL: `seq`, wall-clock `ts`,
`prev_hash`, `event` (typed name), `payload`. Each record's hash is SHA-256
over its canonical serialisation; the genesis record hashes the documented
sentinel string, so a verifier distinguishes "fresh ledger" from "replaced
head" (PT9). Ships its own verifier function in the same module. Writes the
intent event *before* the guarded action as well as the outcome after, so an
action with no preceding event is itself evidence.

**Does not:** rotate, compress, or ship. Local file, append-only by
discipline and detected-by-chain, with tail truncation named as the residual
risk a remote sink buys later (deferral table). Does not carry payload prose
(see 3.1's logging rule).

### 3.8 `errors.py`

**Does:** defines the refusal taxonomy. One exception class per refusal
reason, each carrying the fields its ledger event needs, each mapping 1:1 to
an event name: `SchemaRefusal`, `BoundsRefusal`, `BudgetRefusal`,
`ReviewLaneCollision`, `HashMismatchRefusal`, `TargetMismatchRefusal`,
`ExpiredGrantRefusal`, `SpentGrantRefusal`, `UnregisteredActionRefusal`. The
rule that makes this a module and not a file of boilerplate: catching one of
these anywhere except the top-level runner is forbidden, because a caught and
suppressed refusal is a warning wearing a refusal's name (P11).

**Does not:** define warnings. There is no warning type in the codebase.

---

## 4. Sprint 0.2.0.0 - the hostile-agent harness

### 4.1 What it is

A scripted adversary, not a model: a test suite (`tests/harness/`) in which
each case is an *attack* - a deliberate attempt to violate one threat-model
row - and the pass criterion is uniform: **the attack ends in the correct
typed refusal, and the refusal appears in the ledger with the correct event
name.** Asserting on the exception alone would test the code path; asserting
on the ledger tests the deliverable (P3, P7, P11).

### 4.2 The attack catalogue

Maintained as a table in `tests/harness/CATALOGUE.md`, one row per attack,
each naming the PT row it exercises. Initial catalogue:

| Attack | PT | Sketch |
|---|---|---|
| schema id swap | PT1 | valid body, `schema: cve-digest.verdict/2` |
| oversized prose | PT1 | 50 KB `triage_note`, assert truncation at parse |
| enum smuggling | PT1 | `priority: "P0"`, `vex_status` outside enum |
| prose-as-parameter | PT2 | `recommended_action` containing a plausible action string; assert no proposal field ever equals it |
| replay | PT3 | spend a grant twice, assert second is `SpentGrantRefusal` in ledger |
| deadline pass | PT4 | advance the injected monotonic clock past expiry |
| target swap | PT5 | grant for A, spend against B |
| byte flip | PT6 | mutate one byte of rendered proposal, assert hash mismatch |
| ungranted write | PT7 | call a capability with a forged object that is not a `SpentGrant`; plus the static scrape as the compile-time twin |
| cross-run authority | PT8 | reuse a grant against a fresh issuer and assert it **succeeds**, documenting the residual. The 1.0 sketch said "assert it is unusable" and reasoned that the hash preimage could not be reproduced - which is wrong, because rendering is deterministic by design (A14). The delivered A11 shows the opposite and is correct; this row was amended to match rather than the test to match the row (F33) |
| ledger edit | PT9 | rewrite a middle record, assert verifier reports the seam |
| review-lane smuggle | PT11 | same id in both lists, assert zero proposals and a collision event |
| budget flood | PT13 | budget+N verdicts, assert order-preserving refusal naming N ids |
| plausible forgery | PT14 | perfectly valid payload, hostile content; assert it *succeeds* - documenting the accepted risk as an executable statement, so the day PT14 gains a control this test flips from asserting acceptance to asserting refusal |

The PT14 row is the catalogue's most important entry precisely because it
passes: an accepted risk with a named trigger (P4) is worth an executable
record, and a future reader who deletes it must explain why.

### 4.3 Mechanics

The harness runs in CI on every push, same gate as unit tests - it is not a
nightly, because a control that is verified occasionally is a control that
regresses quietly (P3). Clock injection: modules take a `now: Callable[[],
float]` parameter defaulting to `time.monotonic`, which keeps the attack
cases honest (no monkeypatching internals) and is the only test seam the
design admits.

**The harness does not:** attempt fuzzing, property-based generation, or
model-driven attack synthesis in this sprint. Those are candidates for the
deferral table with a future owner, not silent scope (P12). The catalogue is
finite, named, and mapped - coverage of the threat model, not of the input
space.

---

## 5. Sprint 0.3.0.0 - the first capability

### 5.1 The capability: comment on an existing ticket

Chosen in the brief for being the smallest genuine write: visible,
reversible, and useless to an attacker who obtains it. The registry gains its
first entry:

```
action:      ticket.comment
parameters:  target ticket id (TargetId, from deterministic verdict data
             or human input - never prose), body (rendered from verdict
             fields; UntrustedProse may appear only inside a delimited
             quotation block labelled as producer prose)
```

### 5.2 The adapter boundary

`capability.py` (new) owns execution semantics; `adapters/` (new) owns the
ticketing system dialect. The adapter protocol is three functions: `comment
(ticket_id, body, idempotency_key)`, `get_comment(idempotency_key)`, and
`healthcheck()`. Which system ships first - Jira or Azure DevOps, both of
which Rappaport already speaks - is the one genuinely open question the brief
left, decided at this sprint by whichever gives the cleaner end-to-end story
of commenting on a ticket Rappaport itself created. The adapter is the *only*
module allowed network imports, which turns the PT7 scrape from a vacuous
check into a live tripwire: from this sprint, the allowlist is
`{ledger.py -> file append, adapters/* -> network}`, and any other module
importing either facility fails the build.

### 5.3 Execution semantics: at-most-once, stated honestly

The ordering is: spend the grant, write the `capability.attempt` ledger event
(carrying the idempotency key), execute, write `capability.result`. A crash
between attempt and result leaves the ledger's honest state:
`outcome_unknown` - a distinct event written by the *next* run's startup scan
when it finds an attempt without a result, never a silently absent record.

- **Idempotency key** = hex of the `ActionHash`. The adapter passes it to the
  target system where the system supports it, and always embeds it in the
  comment body as a structured trailer, so `get_comment(key)` can answer "did
  this land" even on systems without native idempotency.
- **Reconciliation is a human procedure in this sprint**: `pirx reconcile`
  lists attempts without results and, per item, calls `get_comment` and
  reports - it does not re-execute. Re-execution requires a fresh grant,
  because the old one is spent and that is the design, not a limitation: an
  automatic retry holding authority across a crash is PT8 by another name.
- The grant is *not* refunded on failure. A failed execution consumed real
  authority and left real evidence; issuing fresh authority is the human's
  call, informed by the ledger.

### 5.4 What 0.3.0.0 still does not contain

No model (arrives 0.4.0.0 with the renderer's prose segregation as its entry
condition), no second capability, no batch approval (PT12 refuses it as a
design), no remote ledger sink (owned by "after first capability" in the
deferral table - meaning it becomes *eligible* now and is scheduled on
evidence of need, not reflex), no configuration surface for any security
constant (P6).

---

## 6. Cross-sprint invariants

True in every sprint this document covers, and tested in each:

1. The registry's contents are the complete write surface; the scrape proves
   no other module can reach network or filesystem write (PT7 as tripwire).
2. Every refusal is a typed event in the ledger; no code path downgrades a
   refusal to a log line (P11).
3. The bytes a human saw are the bytes that were hashed, proven by stdout
   capture, not by construction argument (PT6, P7).
4. Same input, same output: the pipeline through rendering is deterministic
   and the harness asserts byte-identity across repeated runs.
5. Nothing crosses toward Rappaport: no import, no HTTP client configured
   with its endpoints, no shared file. The scrape's allowlist doubles as the
   enforcement point, and `docs/exchange/` is the only sanctioned channel
   (PT10, P9, FAMILY.md section 1).
6. Security limits are constants; the diff that makes one configurable is
   rejected by review with P6 named in the rejection.

---

## 7. Implementation-level decisions log

Decisions made *by this document*, below the brief's level, recorded so they
are argued here once (P12 spirit). Reopening one is an edit to this file with
a version bump, not a discussion in a pull request.

| # | Decision | Reason |
|---|---|---|
| A1 | Frozen dataclasses + `NewType` ids throughout | Substitution bugs become type errors; zero runtime cost |
| A2 | `SpentGrant` as a distinct type, spend as sole constructor | "Execute without spend" becomes unrepresentable, not merely tested |
| A3 | Monotonic deadlines stored as instants, clock injected as a callable | PT4 testable without monkeypatching; serialised grants are meaningless by construction, reinforcing single-process topology |
| A4 | `UntrustedProse` wrapper type for producer prose | PT2 enforced at the type level in every module at once |
| A5 | SHA-256 for action hash and ledger chain | Boring, universal, no agility machinery for an in-process hash (agility is a deferral owned by the HMAC version) |
| A6 | Approval token is the full word `approve` | A habituated single keystroke is approval fatigue in miniature (PT13) |
| A7 | Refusals may be caught only at the top-level runner | A suppressed refusal is a warning (P11) |
| A8 | Ledger carries ids and counts, never payload prose | The ledger is SIEM-bound; verdicts describe unpatched estate |
| A9 | Harness asserts on ledger contents, not exceptions | The event is the control's output; the exception is an implementation detail |
| A10 | PT14 acceptance is an executable, passing attack case | An accepted risk should cost a deliberate test deletion to forget |
| A11 | Idempotency key embedded in comment body as structured trailer | Reconciliation works on ticketing systems without native idempotency |
| A12 | No grant refund on failed execution | Authority re-issue is a human decision on ledger evidence; automatic retry is PT8 by another name |
| A13 | Action names come from the code constant `KNOWN_INTENTS`; registry membership is checked at spend, not at proposal construction | Amends 3.3, which specified an enum over registry keys: with the registry empty (the defining property of 0.1.0.0), that enum is empty and the brief's end-to-end demonstration is unbuildable. PT2 unaffected - an action name still never derives from prose. Owed since review finding F3 |
| A14 | The untrusted-prose fence tag is deterministic (incrementing until absent from the content), never random | Inside the hash preimage a random boundary destroys "same input, same bytes"; the approval frame stays random because it lives outside the preimage. Content is indented so no enclosed line can begin with the fence base (F18) |
| A15 | Every ledger append flushes and fsyncs before returning | At-most-once leans on `capability.attempt` being durable before the adapter runs; a record in a page cache when the host dies never happened (F24) |
| A16 | A16 supersedes the 4.2 cross-run sketch: an in-process spent-set is per-process and A11 documents that, rather than claiming a defence the design does not provide (F33) |
