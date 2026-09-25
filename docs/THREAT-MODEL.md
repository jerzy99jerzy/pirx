# Threat model

> Codename **Pirx** (package `pirx`). After Lem's pilot, trusted with a ship
> precisely because he treats his own judgement as fallible and checks it
> against the instruments. This document is where the name earns itself: every
> guardrail assumes the agent - and the human approving it - can be wrong.

```
Document:  docs/THREAT-MODEL.md, version 1.2 (0.7.6.0: PT9 records issuance
           before the grant file). 1.1 with 0.7.5.1; 1.0 shipped with
           0.1.0.0 as PT1-PT14; PT15 (0.5.0.0), PT16-PT20 (0.7.0.0) and
           PT21 (0.7.5.0) landed without a header change, corrected in 1.1
Source:    PT1-PT14 from PIRX-PROJECT-BRIEF.md v1.2, section 5; each later
           row from the version named above. PT numbering is never
           renumbered or repurposed
```

Each entry: the threat, the control (or the acceptance), where it lives, and
which test measures it. A control without a named test is listed as such -
claims are measured, not asserted (P7).

## PT1 - Malformed or hostile-shaped verdict payload

**Control.** Schema and bounds validation on arrival; enumerated values only;
no prose parsed for intent. Shape only - origin is PT14.
**Lives in** `consumer.py`. **Measured by** `test_consumer.py` (schema id
refusal, bounds, enums, malformed ids, parse-time truncation).

## PT2 - Prompt injection in `triage_note` steering the proposer

**Control.** The proposer selects from a code-constant intent list; action
parameters come from deterministic fields, never from prose. Prose travels as
`UntrustedProse`, which cannot occupy a parameter position (constructor
rejects it) and cannot be interpolated implicitly. From 0.4.0.0 a model may
select the action - by exact string membership in the registry, no
normalisation - and write a rationale; its reply is validated as hostile
input, an out-of-contract reply refuses without falling back, and nothing
under `model/` may import grant, capability, ledger, or session machinery.
**Lives in** `types.py`, `proposal.py`, `proposer.py`, `model/client.py`.
**Measured by** attacks A21-A26 and A30 in the harness, plus
`test_proposal.py::test_prose_in_a_parameter_position_is_rejected` and
`test_no_capabilities.py::test_the_model_boundary_cannot_reach_authority`.

## PT3 - Approval reuse: a valid grant spent on a second action

**Control.** Grant bound to the action hash, single-use; the nonce is marked
spent *before* the caller can act.
**Lives in** `grant.py`. **Measured by**
`test_grant.py::test_a_spent_grant_cannot_be_spent_again` and the
replay-over-expiry ordering test.

## PT4 - Stale approval

**Control.** Short expiry measured on the **wall clock**, checked at spend
time, bounded on both sides: `spend` refuses a clock reading after the
deadline (`refusal.expired_grant`) and a clock reading before `issued_at`
(`refusal.grant_not_yet_valid`). Both instants are inside the MAC scope, so
neither can be edited to widen the window.

**Resolution, 0.7.5.0 (F60).** From 0.7.0.0 through 0.7.4.0 every wiring site
injected `time.monotonic`, while 0.7.0.0 had decided on the wall clock and
three documents disagreed about which one ran. Kept as history because the
monotonic clock was wrong in three measurable or documented ways, not one:
its reference point is undefined across processes by CPython's contract; it
restarts at boot, so a grant file written before a reboot carried a deadline
in the old epoch and stayed spendable for up to the previous uptime
(reproduced by A48 with an injected clock); and by the platforms' own
documentation it does not advance while a macOS or Linux host sleeps, so a
grant could outlive its TTL by the length of the sleep (documented, not
measured on a host). The wall clock removes all three. Its cost is PT21.
Every production issuer is now built by one constructor,
`GrantIssuer.on_wall_clock`, and a scrape in the grant tests fails if a
module builds one around it - a regression tripwire, not a proof.

Durations stay monotonic: the attention interval and the proposal age are
differences inside one process, and a backwards wall-clock step must not be
able to shorten a reading floor (PT15).

Residual, named:
the human's absence *before* approval is not covered by expiry - the approval
surface prints the proposal's age as a labelled decision aid.
**Lives in** `grant.py`, `approve.py`. **Measured by**
`test_grant.py::test_expired_grant_is_refused_at_spend_time_though_valid_at_issue`,
`test_grant.py::test_a_grant_is_spendable_at_exactly_its_deadline`,
`test_grant.py::test_a_spend_clock_before_issuance_is_refused`,
`test_grant.py::test_the_production_issuer_writes_wall_clock_deadlines`,
harness A06 and A48,
`test_approve.py::test_age_is_shown_and_labelled_as_not_an_integrity_control`.

## PT5 - Substitution: approved for target A, executed on target B

**Control.** Target id inside the hashed scope; verified independently at
spend.
**Lives in** `grant.py`. **Measured by**
`test_grant.py::test_grant_for_target_a_is_refused_against_target_b`.

## PT6 - Agent-authored approval prompt

**Control.** One render function produces the canonical bytes; the same bytes
are the hash preimage; the approval surface writes them verbatim inside a
frame whose boundary is 128 random bits generated per presentation, so
producer prose cannot forge the frame's end (review finding F1). Inside the
preimage, untrusted prose sits in a deterministic incrementing fence labelled
with its origin (`producer` / `pirx-model`), content indented so no enclosed
line can begin with the fence base (F18) - a random boundary there would
destroy determinism, so the tag derives from content instead. Which mind
proposed is itself recorded per run (`proposer.mode`).
**Lives in** `proposal.py`, `approve.py`. **Measured by**
`test_approve.py::test_stdout_contains_the_hash_preimage_byte_for_byte`,
`test_framed_region_survives_hostile_prose`,
`test_proposal.py::test_prose_cannot_forge_a_field_line`, and attacks
A27-A29 in the harness.

## PT7 - Capability reachable without a grant

**Control.** Grant is a required argument (`SpentGrant`, sole constructor:
spend). A build-failing scrape asserts network and filesystem-write imports
appear only in an allowlisted module set, plus no dynamic imports and no
process/shell reach anywhere. **This is a regression tripwire for the honest
mistake, not a proof**: indirection defeats any static check, and the test's
docstring says so.
**Lives in** `grant.py`, `tests/test_no_capabilities.py`. **Measured by** the
whole of `test_no_capabilities.py`.

## PT8 - Privilege accumulation across runs

**Control.** No persistent credential. A grant authorises one action, once,
and expires on the wall clock (PT4). Since 0.7.0.0 it is a file that
outlives the process that issued it, by design - the gate and the approval
surface are separate processes - so what stops it accumulating is the
durable spend store, whose burnt nonce holds for every process sharing the
store. The store shipped together with the HMAC that makes the file
verifiable (P5).
**History.** Through 0.6.0.0 the spent-set was in memory, and
`test_grant.py::test_authority_does_not_survive_a_new_issuer` documented the
residual: a second issuer accepted the replay. It and harness A11 were
inverted at 0.7.0.0 and now assert refusal.
**Lives in** `grant.py`, `spendstore.py`. **Measured by**
`test_grant.py::test_authority_does_not_survive_a_new_issuer`, harness A11.

## PT9 - Ledger tampering or gaps

**Control.** Append-only JSONL, each record chaining the previous record's
hash, genesis chaining a documented sentinel; intent written before the
guarded action. Verifier ships in the same module. **Named residual:** tail
truncation is *not* detected, asserted by
`test_ledger_chain.py::test_tail_truncation_is_NOT_detected`; a remote
append-only sink buys that later (deferral table).

Since 0.7.3.0 an append also takes an exclusive `flock` and re-reads the tail
inside it, because the gate topology has **two writers on one file**: the
long-lived pump and each `gate-approve` queue walk. Before that fix the
second writer's records were chained past, and `pirx verify` refused a ledger
produced by the manual's own procedure (F59). **Named residual:** `flock` is
advisory and local, so the ordering claim covers writers on one filesystem
and nothing else; a shared or networked ledger is the first networked
transport and fires PT14's trigger rather than arriving quietly.
Since 0.7.6.0 `gate-approve` records `grant.issued` before it writes the
grant file, and writes the file whole, so a crash leaves a record without
authority and never authority without a record (F65).
**Lives in** `ledger.py`, `gate_approve.py`. **Measured by**
`test_ledger_chain.py`, in particular
`test_two_writers_on_one_file_keep_the_chain_intact`, and
`test_gate_approve.py::test_a_failed_grant_write_leaves_a_record_and_no_authority`.

## PT10 - Feedback loop toward the ranking system

**Control.** No write path back to Rappaport: no import, no client configured
with its endpoints, no shared file. The network-import scrape doubles as the
enforcement point: its allowlist holds `adapters/jira.py` (0.3.0.0) and
`model/client.py` (0.4.0.0), and neither is configured with Rappaport's
endpoints. The
sanctioned backchannel is a human carrying files in `docs/exchange/`
(FAMILY.md section 3).
**Measured by** `test_no_capabilities.py::test_no_network_imports_outside_the_allowlist`.

## PT11 - Review-lane items reaching the write path

**Control.** Review-lane items produce no proposals and win over `verdicts`
on `cve_id` collision; the collision is itself a ledger event.
**Lives in** `consumer.py`. **Measured by**
`test_consumer.py::test_review_lane_wins_on_collision_and_collision_is_reported`,
`test_budget.py::test_review_lane_items_produce_no_proposals`.

## PT12 - Blast radius: one approval, many targets

**Control.** One grant, one target, one action; the approval surface offers
no bulk affordance and no single-key shortcut. Batch approval, if ever added,
issues N grants and is refused as a design until PT3-PT5 are proven in
production.
**Lives in** `approve.py`, `grant.py`. **Measured by**
`test_approve.py::test_single_keystroke_does_not_approve`.

## PT13 - Approval fatigue

**Control.** Hard proposal budget per run, a constant in code (P6), enforced
before rendering, consumed in the producer's ranking order so only the tail
can overflow; the refusal event names every excluded id. The approve token is
the full word, because a habituated keystroke is this threat in miniature.
**Lives in** `types.py`, `proposer.py`, `approve.py`. **Measured by**
`test_budget.py`.

## PT14 - Well-formed payload from an unauthenticated origin

**Accepted, not controlled.** Shape validation cannot distinguish a real
verdict from a plausible forgery. Accepted because the transport is a local
file on a host the operator already controls and the entire write surface is
reversible coordination-layer text (and, in 0.1.0.0, empty). **Trigger:** the
moment the payload crosses a network or a shared queue, a detached signature
from Rappaport becomes required and this row becomes a control row. The
acceptance is executable: the 0.2.0.0 harness carries a passing
plausible-forgery case whose deletion must be explained.

## PT15 - Approval-attention exhaustion (proof-of-read)

**The threat.** At volume, per-action approval degrades into reflexive
confirmation: the human is shown the bytes, the token is typed, and the
ledger continues to look clean while the property the thesis rests on - a
real review - is gone. This is B1, the thesis's named weakest link, made a
threat row so its mitigations do not invert P4. No attacker is required;
normal operation induces it. An attacker who can generate approval volume
(a flood of plausible verdicts, or later a flood of gated tool calls) can
induce it deliberately and then slip one hostile action into the rhythm.

**Distinct from PT13**, which bounds *volume* (proposal budget, full-word
token). PT15 is about the *evidentiary quality* of each approval that
happens within that volume.

**Controls.**
- *Content-derived challenge*: before the decision prompt, the approver
  transcribes one deterministic field, selected from `CHALLENGE_FIELDS` by
  the action hash - unpredictable before the canonical bytes exist, so a
  cached or scripted answer from another proposal fails unless the values
  coincide. A mismatch is `refusal.challenge_failed`; the event names the
  field, never the expected value. Prose is never challengeable (PT2).
- *Reading floor*: an approving answer arriving faster than a constant floor
  derived from the byte length is `refusal.reading_floor`. Declining is not
  floor-checked. The floor is a lower bound that catches reflexive approval;
  it is deliberately far below an honest reading time, because a floor
  dressed up as proof of reading would be theatre.
- *Session grant budget*: `MAX_GRANTS_PER_SESSION` grants per issuer, a
  constant (P6); the next issue is `refusal.session_budget`. Refused issues
  do not consume the budget. In the single-run topology PT13's proposal
  budget (10) binds first, so this control's bite arrives with a long-lived
  approval surface (the gate, 0.7.0.0); the primitive ships and is attacked
  now, per P3.
- *Issuance re-verification*: `AttentionEvidence` is a required field of the
  decision, checked again by the issuer, so a decision object fabricated in
  code cannot route around the surface.

**Named residual, stated so it cannot be inflated.** All of this
demonstrates that the approver **operated on the exact hashed bytes** -
located a field in them, within a measured interval. It does not and cannot
demonstrate comprehension, and no document in this repository may use
"understood" where the measurement supports only "read" (P7). A determined
approver can still tool their way past the challenge; what remains is that
the bytes pass through something the approver operates, and the ledger's
latency record makes the pattern visible to an auditor.

**Lives in** `types.py` (constants), `approve.py` (surface),
`grant.py` (issuance), `session.py`/`cli.py` (events).
**Measured by** `test_approve.py` (PT15 block), `test_grant.py` (PT15
block), and harness attacks A31-A35.

## PT16 - Tool-definition drift between approval and execution (rug-pull)

**Control.** The hash of the tool definition in force at approval time is
part of the justification and therefore inside the action hash, so a
definition that changes invalidates every outstanding grant against it by
construction rather than by policy. The gate additionally fingerprints what
it observed against the hash the registry entry was reviewed with, and a
mismatch is `refusal.tool_definition_drift`. Neither check leans on the
client re-fetching: the 2026-07-28 revision made `tools/list` results
cacheable (`ttlMs`, `cacheScope`), and a gate is precisely the shared
intermediary that caching talks about, so it computes fingerprints itself and
treats a cached catalogue as evidence of nothing.
**Lives in** `justification.py`, `mcp/gate.py`. **Measured by** harness A40,
A40b, A42d.

## PT17 - Approval routed through the party under review

**Control.** The approval surface is a Pirx-owned process reading a queue on
disk; no primitive of the intercepted protocol carries an approval decision.
MRTR (`resultType: "input_required"`) is used **only** as a poll ticket: the
result carries an opaque identifier in `requestState` and nothing else - no
proposal bytes, no action hash, no field a client could fill with an
approval - and `inputResponses` are never read as evidence of anything.
MRTR renders in the calling agent's host, which is the trust domain of the
party whose call is being gated; an approval prompt delivered there is PT6
one layer up.
**Lives in** `mcp/gate.py`, `gate_approve.py`. **Measured by** harness A38,
A38b.

## PT18 - Gate bypass: the agent host reaches the downstream server directly

**Accepted, not controlled, and scoped honestly.** A stdio gate cannot
prevent a host from launching the downstream server itself. Prevention lives
in the environment: downstream credentials held only in the gate's
environment, and EDR allowlisting keyed on the identity launcher's
attributable process. What the gate provides is **detectability** - it writes
`gate.pending`, `gate.awaiting_approval`, and `gate.forwarded_granted` before
and after every gated call, so an action that landed with no grant event has
no ledger trail, which is exactly the gap PT9 makes visible. Claiming
prevention here would be theatre, in the same register as "does not
authenticate the human". **Trigger:** the moment the gate runs on a host the
approver does not control, this row needs attestation the launcher cannot
currently provide.

## PT19 - Process-identity forgery on the approver's host

**Accepted, not controlled.** An adversary with code execution at the same
privilege level can present a process that looks like the gate. Research on
Windows established why the macOS story does not transfer: parent-PID
spoofing is an established technique, detection content in the wild has to
cope with process-create records whose parent executable is absent, and the
trust architecture itself is subvertible below the API by tampering with SIP
components and trust providers, which misleads `WinVerifyTrust` and the
products that rely on it. Two further platform facts shape the identity
artefact rather than this row: the Authenticode hash is not a file hash (it
covers selected PE sections in a specific order), and `ProcessGuid` rather
than the PID is the correlation key, because PIDs are reused. **Evidence, not
prevention:** the ledger is hash-chained and written by the real gate, so a
forged gate produces actions with no chain-consistent record. **Trigger:** a
host the approver does not control, same as PT18.

## PT20 - Header/body divergence at the gate

**Control.** The 2026-07-28 revision requires `Mcp-Method` and `Mcp-Name` on
Streamable HTTP POSTs so gateways can route without parsing bodies. Pirx
parses the body anyway and refuses any disagreement with
`refusal.header_mismatch`, never a normalisation. The reason is the thesis:
what is hashed must be what executes, so a gate that decides "is this tool
gated?" from a header while forwarding a body naming a different tool has
re-created the shown-versus-executed divergence at the transport layer.
Headers may be used for routing and metrics only.
**Lives in** `mcp/protocol.py`. **Measured by** harness A39, A39b.

## PT21 - Clock rollback on the gate host extends an unspent grant

**Bounded, and accepted beyond the bound.** Since 0.7.5.0 a grant's deadline
is on the wall clock (PT4), and a wall clock can be stepped backwards.
**Control:** `spend` refuses any reading earlier than `issued_at`. A single
backward step is therefore either larger than the time the grant has
already lived - and refused - or no larger, in which case the grant lives
longer by the size of the step. One step buys strictly less than one extra
TTL, so a grant's real lifetime stays under twice `GRANT_TTL_SECONDS`.
**Accepted:** repeated steps, each small enough to pass the check, are not
bounded. Two kinds of principal can step the clock repeatedly. An
administrator or root can, and can also read the grant key file (mode 600 in
the operator's home), which mints a fresh grant with any deadline outright,
so for them a clock step adds nothing. The time daemon can too, and it holds
the privilege to set the clock without the privilege to read the key; so
can anyone who feeds it a false time over unauthenticated NTP. For that path
the acceptance rests on what the step can and cannot change: it keeps an
already approved action spendable for longer, and it cannot change what was
approved - the bytes, the target, and single use are untouched. Time-source
integrity (authenticated NTP) is the operator's control, named here rather
than assumed. A forward step is fail-safe: grants expire early and the human
approves again.
**Trigger:** the first topology in which issuer and spender read different
clocks (a second host, which the networked transport of 0.9.0.0 makes
possible), or the first registered action or gated tool whose effect depends
on when it runs rather than only on what it does. Either turns a bounded
residual into one nobody has measured, and this row then needs a control
rather than an acceptance.
**Lives in** `grant.py`. **Measured by** harness A48 (the control) and
`test_grant.py::test_a_rollback_smaller_than_the_elapsed_time_is_the_named_residual`
(the residual, executable in the manner of A15: if this row gains a control,
that test flips).
