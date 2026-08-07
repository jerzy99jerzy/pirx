# Hostile-agent attack catalogue

```
Document:  tests/harness/CATALOGUE.md, version 1.0 (ships with 0.2.0.0)
Source:    docs/ARCHITECTURE.md section 4.2
Runs in:   CI on every push, same gate as unit tests - not nightly, because
           a control verified occasionally is a control that regresses
           quietly (P3)
```

One row per attack. Each is a deliberate attempt to violate a threat-model
row, and the pass criterion is uniform: **the attack ends in the correct
typed refusal, and that refusal appears in the ledger under the correct event
name.** Asserting on the exception alone would test the code path; asserting
on the ledger tests the deliverable (ARCHITECTURE A9).

The catalogue is finite, named, and mapped: it is coverage of the threat
model, not of the input space. Fuzzing and property-based generation are not
here, deliberately - they are a candidate for the deferral table with a
future owner, not silent scope (P12).

| # | Attack | PT | Expected event | Test |
|---|---|---|---|---|
| A01 | Schema id swap: valid body, `cve-digest.verdict/2` | PT1 | `refusal.schema` | `test_a01_schema_id_swap` |
| A02 | Oversized prose: 50 KB `triage_note` | PT1 | `prose.truncated` | `test_a02_oversized_prose_truncated_at_parse` |
| A03 | Enum smuggling: `priority: P0`, unenumerated `vex_status` | PT1 | `refusal.enum` | `test_a03_enum_smuggling` |
| A04 | Prose as parameter: `recommended_action` carrying a plausible action string | PT2 | no param equals prose | `test_a04_prose_never_reaches_a_parameter` |
| A05 | Replay: spend one grant twice | PT3 | `refusal.spent_grant` | `test_a05_replay` |
| A06 | Deadline pass: advance the injected monotonic clock past expiry | PT4 | `refusal.expired_grant` | `test_a06_deadline_pass` |
| A07 | Target swap: grant for A, spend against B | PT5 | `refusal.target_mismatch` | `test_a07_target_swap` |
| A08 | Byte flip: mutate one byte of the rendered proposal | PT6 | `refusal.hash_mismatch` | `test_a08_byte_flip` |
| A09 | Frame forgery: prose carrying a closing frame marker | PT6 | framed region intact | `test_a09_frame_forgery` |
| A10 | Unregistered action: valid spent grant, action outside the registry | PT7 | `refusal.unregistered_action` | `test_a10_unregistered_action_cannot_execute` |
| A11 | Cross-run authority: reuse a grant against a fresh issuer | PT8 | documented residual | `test_a11_cross_run_authority_residual` |
| A12 | Ledger edit: rewrite a middle record | PT9 | `LedgerChainRefusal` | `test_a12_ledger_edit` |
| A13 | Review-lane smuggle: same id in both lists | PT11 | `review_lane.collision`, zero proposals | `test_a13_review_lane_smuggle` |
| A14 | Budget flood: budget+N verdicts | PT13 | `refusal.budget` naming N ids | `test_a14_budget_flood` |
| A15 | Plausible forgery: perfectly valid payload, hostile content | PT14 | **succeeds, by design** | `test_a15_plausible_forgery_is_accepted` |
| A16 | Registered action, no adapter wired | PT7 | `refusal.adapter_unavailable` | `test_a16_registered_action_without_adapter_refuses` |
| A17 | Intent ordering: attempt must precede the write | PT9 | `capability.attempt` before `capability.result` | `test_a17_intent_written_before_the_write` |
| A18 | Target system refuses the write | PT3 | unsuccessful result, grant **not** refunded | `test_a18_target_failure_is_not_a_refusal` |
| A19 | Crash after the write landed | PT9 | `capability.outcome_reconciled`, no re-execution | `test_a19_crash_after_write_is_reconcilable_never_retried` |
| A20 | Attempt recorded, write never landed | PT9 | `capability.outcome_unknown`, no re-execution | `test_a20_lost_write_is_reported_as_not_landed` |

## A15 is the most important row, precisely because it passes

An accepted risk with a named trigger (P4) is worth an executable record. A15
asserts that Pirx accepts a well-formed payload whose origin nobody
authenticated, which is exactly what PT14 says it does. The day PT14 gains a
control - the first networked transport - this test flips from asserting
acceptance to asserting refusal, and a future reader who deletes it instead
must explain why.

## A18-A20 exist because at-most-once has a cost, and costs get forgotten

Spending the grant before the write means an action can silently not happen.
A19 and A20 are the two halves of that: the write landed and nobody recorded
it, or the write never landed at all. In both, reconciliation **reports and
stops** - it never re-executes, because the grant is spent and an automatic
retry carrying authority across a crash is PT8 wearing a helpful face. A18
pins the related rule: the far side saying no is not a refusal by Pirx, and
it does not refund authority.

## A11 likewise documents rather than defends

An in-process spent-set is per-process. A11 shows that, so the coupling
between HMAC grants and a durable spend store (P5, settled decision 2) rests
on a demonstrated fact rather than an argument.

## What the harness does not do

- No fuzzing, no property-based generation, no model-driven attack synthesis.
- No network, no external services: every attack runs against the same
  single-process pipeline the runner uses.
- No assertion on log text. Events are matched by name and payload field, so
  rewording a message is not a test failure and removing an event is.
