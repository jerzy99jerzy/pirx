# Threat model

```
Document:  docs/THREAT-MODEL.md, version 1.0 (ships with 0.1.0.0)
Source:    PIRX-PROJECT-BRIEF.md v1.2, section 5; PT numbering is never
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

**Control.** Short expiry measured on a **monotonic** clock, checked at spend
time. Single process, so there is no clock to skew or roll back; a serialised
grant is meaningless outside its process by construction. Residual, named:
the human's absence *before* approval is not covered by expiry - the approval
surface prints the proposal's age as a labelled decision aid.
**Lives in** `grant.py`, `approve.py`. **Measured by**
`test_grant.py::test_expired_grant_is_refused_at_spend_time_though_valid_at_issue`,
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

**Control.** No persistent credential; grants die with their action and their
process. The residual is documented executably:
`test_grant.py::test_authority_does_not_survive_a_new_issuer` *shows* that an
in-memory spent-set is per-process, which is why HMAC grants and a durable
spend store are coupled (P5) and land together at the first process split.

## PT9 - Ledger tampering or gaps

**Control.** Append-only JSONL, each record chaining the previous record's
hash, genesis chaining a documented sentinel; intent written before the
guarded action. Verifier ships in the same module. **Named residual:** tail
truncation is *not* detected, asserted by
`test_ledger_chain.py::test_tail_truncation_is_NOT_detected`; a remote
append-only sink buys that later (deferral table).
**Lives in** `ledger.py`. **Measured by** `test_ledger_chain.py`.

## PT10 - Feedback loop toward the ranking system

**Control.** No write path back to Rappaport: no import, no client configured
with its endpoints, no shared file. The network-import scrape doubles as the
enforcement point (the network allowlist is empty in this version). The
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
