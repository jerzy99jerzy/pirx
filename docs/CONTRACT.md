# Contract: `cve-digest.verdict/1`

```
Document:  docs/CONTRACT.md, version 1.0 (ships with 0.1.0.0)
Source:    PIRX-PROJECT-BRIEF.md v1.2, section 3
Owner:     Pirx owns THIS document and the compatibility matrix below, as
           the consumer (FAMILY.md 3.4). Rappaport owns the schema itself
           and keeps a plain-prose consumers note pointing here.
```

## Envelope

| Field | Meaning |
|---|---|
| `schema` | Exactly `cve-digest.verdict/1`. Any other value is refused, not coerced. |
| `verdicts` | Ranked items, in the producer's priority order. That order is authoritative and is never recomputed here. |
| `review_lane` | Items the producer's guardrails stopped. Pirx proposes nothing for these. Entries may be bare CVE-id strings or objects with a `cve_id` field. |
| `notices` | Degradation notices from the producing run, carried as opaque strings. |

## Per-verdict fields, as validated by `consumer.py`

| Field | Accepted values |
|---|---|
| `cve_id` | `CVE-\d{4}-\d{4,}` |
| `priority` | `P1` / `P2` / `P3` |
| `in_kev` | boolean |
| `epss` | number in [0.0, 1.0] |
| `cvss` | number in [0.0, 10.0], or `null` iff `cvss_pending` is true |
| `cvss_pending` | boolean; true forbids a `cvss` value |
| `estate_state` | `present` / `absent` / `unknown` |
| `vex_status` | `affected` / `not_affected` / `fixed` / `under_investigation` |
| `score` | number in [0.0, 100.0] |
| `triage_note` | string; truncated at parse time to the prose bound; becomes `UntrustedProse` |
| `recommended_action` | string; same handling |
| `nvd_url` | string beginning `https://nvd.nist.gov/` |

## Consumption rules

1. **Facts and prose are separated on arrival.** `triage_note` and
   `recommended_action` are model-authored text from the far side of a trust
   boundary. They may be shown to a human inside the rendered proposal's
   labelled, escaped prose section; they may never be parsed for intent,
   matched for keywords, or used to fill an action parameter (PT2).
2. **`review_lane` is a stop, not a hint.** On `cve_id` collision with
   `verdicts`, the review lane wins and the collision is a ledger event
   (PT11).
3. **Shape is validated, origin is not.** Every downstream control is written
   as though the payload could have been authored by an adversary who read
   the schema (PT14, accepted with a named trigger).

## The justification abstraction (0.6.0.0)

From 0.6.0.0 this contract is **one source of justification, not the only
shape one can take.** A `Justification` (see `pirx/justification.py`) carries
the source's schema id, the reference a human reads and the action hash
covers, a digest over the source's own canonical evidence, and how the source
appears in the rendered proposal.

| Source | Schema | Render label | Status |
|---|---|---|---|
| Verdict item | `cve-digest.verdict/1` | `verdict` | adapter #1, shipped 0.6.0.0 |
| Intercepted MCP call | `pirx.intercepted-call/1` | `intercepted_call` | adapter #2, owned by 0.7.0.0 (`docs/PIRX-GATE-DESIGN.md`) |

Two consequences worth stating rather than discovering:

1. **The verdict adapter renders exactly what the verdict path rendered
   before the abstraction existed**, so every action hash and every grant
   scope is unchanged. `tests/test_justification.py` holds the preimage as
   golden bytes; a change there is a wire-format change.
2. **The evidence digest is carried and not hashed.** Putting it in the
   preimage changes every action hash, which means a new render schema id
   (`pirx.proposal/2`), not an edit to `/1`. It lands with adapter #2, where
   it binds a grant to the tool definition in force at approval time (PT16).
   Until then a test asserts its absence, so "carried, not hashed" is
   executable rather than commentary (P7).

## Compatibility matrix (consumer-owned)

| Pirx version | Accepts | Notes |
|---|---|---|
| 0.1.0.0 | `cve-digest.verdict/1` | sole schema; any other id refused |
| 0.6.0.0 | `cve-digest.verdict/1` | unchanged as a wire contract; it becomes adapter #1 of the justification abstraction, which is an internal shape, not a schema change |

A breaking change on the producer side means `cve-digest.verdict/2`; Pirx
then lists both here for the overlap window and retires `/1` explicitly. The
id is never repurposed (P8). A proposed change to the schema travels as a
`contract-proposal` exchange entry (FAMILY.md 3.2), never as a direct edit.
