# Contract: `cve-digest.verdict/1`

```
Document:  docs/CONTRACT.md, version 1.2 (0.7.5.1; 1.1 with 0.7.4.0; 1.0
           shipped with 0.1.0.0)
Source:    cve-digest's published schema, docs/schema/cve-digest.verdict-1.json,
           read at 786efcd (0.7.18.0), and a payload its emitter produced.
           Version 1.0 was written from PIRX-PROJECT-BRIEF.md v1.2's prose,
           which is how it disagreed with the producer for seven weeks (F62)
Owner:     Pirx owns THIS document and the compatibility matrix below, as
           the consumer (FAMILY.md 3.4). Rappaport owns the schema itself.
           FAMILY.md 3.4 also gives it a plain-prose consumers note pointing
           here; at 786efcd there is none, and it belongs to cve-digest's
           FAMILY.md adoption (1.1 said it was there)
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
| `epss` | finite number in [0.0, 1.0] |
| `epss_pending` | optional boolean, absent before cve-digest 0.7.18.0 and then read as false; true requires `epss` to be 0.0, and renders `epss: pending` rather than a number (F63) |
| `cvss` | finite number in [0.0, 10.0], or `null` iff `cvss_pending` is true |
| `cvss_pending` | boolean; true forbids a `cvss` value |
| `estate_state` | `present` / `absent` / `unknown` |
| `vex_status` | `none` / `affected` / `not_affected` / `fixed` / `under_investigation`; `none` means no statement exists and is the producer's value for most CVEs |
| `score` | finite number, at least 0.0, no maximum: KEV items start at 100.0 and rise, so the producer's schema declares only a minimum |
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
4. **Keys this table does not list are ignored, and never rendered.** The
   producer adds optional fields under `verdict/1` (`tickets`,
   `epss_percentile`) and relies on consumers skipping them; a test pins that
   tolerance so it cannot be lost by accident. Ignoring a field is not
   reading it: nothing here trusts or displays one.
5. **The contract is tested against the producer's output, not a description
   of it.** `tests/fixtures/verdict-1.cve-digest-0.7.18.0.json` was emitted by
   cve-digest's own `build_verdicts` and carried into this tree by hand. When
   the producer changes the payload, the fixture is refreshed the same way -
   never fetched (FAMILY section 1).

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
| 0.7.4.0 | `cve-digest.verdict/1` | **first version that accepts what the producer emits.** 0.1.0.0 through 0.7.3.1 refused any payload carrying a CVE without a VEX statement or a KEV item scored above 100.0 - in practice, every real run (F62). Adds `epss_pending`. Tested against cve-digest 0.7.18.0 output |

A breaking change on the producer side means `cve-digest.verdict/2`; Pirx
then lists both here for the overlap window and retires `/1` explicitly. The
id is never repurposed (P8). A proposed change to the schema travels as a
`contract-proposal` exchange entry (FAMILY.md 3.2), never as a direct edit.
