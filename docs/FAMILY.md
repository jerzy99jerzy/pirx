# The codebase family

**Extracted practices and the development-level exchange between Rappaport
(cve-digest) and Pirx.**

```
Document:       FAMILY.md, version 1.0
Canonical home: cve-digest, docs/FAMILY.md
Vendored by:    pirx, docs/FAMILY.md  (verbatim, version pinned in this header)
Amended via:    the exchange protocol in section 3, never by direct edit
                in a vendored copy
```

Two repositories, one author, one set of habits that were paid for in
incidents. This document does two things: it names the practices so they can be
applied deliberately rather than by muscle memory, and it defines the only
sanctioned channel through which the projects influence each other during
development.

---

## 1. The boundary this document must not blur

Pirx's threat model entry PT10 forbids a runtime feedback loop: no signal on a
wire from the agent back to the ranking system, ever. That rule is about
runtime. This document is about development time, and the two must not be
confused in either direction:

- **Development-level exchange is allowed and expected.** Findings, contract
  proposals, and convention amendments flow between the repositories - through
  a person.
- **The exchange is asynchronous, file-based, and human-carried. Always.** No
  CI job, script, hook, or agent in either repository reads or writes the
  other repository's state. Not for status badges, not for drift checks, not
  for convenience. The moment a pipeline in one repo consumes a file from the
  other, a machine channel exists between a ranking system and an agent acting
  on its rankings, and the fact that it carries "only metadata" is exactly the
  kind of qualifier the family's security theses exist to refuse.
- Consequence, stated honestly: **cross-repo drift is detected by humans at
  exchange time, not by automation.** Each repo's docs audit checks internal
  consistency (a vendored file's pinned version matches what the inheriting
  document declares). Whether the canonical copy has moved on is a question a
  person answers when they next carry an exchange entry across. This is a
  measured claim about what the tooling does, not a gap someone forgot.

---

## 2. Extracted practices

Named, with one-line provenance each. A practice earns a place here by having
shaped a real decision in at least one of the repositories, not by sounding
prudent.

**Provenance status, stated because this document demands provenance and must
hold itself to it (review finding F35).** Claims sourced to *Pirx* are
verifiable in this repository: the code, tests, and reviews they name exist.
Claims sourced to *Rappaport* are marked `[cve-digest: confirm]` - they were
written from the project brief and from the author's account rather than read
out of that repository, and this document was drafted in Pirx before it ever
reached its declared canonical home. Confirming or striking them is the
substance of exchange entry PX-0001. A provenance line that nobody checked is
the thing P7 exists to refuse, and it went unchecked here for four versions.

**P1. Absolute-claim isolation.** A security thesis derives its value from
having no qualifier. The moment a qualifier is needed, it gets its own
repository, name, and threat model, joined to the original by a versioned
one-way contract. *(Provenance: Pirx exists because "the model decides
nothing" must stay absolute in Rappaport.)*

**P2. Negative-space documentation.** Every module and every project registers
what it does **not** do, with reasoning, before the code exists. Naming what a
control does not buy is harder than building the control and is what reviewers
actually weigh. *(Provenance: Rappaport's docstring convention `[cve-digest: confirm]`;
Pirx brief section 2.)*

**P3. Trust machinery before payload.** The verification vehicle - tests,
adversarial harness, refusal paths - ships and is exercised before the thing
it protects exists. Retrofitting a control around working functionality is how
the control becomes optional. *(Provenance: Pirx's empty registry with a
build-failing scrape from day one; hostile-agent harness at 0.2.0.0 before the
first write at 0.3.0.0.)*

**P4. Accepted risk with a named trigger.** A risk that is accepted rather
than controlled gets a threat-model row saying so, with the precise condition
under which it stops being acceptable. Silence is worse than either a control
or an acceptance. *(Provenance: Pirx PT14 - unauthenticated payload origin,
trigger: first networked transport.)*

**P5. Coupled controls ship together or not at all.** When two mechanisms are
only sound in combination, the coupling is written down and enforced as
"either both or neither in the same version". *(Provenance: HMAC grants and
the persistent spend store - a stateless-verifiable grant without a durable
spend record is replayable.)*

**P6. Security constants, not security configuration.** A limit that exists
for a security reason is a constant in code. A configurable limit is a
disabled limit on the day someone is in a hurry. *(Provenance: Pirx proposal
budget; Rappaport's refusal to expose ranking weights as config
`[cve-digest: confirm]`.)*

**P7. Claims are measured, not asserted.** A number or a strength-word
("enforced", "proves") appears in documentation only when the code produces
it. Static checks are named as regression tripwires, not proofs.
*(Provenance: family-wide; applied against Pirx's own PT7 wording in brief
v1.1.)*

**P8. Contract ids are never repurposed.** A breaking change means a new
schema id; the consumer supports both until it explicitly does not; the old id
is retired, never redefined. *(Provenance: cve-digest.verdict/1 discipline `[cve-digest: confirm]`.)*

**P9. One-way arrows with a human backchannel.** Where a data flow must be
one-directional, the reverse path is not merely absent - it is replaced by an
explicit human-carried procedure, so the pressure to add a wire has a
sanctioned outlet. *(Provenance: PT10 plus this document's section 3.)*

**P10. Shown bytes are hashed bytes.** Whatever a human approves is the
canonical byte sequence, produced by one function, and the same bytes are what
any integrity mechanism covers. A summary shown in place of the artefact is an
approval the agent authored. *(Provenance: Pirx renderer and PT6.)*

**P11. Refusal is an event, never a warning.** Every guardrail that declines
to proceed emits a structured, typed event with a reason. A warning that lets
execution continue is not a control. *(Provenance: Rappaport's sink
discipline `[cve-digest: confirm]`; Pirx errors.py convention.)*

**P12. Deferrals have owners.** Anything deliberately not built is listed with
the version that owns it and the reason it is not owed now. An unowned
deferral is a decision that will be re-argued mid-sprint. *(Provenance: Pirx
brief section 9.)*

**P13. Verification and the action it guards never share a pasted block.**
Command hygiene: the check that something worked is issued separately from the
thing being checked, so a copy-paste cannot silently skip it. *(Provenance:
inherited WORKFLOW.md `[cve-digest: confirm - no WORKFLOW.md is vendored
in Pirx; see F32]`, paid for in an incident.)*

Amending this list is a convention-amendment exchange entry (section 3), so
that a practice invented in one repo reaches the other deliberately.

---

## 3. The exchange protocol

The continuity loop. Everything that crosses between the repositories during
development crosses here, as a file, carried by a person.

### 3.1 Location and naming

Each repository has `docs/exchange/`. An entry is a single Markdown file,
authored **in the repository where the evidence lives**, named by origin:

```
PX-NNNN.md   originated in Pirx        (evidence about or from Pirx)
RP-NNNN.md   originated in Rappaport   (evidence about or from Rappaport)
```

Numbering is sequential per origin and never reused. When an entry is acted on
in the target repository, the target records a disposition file with the same
id under its own `docs/exchange/`, so both sides hold the complete story of
every crossing without either side reading the other's tree.

### 3.2 Entry types

| Type | What it carries | Typical direction |
|---|---|---|
| `finding` | Something learned in one repo that should change the other's deterministic rules, tests, or docs. The Pirx-brief case: "Pirx learned something that should change priority" travels here, never on a wire | either |
| `contract-proposal` | A proposed change to `cve-digest.verdict/*`. Breaking means a new id per P8; the proposal names the id | consumer -> producer, usually |
| `convention-amendment` | A change to WORKFLOW.md or to this document, made in the canonical home and then propagated | either |
| `status` | A snapshot crossing (see 3.4), carried when versions or supported contracts change | either |

### 3.3 Entry format

Front matter, then prose. Deliberately close to the `docs/reviews/` findings
convention so the disposition vocabulary is already familiar:

```
id:           PX-0001
type:         finding
origin:       pirx @ 0.1.0.0
target:       cve-digest
disposition:  proposed | accepted | rejected | applied
carried:      2026-08-07, by hand
```

`disposition` starts at `proposed` in the origin repo; the target's mirror
file carries the final state with reasons, same as review findings: applied,
accepted with reasons, or rejected with reasons.

### 3.4 Status sharing

Each repository keeps a machine-readable `STATUS.json` at its root, for humans
and exchange entries to reference - never for the other repository's tooling
to read:

```json
{
  "project": "pirx",
  "version": "0.1.0.0",
  "consumes": ["cve-digest.verdict/1"],
  "produces": [],
  "family_doc": "1.0",
  "workflow": "1.4"
}
```

The producer's file lists `produces`; the consumer's lists `consumes`. The
compatibility question "which Pirx versions accept which verdict schemas" is
owned by the consumer and lives in Pirx's `docs/CONTRACT.md` as a matrix; the
producer keeps a plain-prose consumers note pointing at it. One owner per
question, per P12's spirit: a matrix maintained in two places is wrong in one
of them within a month.

### 3.5 Vendoring rule

Documents with a canonical home (WORKFLOW.md, FAMILY.md) are vendored
verbatim, with the version pinned in the vendored copy's header. The local
docs audit verifies the pin is internally consistent (header version equals
the version the inheriting brief declares). Propagating a bump is a
`convention-amendment` entry and a human act. Editing a vendored copy directly
is the one way to fork the family by accident, which is why the header says
where amendments happen.

---

## 4. What this document is not

- Not a governance process. Two repos, one author; the protocol exists so the
  discipline survives a second contributor or a six-month gap, not to add
  ceremony today.
- Not a synchronisation mechanism. Nothing here runs. If a future reader finds
  a script that automates any part of section 3, that script is a finding.
- Not a substitute for the threat models. A practice in section 2 that
  conflicts with a repo's threat model loses, and the conflict is itself a
  `finding` entry.
