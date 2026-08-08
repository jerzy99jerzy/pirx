# Gate research note - input to 0.7.0.0

```
Document:   docs/GATE-RESEARCH.md, version 1.0
Status:     research complete, design consequences proposed; vendor with the
            0.7.0.0 changeset, not before
Refers to:  PIRX-GATE-DESIGN.md v1.1, THREAT-MODEL.md PT1-PT15,
            reviews/0.6.0.0 (finding F43)
Research:   web sources read 2026-08-08; every load-bearing claim labelled
            [measured] (read in a primary or vendor source) / [inference] /
            [speculation]
Rule:       nothing here is written from memory. Where a source was not
            found, the note says so rather than filling the gap.
```

Three questions were open before gate code could be written. This note
answers all three: Windows process identity, the MCP interception point
under the current specification, and whether `Proposal.verdict` survives
adapter #2.

---

## 1. Windows identity

macOS (signed Mach-O parent, stable cdhash) and Linux (systemd unit + ELF
SHA-256, allowlist by unit path, process name, binary hash) were settled in
earlier sessions. Windows was the platform nobody had checked.

### 1.1 What the platform actually offers

- **Authenticode** is the signing system: a code-signing certificate from a
  CA the OS trusts, signatures embedded in the PE, optionally countersigned
  by a timestamping service so verification survives certificate expiry or
  revocation. [measured]
- **`WinVerifyTrust` / `WinVerifyTrustEx`** are the user-mode APIs through
  which signed-code trust is validated; the same validation underpins
  application allowlisting (AppLocker, Device Guard) and is a classification
  input for AV and EDR products. [measured]
- **The Authenticode hash is not the file hash.** It covers specific PE
  sections in a specific order, deliberately permitting some regions to be
  modified and sections to be reordered; the "ExpectedHash" inside a
  signature does not equal SHA-256 over the file. [measured - Velociraptor's
  Authenticode parser documentation demonstrates the two values differing]
- **Sysmon Event ID 1 (process create)** carries the fields an allowlist
  would key on: `Image`, `CommandLine`, `Hashes` (MD5/SHA-256/IMPHASH),
  `ParentImage`, `ParentCommandLine`, `ProcessGuid`, `ParentProcessGuid`,
  `User`, `LogonId`, plus signature information. `ProcessGuid` exists
  precisely because PIDs are reused and are not a safe correlation key.
  [measured]

### 1.2 What that means for a gate that wants to be attributable

Three consequences, and the third is the one that changes the design.

1. **"Hash the binary" is ambiguous on Windows and must be disambiguated in
   the artefact.** An allowlist keyed on "the hash" may mean the Authenticode
   hash or a plain file digest, and they differ by construction. The
   identity artefact must state which one it publishes - both, labelled -
   or an operator will paste one into a control that expects the other.
   [inference from the measured hash divergence]
2. **The correlation key is `ProcessGuid`, not the PID.** Anything Pirx
   writes into the ledger about its own process identity on Windows should
   carry the GUID; a PID in an audit record is a value that will be reused
   by a different process within the retention window. [inference]
3. **Parent-process attribution is not a control.** Parent PID spoofing is
   an established technique, and detection content in the wild has to handle
   process-create events where the parent executable is simply absent from
   the record. Separately, the Windows trust architecture itself is
   subvertible below the API: tampering with SIP components and trust
   providers misleads `WinVerifyTrust`, and doing so subverts the products
   that rely on it. [measured - Elastic rule tuning issue on PPID spoofing;
   SpecterOps, *Subverting Trust in Windows*]

Consequence (3) is what the macOS story quietly assumed and Windows will not
grant. On macOS the design was "signed parent, stable cdhash, allowlist by
bundle-id/cdhash". The Windows equivalent cannot claim the same strength,
because both halves - the ancestry and the signature validation - have known
subversion paths that do not require kernel access.

### 1.3 Proposed Windows position, stated at its real strength

> The launcher is Authenticode-signed and publishes both its Authenticode
> hash and a plain SHA-256 of the PE, labelled. The gate records its own
> `ProcessGuid` and image path in the ledger at startup. Allowlisting is
> recommended on image path plus file hash plus signer, and the artefact
> says in plain words that **process ancestry is evidence, not a control**:
> an adversary who can spoof a parent PID or tamper with a trust provider
> defeats ancestry-based attribution, and neither is exotic.

This is PT18's shape ("evidentiable, not preventable") applied one platform
down, and it should become its own threat-model row rather than a paragraph
in a README:

> **PT19 (proposed) - process-identity forgery on the host.** An adversary
> with code execution on the approver's host presents a process that appears
> to be `pirx-gate`. Control: none that a user-mode process can offer
> against a peer at its own privilege level. Evidence: the ledger is
> hash-chained and written by the real gate, so a forged gate produces
> actions with no chain-consistent record. Accepted with named trigger:
> **the moment the gate runs on a host the approver does not control**, this
> becomes a control row and requires attestation the launcher cannot
> currently provide.

### 1.4 What was not found

No source was found establishing a Windows equivalent of macOS's *stable
cdhash across interpreter updates* - the property the macOS artefact already
qualifies. Absent evidence, the Windows artefact must not claim it.
[measured absence, not proof of absence]

---

## 2. The MCP interception point, under the 2026-07-28 specification

The gate design v1.1 was written against a reading of the spec from search
results. The primary sources have now been read: the specification changelog
and the release announcement. Four things change the design, one of them
substantially.

### 2.1 Statelessness helps the thesis, unexpectedly

The `initialize`/`initialized` handshake and the `Mcp-Session-Id` header are
**removed**; every request carries its protocol version and client
capabilities in `_meta`, and servers implement a `server/discover` RPC that
clients *may* call. `server/discover` is explicitly usable as a
backward-compatibility probe on **stdio**, which confirms stdio remains a
supported transport. [measured]

Two consequences:

- **stdio-first stays viable, and so does stdlib-only for 0.7.0.0.** The
  gate spawns the downstream server and speaks JSON-RPC over pipes; no HTTP
  server is required to ship the first gate. [inference from the measured
  stdio support]
- **There is no protocol session for authority to accumulate in.** A
  design whose whole thesis is "no ambient authority, no session-scoped
  permission" is now aligned with the protocol rather than fighting it. The
  spec's own guidance - if you need cross-call state, mint an explicit
  handle and pass it as a tool argument - is structurally the same move as
  a grant bound to an action. [inference]

### 2.2 MRTR replaces elicitation, and it is the stall mechanism the gate needs

Server-initiated `elicitation/create`, `sampling/createMessage`, and
`roots/list` are gone. In their place: **Multi Round-Trip Requests**. A
server returns an `InputRequiredResult` (`resultType: "input_required"`)
carrying `inputRequests`; the client **retries the original request** with
`inputResponses` attached. Servers needing to correlate across retries
encode their own identifier in `requestState`. All results now carry a
required `resultType`, and clients must treat a missing one as `"complete"`.
[measured]

This resolves a problem the v1.1 design left open: how a gate holds a call
while a human approves, without holding a connection open. It does not
require blocking, a stream, or a session.

**It also creates the temptation PT17 exists to refuse.** MRTR renders in
the calling agent's host. Routing the *approval* through it would put the
approval prompt inside the trust domain of the party under review - PT6 one
layer up. The refinement, which must be written into PT17 rather than
discovered during implementation:

> The gate MAY use MRTR as a **retry ticket**: an `input_required` result
> whose `inputRequests` say only that an out-of-band approval is pending and
> that the call may be retried, correlated by an opaque identifier in
> `requestState`. The gate MUST NOT place the rendered proposal bytes, the
> attention challenge, or any field that could carry an approval token into
> `inputRequests`, and MUST NOT accept anything arriving in `inputResponses`
> as evidence of approval. Approval is read from Pirx's own surface and from
> the grant store; the client's retry is a poll, never a decision.

`requestState` is the right place for the correlation id precisely because
it is the server's own opaque value, and an opaque poll ticket that grants
nothing is safe to hand to an untrusted client. [inference]

### 2.3 Header-based routing: useful, and a new divergence to refuse

Streamable HTTP POSTs must now carry `Mcp-Method` and `Mcp-Name` headers so
gateways can route and authorise without parsing bodies; the spec defines a
`HeaderMismatchError` (renumbered to `-32020`). [measured]

For Pirx this is a threat, not a feature, and the reason is the thesis:
**what is hashed must be what executes.** A gate that decides "is this tool
gated?" from a header while forwarding a body that names a different tool
has re-created the shown-vs-executed divergence at the transport layer.

> **PT20 (proposed) - header/body divergence at the gate.** Control: gating
> decisions and the justification digest derive from the **parsed body**,
> never the routing headers; a mismatch between `Mcp-Name` and the body's
> `params.name` is a typed refusal, not a normalisation. Headers may be used
> for routing and metrics only.

### 2.4 Tool-definition drift, against a caching protocol

`tools/list` results now carry `ttlMs` and `cacheScope` (`"public"` or
`"private"`, controlling whether shared intermediaries may cache), and
servers SHOULD return tools in a deterministic order. [measured]

PT16 (rug-pull: the tool definition changes between approval and spend)
therefore cannot lean on the client re-fetching, and a gate is itself the
"shared intermediary" the cache scope talks about. The gate must fetch and
fingerprint tool definitions on its own schedule and treat a cached
catalogue as evidence of nothing. The deterministic ordering requirement
helps: a stable order means a fingerprint over the catalogue is stable for
the right reason rather than by luck. [inference]

### 2.5 Deprecations that constrain what may be built

Roots, Sampling, and Logging are deprecated with a twelve-month minimum
window; the legacy HTTP+SSE transport likewise; Dynamic Client Registration
is deprecated in favour of Client ID Metadata Documents; SSE resumability
and message redelivery are removed, so a broken stream loses the in-flight
request and the client must re-issue with a new request id. [measured]

The gate builds on none of these. Suggested logging migration for stdio
servers is stderr, which is where a stdio gate's own diagnostics belong
anyway - the ledger is the audit record, stderr is for operators. [measured
guidance; the split is this project's own]

### 2.6 Net effect on the 0.7.0.0 design

The v1.1 gate design survives, with four amendments: MRTR as poll-only stall
(PT17 refinement), body-authoritative gating (PT20), self-fetched tool
fingerprints (PT16 sharpened), and protocol-version validation on arrival as
ordinary hostile-input discipline - every request now carries its own
version, and an unknown one is a refusal rather than a best-effort parse.

---

## 3. F43 resolved: `Proposal.verdict` goes, at 0.7.0.0

The question left open by the 0.6.0.0 review: does `Proposal` keep both
`verdict` and `justification`, or does the justification become the only
answer?

**Recommendation: remove `verdict` as a distinct field, at 0.7.0.0, coupled
with the other format changes that version already owes.**

The reasoning is that with adapter #2 the field is not merely redundant, it
is *false*. An intercepted `tools/call` has no verdict. A field named
`verdict` holding an id like `mcp:tools/call#a1b2c3` is a lie in the type
system, and the same lie propagates into `Grant.verdict` and into the ledger
event fields an auditor reads. The 0.6.0.0 compromise (both fields, forbidden
to disagree) was correct for a version that shipped no second adapter; it
stops being correct on the day one exists.

The cost is honest and worth naming: this is three coupled format changes,
and they must land in **one** version rather than dribbling out (P5's
spirit, P8's rule):

| Change | New id | Why it cannot be an edit to the old id |
|---|---|---|
| Justification lines and the evidence digest enter the preimage | `pirx.proposal/2` | Every action hash changes; grants issued under `/1` must not verify under `/2` |
| `verdict` → `justification` in grant scope and ledger events | `pirx.ledger/2` | An auditor's query against field names is a consumer of this format |
| Adapter #2 exists | `pirx.intercepted-call/1` | New source, new id, never a repurposed one |

Consumer rule, per P8: `pirx verify` (T8, owned by 0.8.0.0) reads **both**
`pirx.ledger/1` and `/2` and says which it is reading, until `/1` is
explicitly retired. A ledger written under `/1` remains verifiable forever;
that is the whole point of hash-chaining it.

Migration is not required for grants - they are short-lived and single-use
by construction, so there is no population of long-lived `/1` grants to
carry across. That is the first time the grant TTL has paid a dividend
somewhere other than PT4. [inference]

---

## 4. What 0.7.0.0 now owes, in order

1. `pirx.proposal/2`: justification lines plus evidence digest in the
   preimage; `verdict` removed from `Proposal`; golden bytes for `/2`
   alongside the retained `/1` golden as a regression witness.
2. `pirx.ledger/2`: field rename, version marker in the genesis sentinel,
   and `verify` accepting both.
3. Adapter #2 (`pirx.intercepted-call/1`) with the tool-definition hash in
   scope (PT16).
4. `pirx-gate`: stdio pump, gated registry, body-authoritative gating
   (PT20), MRTR poll-only stall (PT17 refinement), protocol-version
   validation on arrival.
5. Threat model: PT16, PT17, PT18 as designed, plus **PT19** (process
   identity forgery, accepted with trigger) and **PT20** (header/body
   divergence).
6. Windows identity artefact, at the strength section 1.3 states and no
   more.
7. Harness: A37+ for header/body divergence, MRTR-as-approval-channel
   attempts, tool-definition drift between approval and spend, and a `/1`
   grant presented against a `/2` proposal.

Two of these (1 and 2) are breaking format changes and belong in the brief's
changelog as such, which makes 0.7.0.0 a brief bump to v1.5.
