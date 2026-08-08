# Pirx manual

> Codename **Pirx** (package `pirx`). Lem's pilot is trusted with a ship
> because he treats his own judgement as fallible and checks it against the
> instruments. This document is the instrument panel.

```
Document:  docs/MANUAL.md, version 2.0
Audience:  the operator - the person who runs Pirx, answers its prompts, and
           is asked afterwards what happened. Assumes competence, not
           familiarity
Companion: README (what Pirx is and is not), ARCHITECTURE (how it is built),
           THREAT-MODEL (what it defends against and what it does not)
Note:      every constant, event name, and exit code here was read out of the
           code, not recalled. Where a claim is weaker than it sounds, this
           document says so rather than rounding up
```

## Contents

1. [What Pirx does](#1-what-pirx-does)
2. [Install](#2-install)
3. [Choosing a topology](#3-choosing-a-topology)
4. [The gate](#4-the-gate)
5. [The runner](#5-the-runner)
6. [The approval prompt](#6-the-approval-prompt)
7. [Key management](#7-key-management)
8. [The ledger](#8-the-ledger)
9. [Directory lifecycle and pruning](#9-directory-lifecycle-and-pruning)
10. [Recovery procedures](#10-recovery-procedures)
11. [Monitoring and alerting](#11-monitoring-and-alerting)
12. [Reference: constants](#12-reference-constants)
13. [Reference: ledger events](#13-reference-ledger-events)
14. [Reference: refusals](#14-reference-refusals)
15. [Reference: exit codes and environment](#15-reference-exit-codes-and-environment)
16. [Troubleshooting](#16-troubleshooting)
17. [What Pirx will not do](#17-what-pirx-will-not-do)
18. [Glossary](#18-glossary)

---

## 1. What Pirx does

Pirx holds a high-impact action until a human has approved the exact bytes
that describe it, then hands over authority bound to the SHA-256 of those
bytes: valid once, expiring shortly, spendable on nothing else.

The sentence that matters most is the one about bytes. Most human-in-the-loop
systems show a person a *summary* and record a *boolean*. Pirx shows the
canonical byte sequence, hashes those same bytes, and binds the resulting
grant to that hash. What was approved and what executes cannot drift apart,
because they are the same object.

Two things can put an action in front of that approval:

| Entry point | The action comes from | You run |
|---|---|---|
| **The gate** | An MCP `tools/call` sent by an agent | `pirx-gate` + `pirx gate-approve` |
| **The runner** | A ranked CVE verdict from cve-digest | `pirx run` |

After the action exists, both paths are identical: render, challenge, decide,
issue, spend, execute, record.

---

## 2. Install

Python 3.14 or newer. The runtime has no third-party dependencies. The Jira
adapter uses `urllib`; the gate uses `subprocess` and `json`. Nothing in the
write path has a supply chain to audit.

```bash
git clone https://github.com/jerzy99jerzy/pirx.git
cd pirx
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

Two commands land on your PATH:

```bash
which pirx pirx-gate
```

Verify by running `pirx` with no arguments. It prints usage and exits 64.
There is no `--version` doctor command: a self-test that passes tells you less
than a run that stops honestly, and section 5 gives you one of those in thirty
seconds.

### 2.1 Virtual environments, and why you want two

If you are gating a downstream MCP server, that server almost certainly has
dependencies. Keep it in its **own** environment and point the gate at its
interpreter by absolute path:

```bash
python3 -m venv ~/mcp-lab && ~/mcp-lab/bin/pip install "mcp>=2"
pirx-gate ~/pirx-gate -- ~/mcp-lab/bin/python /path/to/server.py
```

Pirx stays stdlib-only in its runtime. Installing a server's dependencies into
Pirx's environment quietly gives that property away, and nothing will warn
you.

---

## 3. Choosing a topology

Pirx runs in one of two shapes, and which one you are in is decided by whether
a grant key file exists - not by a flag. A flag that selects a security
property is a security property that gets selected wrongly at 02:00.

### 3.1 Single process (the runner)

```
pirx run  ->  propose  ->  approve (same process)  ->  spend  ->  execute
```

With `PIRX_GRANT_KEY_FILE` **unset**, `pirx run` generates an ephemeral key in
memory. Grants are meaningless outside that process, which is the property the
project had by construction for its first six versions. Nothing to manage, no
key to lose.

### 3.2 Two processes (the gate)

```
agent host  ->  pirx-gate  ->  downstream MCP server
                    |
                    +--> pending/  ->  pirx gate-approve (a human, elsewhere)
                    |                          |
                    +<------ grants/ <---------+
```

The gate cannot host its own approval prompt: its stdin and stdout are the
JSON-RPC pipes, and an approval routed back through the protocol would render
inside the trust domain of the agent whose call is being reviewed. So the
human sits at a second process, and grants must verify across the boundary.
That requires a shared key, and the gate refuses to start without one.

**Two consequences of the split, stated because they are costs:**

- **Grant expiry runs on the wall clock.** A monotonic deadline is meaningless
  in a process that did not issue the grant. An operator who moves the system
  clock backwards extends a grant's life. That is smaller than a deadline no
  reader can evaluate, and it is a line in the threat model rather than a
  silence.
- **A grant is a file, and therefore copyable.** The MAC makes forgery hard;
  the durable spend store makes a copy useless; nothing makes the file secret,
  and no part of the design assumes it is.

---

## 4. The gate

### 4.1 Set up a gate directory

```bash
mkdir -p ~/pirx-gate
python3 -c "import secrets, pathlib; pathlib.Path('$HOME/pirx-gate/key').write_bytes(secrets.token_bytes(32))"
chmod 600 ~/pirx-gate/key
export PIRX_GRANT_KEY_FILE=$HOME/pirx-gate/key
```

The directory fills with five things:

```
~/pirx-gate/
  key            the shared HMAC key (yours to protect; see section 7)
  ledger.jsonl   the hash-chained record of everything that happened
  pending/       proposals rendered and waiting for a human
  grants/        issued grants, waiting to be spent, named by action hash
  spent/         one empty file per burnt nonce - the durable single-use record
```

### 4.2 Run it

```bash
pirx-gate ~/pirx-gate -- ~/mcp-lab/bin/python /path/to/downstream_server.py
```

Everything after `--` is the downstream server's command, exactly as you would
have typed it. **It is the only command the gate will ever spawn.** Nothing
from a payload, a tool definition, or a model can reach that argv; a structural
test asserts exactly one `Popen`, taking its command from the stored
constructor argument, never through a shell.

In an agent host's configuration file:

```json
{
  "mcpServers": {
    "gated-repo": {
      "command": "/Users/you/pirx/.venv/bin/pirx-gate",
      "args": ["/Users/you/pirx-gate", "--",
               "/Users/you/mcp-lab/bin/python", "/path/to/server.py"],
      "env": { "PIRX_GRANT_KEY_FILE": "/Users/you/pirx-gate/key" }
    }
  }
}
```

Use absolute paths for everything. An agent host does not inherit your shell.

### 4.3 The first run gates nothing

The gated registry ships **empty**, exactly as the capability registry did in
0.1.0.0: the machinery runs and guards nothing until you register a tool.

This is the intended first experience. Send a few calls, watch the ledger fill
with `gate.forwarded_ungated`, and satisfy yourself that the plumbing works
before you make anything refuse. A gate that refuses on day one teaches you
nothing about whether it is wired correctly.

### 4.4 Register a tool to be gated

A code change, reviewed like one. There is no runtime path that adds a gated
tool, and there will not be.

**Step 1** - get the definition hash of the tool as your downstream server
currently publishes it. Take the definition from the server's `tools/list`
output; do not retype it from documentation.

```python
from pirx.mcp.protocol import tool_definition_hash

definition = {
    "name": "repo.write_file",
    "description": "Write a file",
    "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
}
print(tool_definition_hash(definition))
```

**Step 2** - add the entry in `pirx/mcp/gate.py`:

```python
PRODUCTION_GATED_REGISTRY = GatedRegistry((
    GatedTool(tool="repo.write_file", definition_hash="e139b922..."),
))
```

**Step 3** - review the diff as you would review a capability. You are
recording that you read this tool's definition and consider calls to it worth
a human's attention.

**Why the hash is pinned.** If the downstream server later changes that tool's
definition - a widened schema, a rewritten description that instructs a model
differently - the gate refuses with `refusal.tool_definition_drift` instead of
silently gating a tool that is no longer the one you reviewed. Re-pinning is a
deliberate act, and that is exactly the review moment a rug-pull needs to hit.

The hash is also **inside the action hash**, so even without the check a grant
approved under one definition cannot be spent against a proposal built under
another.

### 4.5 What the caller sees while waiting

```json
{"result": {"resultType": "input_required",
            "inputRequests": [{"type": "notice",
              "message": "pirx: human approval pending out-of-band; retry this request to learn the outcome"}],
            "requestState": {"pirx.ticket": "c7ccc749..."}}}
```

A Multi Round-Trip Request poll ticket, and nothing more. No proposal bytes,
no action hash, no field an approval could be written into. Retrying is how
the caller learns the outcome; the ticket is opaque and grants nothing.

The gate never reads `inputResponses` as evidence of approval. A client can
send whatever it likes there and it will be ignored.

### 4.6 Approving

In a second terminal, at a keyboard:

```bash
export PIRX_GRANT_KEY_FILE=$HOME/pirx-gate/key
pirx gate-approve ~/pirx-gate
```

It walks the pending queue **once** and exits. A proposal that arrived while
it was running needs another invocation. This is deliberate: a resident
approval daemon is a process holding the key, waiting, which is most of the
way back to a session.

---

## 5. The runner

```bash
pirx run examples/verdict-sample.json my-ledger.jsonl
```

With no ticket credentials, the run walks the entire pipeline - parse,
propose, render, approve, issue, spend - and stops at the write with
`refusal.adapter_unavailable`. Nothing is written anywhere. That is the
intended first experience: the trust machinery is observable before anything
can act.

### 5.1 Wiring the ticket adapter

Three variables, all or none. No partial configuration, no credential
discovery, no prompting.

```bash
export PIRX_JIRA_BASE_URL="https://your.atlassian.net"
export PIRX_JIRA_EMAIL="you@example.com"
export PIRX_JIRA_TOKEN="..."
```

### 5.2 Model assistance (optional)

```bash
export PIRX_ANTHROPIC_API_KEY="..."
```

Unset, the proposer is deterministic. Set, a model may do exactly two things:
select an action by **exact string match** against a fixed list, and write a
rationale. It supplies no parameter, no target, and no authority. An
out-of-contract reply is `refusal.model` and the run stops - it does not fall
back to the deterministic mapping, because a silent downgrade would make "a
model chose this" and "code chose this" indistinguishable on your screen.

Either way the run records `proposer.mode`. Which mind wrote the sentence you
approved should never have to be inferred from an environment variable someone
forgot was set.

---

## 6. The approval prompt

The part that matters, and the part no other tool asks of you.

### 6.1 The frame

```
--- begin canonical proposal bytes [ce631315...] (these are the hashed bytes) ---
pirx.proposal/2
action: ticket.comment
target: ticket:CVE-2026-2100
justification.schema: cve-digest.verdict/1
justification.ref: cve-digest.verdict/1#CVE-2026-2100
justification.digest: 7027b59d...
param.cve_id: CVE-2026-2100
param.priority: P1
~~~pirx-untrusted-0 begin triage_note (origin=producer, chars=61, escaped, NOT a decision input)
  Observed exploitation against edge appliances.
~~~pirx-untrusted-0 end triage_note
bytes: 881
--- end canonical proposal bytes [ce631315...] ---
action hash: ede25aa0...
proposal age: 0.4s (decision aid; not covered by the hash, not an integrity control)
```

Read it in this order:

1. **`action` and `target`** - what will happen, and to what. If either
   surprises you, decline. Everything else is context for that decision.
2. **`justification.*`** - why. The `ref` identifies the evidence; the
   `digest` is a hash over that evidence's own canonical form. For a gated
   tool call the justification also carries `tool`, `tool_definition_hash`,
   and the full canonical `arguments`.
3. **`param.*`** - the exact parameters the action will carry. These come from
   deterministic fields only. A model or a producer can never fill one.
4. **Anything inside a `~~~pirx-untrusted-N` fence** - text written on the far
   side of a trust boundary. Escaped, labelled with its origin, and filling
   nothing. Read it as context; never as instruction.

Three properties of the frame worth knowing:

- **These bytes are the hash preimage.** Not a summary of what will happen -
  the thing itself.
- **The boundary marker is random per presentation** and is chosen so it does
  not occur inside the enclosed text. A payload cannot forge the frame's own
  end and make you think the proposal stopped earlier than it did.
- **`proposal age` is a decision aid, not a control.** It is not covered by
  the hash. Grant expiry starts at issue, which is after you decide, so a
  stale proposal is a decision-quality question and not an integrity one.

### 6.2 The attention challenge

```
attention challenge - transcribe the value of 'justification' exactly as rendered above:
```

The field is selected **by the action hash**, so it cannot be predicted before
the bytes exist and yesterday's answer will not work today. Find it in the
frame and type it.

A wrong answer is `refusal.challenge_failed`. The proposal is not approved and
is presented again from the top. There is no retry counter to grind against,
and the ledger records which field was challenged but never the expected value
- a ledger that carried the answer would be a cheat sheet.

**What this proves:** that you operated on the exact hashed bytes - located a
field in them and answered within a measured interval.

**What it does not prove:** that you understood them. Pirx never claims it
does, and no document in this repository writes "understood" where the
measurement supports only "read".

### 6.3 The decision

```
type 'approve' or 'decline' (no single-key shortcut, by design):
```

The full word. A habituated `y` is approval fatigue in miniature.

An **approving** answer arriving faster than a floor derived from the byte
length is `refusal.reading_floor`. Declining is never floor-checked: refusing
fast is not the threat.

**You cannot script this.** Piping answers in trips the floor, by design. If
you find yourself wanting to, the volume is wrong, not the control.

### 6.4 What gets recorded

```json
{
  "approved": true,
  "approver_claim": "jerzy90",
  "authenticated": false,
  "challenge_field": "justification",
  "challenge_passed": true,
  "elapsed_seconds": 90.401,
  "floor_seconds": 3.742
}
```

`approver_claim` comes from the process environment. It sits beside
`authenticated: false` in the same record, because Pirx does not authenticate
you and the ledger must not let a reader mistake a claim for an identity.

**Read `elapsed_seconds` honestly.** It measures presence at the terminal, not
attention. Ninety seconds may be ninety seconds of reading or ninety seconds
of a phone call. One sample tells you only that the approval was not
reflexive, which is exactly what the floor claims and nothing more.

---

## 7. Key management

The grant key is shared between `pirx-gate` and `pirx gate-approve`. It is the
only secret Pirx holds.

### 7.1 Generating

```bash
python3 -c "import secrets, pathlib; pathlib.Path('key').write_bytes(secrets.token_bytes(32))"
chmod 600 key
```

32 bytes is the minimum, enforced in code. A shorter key is refused at
startup: a short key is a long key that was never generated properly.

### 7.2 What the key does and does not do

- **Does**: let the gate verify that a grant was issued by something holding
  the same key, in a process the gate did not run.
- **Does not**: encrypt anything, authenticate the approver, or make the grant
  file secret. A grant is signed, not sealed.

### 7.3 Rotation

There is no rotation command, and that is not an oversight - rotation is three
deliberate steps, and a command that did them silently would hide which grants
died:

1. Stop the gate.
2. Replace the key file.
3. Restart. **Every outstanding grant in `grants/` is now unverifiable** and
   will be refused with `refusal.grant_mac`. Delete them, or leave them and
   read the refusals as the record of what rotation cost.

Rotate when the key may have been read by anything you do not control. There
is no scheduled rotation, because a grant lives for five minutes and a key
that leaks is an incident, not a calendar item.

### 7.4 If the key is lost

Outstanding grants become unverifiable; nothing else is lost. The ledger is
not encrypted and stays readable and verifiable. Generate a new key, restart,
and re-approve whatever was pending.

### 7.5 If the key is stolen

An attacker holding the key can forge grants. What they still cannot do:

- **Spend one twice.** The durable spend store is on the gate's filesystem,
  not in the grant.
- **Spend one against different bytes.** The action hash binds the grant to
  one specific rendered proposal.
- **Act without leaving a record.** The gate writes `grant.spent` and
  `gate.forwarded_granted` for anything it forwards.

A stolen key therefore buys the ability to approve without a human, once per
distinct action, visibly. Treat it as an incident, rotate, then read the
ledger for grants you did not issue.

---

## 8. The ledger

Everything is an event. The file is the audit trail, and it is the artefact
you will be asked for.

### 8.1 Record shape

One JSON object per line, canonically serialised, fsynced on write:

```json
{
  "event": "run.started",
  "payload": {"payload": "verdict-sample.json"},
  "prev_hash": "10b87dfa...",
  "seq": 0,
  "ts": "2026-08-08T18:08:48.588648+00:00"
}
```

`prev_hash` chains each record to the previous one. The first record chains a
documented genesis sentinel, so a verifier can tell a fresh ledger from one
whose head was replaced.

### 8.2 Verifying

```bash
pirx verify my-ledger.jsonl
```

```
pirx.ledger/2: 20 record(s), chain intact
tail truncation is NOT detected; a remote append-only sink is what buys that
```

That second line is not boilerplate. The chain detects **edits** and
**interior gaps**. It does **not** detect removal of the last N records,
because a truncated chain is internally consistent. Buying that property means
shipping records off the host as they are written, and Pirx does not do it for
you.

`pirx.ledger/1` predates the gate and remains verifiable. Retiring a format's
writer is not retiring its reader.

### 8.3 Reading a run

```bash
python3 -c "
import json
for line in open('my-ledger.jsonl'):
    r = json.loads(line)
    print(f\"{r['seq']:>3} {r['event']:<28} {json.dumps(r['payload'])[:80]}\")"
```

A completed gated call:

```
  0 gate.started                  pid, executable, downstream command
  1 gate.pending                  a proposal was rendered and queued
  2 gate.awaiting_approval        the caller got a ticket; nothing forwarded
  3 gate.presented                a human saw the bytes
  4 attention.challenge_issued    intent, recorded before the answer
  5 approval.decided              with elapsed_seconds and floor_seconds
  6 grant.issued
  7 gate.forwarded_granted        the original bytes went downstream
  8 refusal.spent_grant           an immediate replay, refused
```

### 8.4 Three habits worth forming

**Absence is evidence.** No `grant.issued` for a proposal means nothing was
authorised. An action that landed on a target with no grant event in any
ledger did not come through Pirx - which is how gate bypass becomes visible.

**`grant.spent` followed by a refusal is normal and important.** Authority is
consumed *before* the action runs, so a crash mid-action leaves a spent grant
and no result. Pirx will not retry: re-issuing is a human decision made with
the ledger in hand.

**An open tail is information.** A `challenge_issued` with no successor means
someone was interrupted mid-approval. Intent precedes action here precisely so
that an interruption leaves a missing record rather than silence.

---

## 9. Directory lifecycle and pruning

Nothing in the gate directory expires on its own, and that is deliberate.

| Directory | Grows with | Safe to prune? |
|---|---|---|
| `pending/` | every distinct gated call | Yes, once approved or abandoned. A pending file is a rendered proposal; deleting it loses the record of what was asked |
| `grants/` | every approval | Yes, after the grant is spent or expired. An unspent, unexpired grant is live authority - deleting it cancels it |
| `spent/` | every spent grant, forever | **No.** Each file is the durable proof that a nonce is burnt. Pruning is a replay window with a timer on it |
| `ledger.jsonl` | every event | **No.** Truncation is undetectable by design (§8.2) |

If `spent/` size becomes a real problem, the answer is archival alongside the
ledger, not deletion: the two records are read together, and one without the
other answers half a question.

---

## 10. Recovery procedures

### 10.1 A run was interrupted mid-action

```bash
pirx reconcile my-ledger.jsonl
```

It asks the target system whether the write landed, using the idempotency key
embedded in the action, and **reports**. It never re-executes. An automatic
retry carrying authority across a crash is the privilege-persistence failure
this design exists to refuse.

If reconciliation says the write did not land and you still want it: approve a
new proposal. That is one more human decision, made with the full record in
front of you, which is the correct price.

### 10.2 The gate's downstream server died

The pump exits 74 and records `gate.downstream_gone`. It does **not** restart
the child: a supervisor that silently respawned it would hide the crash the
ledger exists to show. Restart the gate yourself once you know why the server
died.

### 10.3 The ledger fails verification

`refusal.ledger_chain` names the line and the sequence number where the chain
broke. Treat it as an incident, not a corruption to repair:

- **A seam** (`prev_hash` mismatch) means a record was edited or replaced.
- **A sequence gap** means a record was removed from the interior.

Do not "fix" the file. Preserve it, and reconstruct what happened from the
target system and any off-host copy. A repaired ledger is a ledger nobody can
rely on afterwards.

### 10.4 A grant is refused unexpectedly

Each refusal names exactly one cause.

| Refusal | Means |
|---|---|
| `refusal.grant_mac` | the key changed, or the grant came from elsewhere |
| `refusal.hash_mismatch` | the bytes changed after approval - most often a tool definition or an argument |
| `refusal.target_mismatch` | the grant is for a different target |
| `refusal.expired_grant` | more than five minutes passed between issue and spend |
| `refusal.spent_grant` | a replay, or a retry after a crash that had already spent it |

---

## 11. Monitoring and alerting

The ledger is JSON lines and is designed to be shipped. Every event has a
stable name; payload keys are stable within a name.

**Alert on these:**

| Event | Why |
|---|---|
| `refusal.grant_mac` | someone presented a grant this gate did not issue |
| `refusal.tool_definition_drift` | a downstream tool changed under a pinned hash |
| `refusal.header_mismatch` | a peer's routing headers disagreed with its body |
| `refusal.ledger_chain` | the audit trail itself failed verification |
| `gate.oversized_frame` | a peer sent something past the frame bound |

**Trend these, do not alert:**

| Signal | What it tells you |
|---|---|
| `approval.decided.elapsed_seconds` distribution | approvals clustering just above the floor is the fatigue picture; the upper tail is noise |
| `refusal.challenge_failed` rate | rising means approvers are answering without reading |
| `refusal.session_budget` | the volume is beyond what one session should carry |
| `gate.forwarded_ungated` vs `gate.forwarded_granted` | how much of your traffic the registry actually covers |

**The alert nobody can write for you:** an action appearing in your target
system with no corresponding `gate.forwarded_granted` anywhere. Pirx cannot
detect that from inside, and it is the reason the ledger is worth shipping to
a place the gate's host cannot rewrite.

---

## 12. Reference: constants

Every limit that exists for a security reason is a constant in code. There is
no configuration file, and adding one would be a rejected change.

| Constant | Value | What it bounds |
|---|---|---|
| `MAX_PROSE_CHARS` | 2 000 | Producer or model text kept per field; the rest is truncated and recorded |
| `MAX_PROPOSALS_PER_RUN` | 10 | Proposals a single run will put in front of a human |
| `GRANT_TTL_SECONDS` | 300.0 | Grant lifetime, from issue to spend |
| `READING_FLOOR_BASE_SECONDS` | 2.0 | Fixed part of the approval floor |
| `READING_FLOOR_SECONDS_PER_KIB` | 2.0 | Per-kilobyte part of the approval floor |
| `MAX_GRANTS_PER_SESSION` | 20 | Grants one issuer produces before refusing |
| `MAX_CALL_ARGUMENT_CHARS` | 4 000 | Canonical argument JSON accepted from an intercepted call |
| `MIN_GRANT_KEY_BYTES` | 32 | Shortest accepted grant key |
| `MAX_FRAME_BYTES` | 1 000 000 | Longest JSON-RPC line the pump will read |

The reading floor for a proposal is `2.0 + 2.0 x (byte_length / 1024)`
seconds. For an 892-byte proposal that is 3.742 s - checkable with a
calculator, which is the point.

**Schema identifiers**

| Id | Role |
|---|---|
| `cve-digest.verdict/1` | the verdict payload Pirx consumes |
| `pirx.proposal/2` | the canonical proposal rendering |
| `pirx.ledger/2` | the current ledger format (`/1` still readable) |
| `pirx.intercepted-call/1` | the justification produced from an MCP call |
| `2026-07-28` | the only MCP protocol revision the gate accepts |

---

## 13. Reference: ledger events

| Event | Emitted when |
|---|---|
| `run.started` | a run begins; carries payload name, ledger schema, budget |
| `payload.accepted` | a verdict payload passed validation |
| `proposer.mode` | records whether a model was involved |
| `proposal.created` | a proposal was built from a justification |
| `proposal.rendered` | canonical bytes and an action hash exist |
| `prose.truncated` | producer or model text exceeded the bound |
| `review_lane.collision` | an item appeared in both the digest and the review lane |
| `attention.challenge_issued` | the challenge was shown, before the answer |
| `approval.decided` | a human answered; carries attention evidence |
| `grant.issued` | authority was created |
| `grant.spent` | the nonce was burnt; carries the nonce alone |
| `capability.attempt` | the action is about to run |
| `capability.result` | the action returned |
| `capability.outcome_unknown` | the process died between attempt and result |
| `capability.outcome_reconciled` | reconciliation established what happened |
| `run.finished` | the run ended; carries the exit code |
| `gate.started` | the pump came up; pid, executable, downstream command |
| `gate.pending` | a gated call was rendered and queued |
| `gate.awaiting_approval` | a poll ticket was returned |
| `gate.presented` | a pending proposal was shown to a human |
| `gate.forwarded_ungated` | a call not in the gated registry passed through |
| `gate.forwarded_granted` | a gated call was released under a spent grant |
| `gate.oversized_frame` | a line past `MAX_FRAME_BYTES` was refused and drained |
| `gate.downstream_gone` | the child closed its pipe |
| `gate.stopped` | the pump exited |
| `refusal.*` | see section 14 |

---

## 14. Reference: refusals

Every refusal is a typed event. None is a warning, and none lets execution
continue.

**Payload and parsing**

| Event | Cause |
|---|---|
| `refusal.schema` | the payload's schema id is not one Pirx consumes |
| `refusal.bounds` | a field exceeded a hard bound |
| `refusal.malformed_id` | a CVE id did not match the anchored pattern |
| `refusal.enum` | a field carried a value outside its permitted set |
| `refusal.budget` | the run's proposal budget is exhausted |

**Approval and attention**

| Event | Cause | Usually means |
|---|---|---|
| `refusal.challenge_failed` | transcription did not match | reading the wrong window, or not reading |
| `refusal.reading_floor` | an approval arrived below the floor | a piped or reflexive answer |
| `refusal.session_budget` | too many grants in one session | rotate the session |
| `refusal.declined` | a human said no | nothing is wrong |

**Grants**

| Event | Cause |
|---|---|
| `refusal.hash_mismatch` | the grant does not cover these bytes |
| `refusal.target_mismatch` | the grant is for another target |
| `refusal.expired_grant` | the deadline passed before the spend |
| `refusal.spent_grant` | a replay: the nonce is already burnt |
| `refusal.grant_mac` | not issued by a holder of this key |
| `refusal.malformed_grant` | the grant file's shape is wrong |

**The gate**

| Event | Cause |
|---|---|
| `refusal.protocol` | the frame is not valid JSON-RPC |
| `refusal.protocol_version` | the peer speaks an MCP revision Pirx does not |
| `refusal.header_mismatch` | a routing header disagreed with the body |
| `refusal.tool_definition_drift` | the definition changed since you pinned it |

**Execution**

| Event | Cause |
|---|---|
| `refusal.unregistered_action` | the action is not in the capability registry |
| `refusal.adapter_unavailable` | registered, but nothing is wired to perform it |
| `refusal.model` | the model returned something out of contract |
| `refusal.ledger_chain` | the ledger has a seam or a sequence gap |

**One event you should never see**

`refusal.unspecified` is the default on the base `Refusal` class and no
subclass uses it. If it appears in a ledger, a refusal type was added without
naming its event - a defect in Pirx, not a condition in your environment.
Report it with the surrounding records.

---

## 15. Reference: exit codes and environment

| Code | Meaning |
|---|---|
| 0 | the run completed; every proposal reached a decision |
| 2 | the payload was refused before any proposal existed |
| 3 | a refusal fired inside the loop |
| 64 | usage error |
| 74 | the gate's downstream server died |
| 78 | required configuration is absent |

| Variable | Read by | Effect if unset |
|---|---|---|
| `PIRX_GRANT_KEY_FILE` | gate, `gate-approve`, runner | Runner generates an ephemeral key; the gate refuses to start |
| `PIRX_JIRA_BASE_URL` / `_EMAIL` / `_TOKEN` | Jira adapter | The write refuses with `refusal.adapter_unavailable` |
| `PIRX_ANTHROPIC_API_KEY` | model client | The proposer is deterministic |

**The test suite strips all of these**, automatically. A suite that passes only
in a clean shell reports the shell rather than the code.

---

## 16. Troubleshooting

**`command not found: pirx`** - you are in a different virtual environment.
The downstream server usually lives in its own venv; that is correct, and it
is not the one Pirx is installed into.

**`refusal.protocol_version` on every call** - the peer is speaking an older
MCP revision. Pirx accepts `2026-07-28` only, and most SDKs still default to
the 2025 era unless the new revision is opted into explicitly. This is a real
limitation, not a misconfiguration: supporting the older era would bring back
the `initialize` handshake and a protocol session, which is the ambient state
the design is glad to be rid of.

**`PIRX_GRANT_KEY_FILE must name a key file`** - the gate verifies grants
another process issued. The runner may generate an ephemeral key because it
approves and executes in one process; the gate may not.

**The gate forwards everything and holds nothing** - the gated registry is
empty. That is the shipped state; see §4.4.

**`refusal.tool_definition_drift` after upgrading a server** - the definition
you pinned no longer matches. Re-derive the hash, read what changed, and
re-pin deliberately. This is the control working.

**`gate-approve` exits immediately** - the pending queue is empty, or every
pending proposal already has a grant. It walks the queue once by design.

**An approval "hangs"** - it is waiting for you to type. There is no timeout
on the prompt, because a prompt that expires would train you to answer fast.

**Tests fail with `FileNotFoundError` on a key path** - you are running a
checkout older than 0.7.1.0. The suite has stripped Pirx's environment since.

---

## 17. What Pirx will not do

Load-bearing, not modesty. Each is a decision with reasoning in the threat
model.

- **It does not authenticate you.** `approver_claim` comes from the
  environment and is recorded with `authenticated: false`.
- **It does not prevent gate bypass.** An agent host that launches the
  downstream server directly never passes through the gate. Prevention lives
  in your environment - hold downstream credentials only in the gate's
  environment, and allowlist by process identity. What Pirx gives you is
  detectability.
- **It does not measure comprehension.** See §6.2.
- **It is not a policy engine.** No risk scoring, no rule language, no
  auto-approve threshold. A tool is gated or it is not.
- **It does not do discovery, inventory, or payload inspection.**
- **It does not retry.** Ever. See §10.1.
- **It has no configurable security limits.** See §12.
- **It sends nothing back to the ranking system.** Not at runtime, and not
  through development-time automation.

---

## 18. Glossary

**Action hash** - SHA-256 of the canonical rendered proposal. The identity of
one fully-specified action.

**Attention evidence** - what the approval surface measured: which field was
challenged, whether the answer matched, elapsed time, and the floor.

**Canonical bytes** - the one rendering of a proposal. Shown to the human,
hashed for the grant, and never regenerated by a second code path.

**Gated tool** - an MCP tool registered in code, with the hash of the
definition its reviewer read, whose calls the gate holds for approval.

**Grant** - authority bound to one action hash, single-use, expiring, MAC'd so
another process can verify it.

**Justification** - why an action is warranted: a schema id, a reference, a
digest over the source's own evidence, and any extra deterministic lines.
Either a CVE verdict or an intercepted call.

**Nonce** - a grant's unique identifier, burnt in the spend store on use.

**Poll ticket** - the opaque identifier the gate returns while a call waits for
a human. Carries no authority and no proposal content.

**Reading floor** - the minimum elapsed time before an approving answer is
accepted, derived from the proposal's byte length.

**Spend store** - a directory with one file per burnt nonce, created with
`O_EXCL` so two processes racing the same grant produce exactly one winner.

**Untrusted prose fence** - the labelled block around text written by a
producer or a model. Escaped, bounded, and never a decision input.
