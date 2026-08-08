# Pirx manual

> Codename **Pirx** (package `pirx`). Lem's pilot is trusted with a ship
> because he treats his own judgement as fallible and checks it against the
> instruments. This document is the instrument panel.

```
Document:  docs/MANUAL.md, version 1.0 (ships with 0.7.1.0)
Audience:  the operator - the person who runs Pirx and answers its prompts.
           Assumes competence, not familiarity: no concept is explained twice
           and none is assumed known the first time
Companion: README (what Pirx is and is not), ARCHITECTURE (how it is built),
           THREAT-MODEL (what it defends against and what it does not)
```

Pirx holds a high-impact action until a human has approved the exact bytes
that describe it, then hands over authority bound to the hash of those bytes:
valid once, expiring shortly, spendable on nothing else.

There are two ways an action arrives, and they share every part of the trust
loop after that:

| Entry point | Action comes from | Command |
|---|---|---|
| **The gate** | An MCP `tools/call` from an agent | `pirx-gate` + `pirx gate-approve` |
| **The runner** | A ranked CVE verdict from cve-digest | `pirx run` |

---

## 1. Install

Python 3.14 or newer. The runtime has no third-party dependencies: the Jira
adapter uses `urllib`, the gate uses `subprocess` and `json`. Nothing in the
write path has a supply chain to audit.

```bash
git clone https://github.com/jerzy99jerzy/pirx.git
cd pirx
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

That puts two commands on your PATH: `pirx` and `pirx-gate`.

Verify:

```bash
pirx
```

It prints usage and exits 64. That is the whole install check - Pirx has no
`--version` doctor command, because a self-test that passes tells you less
than a run that stops honestly.

**A note on virtual environments.** If you are gating a downstream MCP server
that has its own dependencies, keep it in a *separate* venv and point the gate
at that interpreter by absolute path. Pirx stays stdlib-only in its runtime,
and mixing the two environments quietly gives up that property.

---

## 2. The gate

### 2.1 What it does

`pirx-gate` is launched by an agent host **in place of** the MCP server the
host meant to talk to. It spawns that server as a child and sits on the wire
between them. A tool call naming a **gated tool** is held: the gate renders a
canonical proposal, writes it to a queue, and answers the caller with a poll
ticket. Only when a human has approved those exact bytes does the call go
through - once.

A tool that is *not* in the gated registry is forwarded unchanged and recorded
as ungated. That is a registry decision reviewed like code, not an approval
that was skipped.

### 2.2 Set up a gate directory

The gate and the approval surface are separate processes, so they need a
shared key. 32 bytes is a floor in code, not a setting.

```bash
mkdir -p ~/pirx-gate
python3 -c "import secrets, pathlib; pathlib.Path('$HOME/pirx-gate/key').write_bytes(secrets.token_bytes(32))"
chmod 600 ~/pirx-gate/key
export PIRX_GRANT_KEY_FILE=$HOME/pirx-gate/key
```

The directory fills with four things as you use it:

```
~/pirx-gate/
  key            the shared HMAC key
  ledger.jsonl   the hash-chained record of everything
  pending/       proposals waiting for a human
  grants/        issued grants, waiting to be spent
  spent/         one empty file per burnt nonce - the durable single-use record
```

### 2.3 Run it

```bash
pirx-gate ~/pirx-gate -- python3 /path/to/downstream_server.py
```

Everything after `--` is the downstream server's command, exactly as you would
have launched it yourself. It is the **only** command the gate will ever
spawn: nothing from a payload, a tool definition, or a model can reach that
argv, and a test asserts it structurally.

In an agent host's config, the same thing looks like:

```json
{
  "command": "pirx-gate",
  "args": ["/Users/you/pirx-gate", "--", "python3", "/path/to/server.py"],
  "env": { "PIRX_GRANT_KEY_FILE": "/Users/you/pirx-gate/key" }
}
```

**The first run gates nothing.** The gated registry ships empty, exactly as
the capability registry did in 0.1.0.0: the machinery runs and guards nothing
until you register a tool. Watch the ledger fill with `gate.forwarded_ungated`
and confirm the plumbing works before you make it refuse anything.

### 2.4 Register a tool to be gated

This is a code change, reviewed like one. There is no runtime path that adds a
gated tool, and there will not be.

First, get the definition hash of the tool as your downstream server currently
publishes it:

```python
from pirx.mcp.protocol import tool_definition_hash

definition = {
    "name": "repo.write_file",
    "description": "Write a file",
    "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
}
print(tool_definition_hash(definition))
```

Then add the entry in `pirx/mcp/gate.py`:

```python
PRODUCTION_GATED_REGISTRY = GatedRegistry((
    GatedTool(tool="repo.write_file", definition_hash="e139b922..."),
))
```

Pinning the hash is the point. If the downstream server later changes that
tool's definition - a widened schema, a rewritten description - the gate
refuses with `refusal.tool_definition_drift` instead of silently re-approving
a tool that is no longer the one you reviewed. Re-pinning is a deliberate act,
which is exactly the review moment a rug-pull needs to hit.

### 2.5 Approve, as a human

In a second terminal, on a machine you are sitting at:

```bash
export PIRX_GRANT_KEY_FILE=$HOME/pirx-gate/key
pirx gate-approve ~/pirx-gate
```

For each pending proposal you get the canonical bytes printed verbatim inside
a random-boundary frame, then two prompts. Section 4 covers what to do with
them.

Approving writes a grant into `grants/`. The gate finds it on the caller's
next retry.

### 2.6 What the caller sees while waiting

```json
{"result": {"resultType": "input_required",
            "inputRequests": [{"type": "notice", "message": "pirx: human approval pending out-of-band; retry this request to learn the outcome"}],
            "requestState": {"pirx.ticket": "c7ccc749..."}}}
```

That is a Multi Round-Trip Request poll ticket and nothing more. It carries no
proposal bytes, no action hash, and no field an approval could be written
into, because it renders inside the agent host - the trust domain of the party
whose call is under review. Retrying is how the caller learns the outcome.

---

## 3. The runner

For the original path: ranked CVE verdicts from cve-digest.

```bash
pirx run examples/verdict-sample.json my-ledger.jsonl
```

With no ticket credentials configured, the run walks the entire pipeline -
parse, propose, render, approve, issue, spend - and stops at the write with
`refusal.adapter_unavailable`. Nothing is written anywhere. That is the
intended first experience: the trust machinery is observable before anything
can act.

To wire the Jira adapter, three variables, all or none:

```bash
export PIRX_JIRA_BASE_URL="https://your.atlassian.net"
export PIRX_JIRA_EMAIL="you@example.com"
export PIRX_JIRA_TOKEN="..."
```

There is no partial configuration, no credential discovery, and no prompting.

Optional model assistance for the proposer:

```bash
export PIRX_ANTHROPIC_API_KEY="..."
```

Unset, the proposer is deterministic. Set, a model selects the action from a
fixed list and writes the rationale - it supplies no parameter and no target.
Either way the run records `proposer.mode`, because which mind wrote the
sentence a human approved should never have to be inferred from an environment
variable someone forgot was set.

---

## 4. The approval itself

This is the part that matters, and the part no other tool asks of you.

### 4.1 What you are shown

```
--- begin canonical proposal bytes [ce631315...] (these are the hashed bytes) ---
pirx.proposal/2
action: ticket.comment
target: ticket:CVE-2026-2100
justification.schema: cve-digest.verdict/1
justification.ref: cve-digest.verdict/1#CVE-2026-2100
justification.digest: 7027b59d...
param.cve_id: CVE-2026-2100
...
~~~pirx-untrusted-0 begin triage_note (origin=producer, chars=61, escaped, NOT a decision input)
  Observed exploitation against edge appliances.
~~~pirx-untrusted-0 end triage_note
bytes: 881
--- end canonical proposal bytes [ce631315...] ---
```

Three things to know about this block:

- **These bytes are the hash preimage.** Not a summary of what will happen -
  the thing itself. The grant you are about to issue is bound to their SHA-256.
- **The boundary marker is random per presentation.** Text inside the frame
  cannot forge the frame's own end, so a payload cannot make you think the
  proposal stopped earlier than it did.
- **Anything inside a `~~~pirx-untrusted-N` fence is not a decision input.**
  It was written by a producer or a model, it is escaped, and it fills no
  parameter. Read it as context, never as instruction.

### 4.2 The attention challenge

```
attention challenge - transcribe the value of 'justification' exactly as rendered above:
```

The field is selected by the action hash, so it cannot be predicted before the
bytes exist, and yesterday's answer will not work today. Find it in the frame
and type it.

A wrong answer is `refusal.challenge_failed`: the proposal is not approved and
is presented again from the top. There is no retry counter to grind against.

**What this proves and what it does not.** It demonstrates that you operated
on the exact hashed bytes - located a field in them. It does not demonstrate
that you understood them, and Pirx never claims it does. That limit is
deliberate and written into the threat model (PT15).

### 4.3 The decision

```
type 'approve' or 'decline' (no single-key shortcut, by design):
```

The full word. A habituated `y` is approval fatigue in miniature.

An approving answer that arrives faster than a floor derived from the byte
length is `refusal.reading_floor`. Declining is never floor-checked - refusing
fast is not the threat.

**You cannot script this.** Piping answers in trips the floor, by design. If
you find yourself wanting to, that is the system telling you the volume is
wrong, not the control.

---

## 5. Reading the ledger

Everything is an event, and the file is the audit trail.

```bash
pirx verify my-ledger.jsonl
```

```
pirx.ledger/2: 20 record(s), chain intact
tail truncation is NOT detected; a remote append-only sink is what buys that
```

That last line is not boilerplate. The chain detects edits and interior gaps.
It does **not** detect someone removing the last N records, because a
truncated chain is internally consistent. Buying that property means shipping
records off the host as they are written, and Pirx does not do it for you.

To read the flow:

```bash
python3 -c "
import json
for line in open('my-ledger.jsonl'):
    r = json.loads(line)
    print(f\"{r['seq']:>3} {r['event']:<28} {json.dumps(r['payload'])[:80]}\")"
```

A completed gated call looks like this:

```
  0 gate.started
  1 gate.pending                  a proposal was rendered and queued
  2 gate.awaiting_approval        the caller got a ticket; nothing forwarded
  3 gate.presented                a human saw the bytes
  4 attention.challenge_issued    intent recorded before the answer
  5 approval.decided              with elapsed_seconds and floor_seconds
  6 grant.issued
  7 gate.forwarded_granted        the original bytes went downstream
  8 refusal.spent_grant           an immediate replay, refused
```

Two habits worth forming:

- **Absence is evidence.** No `grant.issued` for a proposal means nothing was
  authorised. An action that landed on a target with no grant event in any
  ledger did not come through Pirx - which is how gate bypass becomes visible
  (PT18).
- **`grant.spent` followed by a refusal is normal and important.** Authority
  is consumed before the action runs, so a crash mid-action leaves a spent
  grant and no result. Pirx will not retry it: re-issuing is a human decision
  made with the ledger in hand.

### 5.1 Reconciling an interrupted run

```bash
pirx reconcile my-ledger.jsonl
```

It asks the target system whether the write landed and **reports**. It never
re-executes. An automatic retry carrying authority across a crash is the
privilege-persistence failure this whole design exists to refuse.

---

## 6. Exit codes

| Code | Meaning |
|---|---|
| 0 | the run completed; every proposal reached a decision |
| 2 | the payload was refused before any proposal existed |
| 3 | a refusal fired inside the loop - expired grant, unregistered action, no adapter, failed challenge, reading floor, session budget, or a broken ledger chain |
| 64 | usage error |
| 74 | the gate's downstream server died |
| 78 | required configuration is absent - no adapter for `reconcile`, or no key file for `gate-approve` |

---

## 7. Refusals, and what each one means

Every refusal is a typed event in the ledger. None of them is a warning, and
none of them lets execution continue.

**Payload and parsing**

| Event | What happened |
|---|---|
| `refusal.schema` | the payload's schema id is not one Pirx consumes |
| `refusal.bounds` | a field exceeded a hard bound - prose length, argument size |
| `refusal.malformed_id` | a CVE id did not match the anchored pattern |
| `refusal.enum` | a field carried a value outside its permitted set |
| `refusal.budget` | the run's proposal budget is exhausted |

**Approval and attention**

| Event | What happened | Usual cause |
|---|---|---|
| `refusal.challenge_failed` | the transcription did not match | reading the wrong window, or not reading |
| `refusal.reading_floor` | an approval arrived below the floor | a piped or reflexive answer |
| `refusal.session_budget` | too many grants in one session | rotate the session |
| `refusal.declined` | a human said no | nothing is wrong |

**Grants**

| Event | What happened |
|---|---|
| `refusal.hash_mismatch` | the grant does not cover these bytes - something changed after approval |
| `refusal.target_mismatch` | the grant is for another target |
| `refusal.expired_grant` | the deadline passed before the spend |
| `refusal.spent_grant` | a replay: this nonce is already burnt |
| `refusal.grant_mac` | the grant was not issued by a holder of this key |
| `refusal.malformed_grant` | the grant file's shape is wrong |

**The gate**

| Event | What happened |
|---|---|
| `refusal.protocol` | the frame is not valid JSON-RPC |
| `refusal.protocol_version` | the peer speaks an MCP revision Pirx does not (see §8) |
| `refusal.header_mismatch` | a routing header disagreed with the body |
| `refusal.tool_definition_drift` | the tool's definition changed since you reviewed it |

**Execution**

| Event | What happened |
|---|---|
| `refusal.unregistered_action` | the action is not in the capability registry |
| `refusal.adapter_unavailable` | registered, but nothing is wired to perform it |
| `refusal.model` | the model returned something out of contract; the run stops rather than falling back |
| `refusal.ledger_chain` | the ledger has a seam or a sequence gap |

---

## 8. Troubleshooting

**`command not found: pirx`** - you are in a different virtual environment.
The gate's downstream server usually lives in its own venv; that is correct,
and it is not the one Pirx is installed into.

**`refusal.protocol_version` on every call** - the peer is speaking an older
MCP revision. Pirx accepts `2026-07-28` only, and most SDKs still default to
the 2025 era unless the new revision is opted into explicitly. This is a real
limitation, not a misconfiguration: supporting the older era would bring back
the `initialize` handshake and a protocol session, which is the ambient state
the thesis is glad to be rid of.

**`PIRX_GRANT_KEY_FILE must name a key file`** - the gate verifies grants
another process issued. `pirx run` may generate an ephemeral key because it
approves and executes in one process; the gate may not.

**The gate forwards everything and holds nothing** - the gated registry is
empty. That is the shipped state. See §2.4.

**`refusal.tool_definition_drift` after upgrading a server** - the definition
you pinned no longer matches. Re-derive the hash, read what changed, and
re-pin deliberately. This is the control working.

**An approval seems to hang** - `gate-approve` walks the queue once and exits.
If a proposal arrived after it started, run it again.

---

## 9. What Pirx will not do for you

Pointers, so you do not go looking:

- **It does not authenticate you.** `approver_claim` comes from the process
  environment and is recorded with `authenticated: false`. Identity is the
  identity provider's job.
- **It does not prevent gate bypass.** An agent host that launches the
  downstream server directly never passes through the gate. Prevention lives
  in your environment - hold the downstream credentials only in the gate's
  environment, and allowlist by process identity. What Pirx gives you is
  detectability.
- **It does not decide what is worth doing.** No risk scoring, no policy
  language, no auto-approve threshold, and no configurable security limits.
  Every limit that exists for a security reason is a constant in the code.
- **It does not measure comprehension.** See §4.2.

The full register is in the README, and the reasoning is in
`docs/THREAT-MODEL.md`.
