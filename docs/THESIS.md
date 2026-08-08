# Thesis: approval is a capability grant, not a checkbox

> Codename **Pirx** (package `pirx`). Lem's pilot is trusted because he does
> not trust himself; the thesis is the same discipline in code.

```
Document:  docs/THESIS.md, version 1.0 (ships with 0.1.0.0)
Expands:   PIRX-PROJECT-BRIEF.md v1.2, section 1
```

## The failure this project is built against

Most "human-in-the-loop" agents implement approval as a boolean. A dialogue
appears, a person clicks yes, and from that moment the agent holds whatever
authority it had before the dialogue. The check is real; the authority it
gates is not - because what was approved ("proceed?") and what is then
executed (any action the code can reach) are different things, joined only by
the assumption that the agent will do what it said.

The realistic failure is not a forged approval. It is a **real approval,
reused in a context nobody reviewed**: spent on a different target, spent
twice, spent hours later, or given against a summary the agent wrote about
itself.

## The inversion

Pirx makes approval *constitutive* of authority rather than a gate in front
of it. Concretely, in this codebase:

1. **Zero authority by default.** Every write path takes a grant as a
   required argument (`SpentGrant`, whose only constructor is the spend
   function) and the production registry ships empty. "Unreachable" is a type
   error and a build-failing test, not a policy.
2. **A grant authorises one action.** Its scope is the SHA-256 of the
   canonically rendered proposal - verb, target, parameters, justifying
   verdict. Changing one byte of what was approved invalidates it.
3. **Grants expire and are single-use.** Expiry runs on the monotonic clock
   and is checked at spend, not at issue; the nonce is burned before the
   caller can act.
4. **What was approved is what was shown.** One render function produces the
   bytes; the same bytes are the hash preimage; the approval surface writes
   them to the terminal verbatim inside a per-presentation random frame, and
   a test compares captured stdout with the preimage byte-for-byte.
5. **Every grant, spend, and refusal is a structured event.** The
   hash-chained ledger answers *what was authorised, when, on what evidence,
   and did it run* with a query. *Who* is a separate question: the ledger
   carries an `approver_claim` marked `authenticated: false`, because
   identity is the identity provider's job and claiming otherwise would be
   theatre.

## The corollary that cannot be quietly dropped

The grant machinery is ordinary code that no model-authored output can reach
or influence. In 0.1.0.0 there is no model at all; when one enters (0.4.0.0),
it proposes prose and selects from a fixed registry - it never issues,
modifies, or validates a grant, and no field it produces is ever a parameter
of one.

Wording note: "the model cannot X" is shorthand throughout. The precise
adversary is code driven by attacker-controlled data and, after an eventual
process split, a second process asserting authority it was not given.
Controls are written against those, not against a mind.
