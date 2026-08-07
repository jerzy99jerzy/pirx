# Pirx

**A write-capable remediation agent whose authority is granted per action,
not per session.**

Version 0.2.0.0: the complete trust loop with **zero capabilities
registered**, plus the hostile-agent harness that attacks it. A human can run
it end to end - see a rendered proposal, approve it, watch a grant be issued
and spent, and watch execution be refused because nothing is registered.
Nothing can write anything, by construction and by test.

The harness (`tests/harness/`) runs fifteen scripted attacks in CI on every
push, one per threat-model row, each asserting that the attack ends in the
correct typed refusal **and** that the refusal appears in the ledger the
product wrote. Its catalogue is in `tests/harness/CATALOGUE.md`. One attack
passes by design: PT14's accepted risk is recorded as an executable
assertion, so forgetting it costs a deliberate test change.

The name is Lem's pilot: trusted with a ship precisely because he treats his
own judgement as fallible and checks it against the instruments. Upstream
companion: [cve-digest](https://github.com/jerzy99jerzy/cve-digest)
(Rappaport), which emits `cve-digest.verdict/1`; Pirx consumes it one-way,
and nothing ever flows back - not at runtime, not through development-time
automation (see `docs/FAMILY.md`).

## Quick start

```
python -m pirx.cli examples/verdict-sample.json my-ledger.jsonl
```

Verify the ledger chain afterwards (separately - a verification and the
action it guards never share a pasted block):

```
python -c "from pathlib import Path; from pirx import ledger; print(ledger.verify(Path('my-ledger.jsonl')), 'records, chain intact')"
```

## Documentation

- `docs/THESIS.md` - why approval is a capability grant, not a checkbox
- `docs/THREAT-MODEL.md` - PT1-PT14, each with its control or its named
  acceptance, and the test that measures it
- `docs/CONTRACT.md` - the `cve-digest.verdict/1` contract and the
  consumer-owned compatibility matrix
- `docs/ARCHITECTURE.md` - implementation-level assumptions for
  0.1.0.0-0.3.0.0
- `docs/FAMILY.md` - vendored family practices and the human-carried
  exchange protocol (canonical home: cve-digest)
- `tests/harness/CATALOGUE.md` - the attack catalogue, one row per threat
- `docs/reviews/` - pre-push reviews with dispositioned findings
- `docs/exchange/` - development-level exchange entries

## Gate

```
ruff check .
mypy pirx
python -m pytest
```

## Environment note (measured, not asserted)

This version was built and gated on **Python 3.12.3**: ruff clean, mypy
strict clean, 71 tests passing - on 3.12.3. The project declares
`requires-python = ">=3.14"`; that declaration is **unverified in the build
environment** and no 3.13+ syntax is used. Closing this gap is owned by the
first CI run on 3.14 (review finding F4).
