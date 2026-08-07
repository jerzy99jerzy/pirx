# Pirx

**A write-capable remediation agent whose authority is granted per action,
not per session.**

Version 0.1.0.0: the complete trust loop with **zero capabilities
registered**. A human can run it end to end - see a rendered proposal,
approve it, watch a grant be issued and spent, and watch execution be refused
because nothing is registered. Nothing can write anything, by construction
and by test.

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
- `docs/reviews/` - pre-push reviews with dispositioned findings
- `docs/exchange/` - development-level exchange entries

## Gate

```
ruff check .
mypy pirx
python -m pytest
```

## Environment note (measured, not asserted)

Authored on Python 3.12.3 and gated on **Python 3.14.6** (macOS, Homebrew):
ruff clean, mypy strict clean, 71 tests passing on both. `requires-python =
">=3.14"` is therefore a measured claim on a developer machine, not an
untested declaration. Reproducible verification is CI's job, not this note's
(review finding F4).
