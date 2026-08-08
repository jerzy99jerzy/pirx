#!/usr/bin/env python3
"""Check docs/MANUAL.md against the code it documents.

The manual carries constant values, refusal names, and ledger event names.
Every one of them is a fact about the code, and a manual whose facts drift is
worse than no manual: an operator trusts it precisely where they cannot check.

This is a regression tripwire, not a proof. It verifies that documented
numbers match the constants and that no refusal or event exists without being
documented. It cannot verify that the prose describing them is true.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pirx import errors, types  # noqa: E402
from pirx.approve import reading_floor_seconds  # noqa: E402
from pirx.mcp import pump  # noqa: E402

MANUAL = ROOT / "docs" / "MANUAL.md"

#: Constants the manual quotes, with the exact string it must use. The
#: formatting is part of the check: a table that says 2000 where the manual
#: standard is 2 000 has been edited by hand and may have been edited wrongly.
QUOTED = {
    "MAX_PROSE_CHARS": (types.MAX_PROSE_CHARS, "2 000"),
    "MAX_PROPOSALS_PER_RUN": (types.MAX_PROPOSALS_PER_RUN, "10"),
    "GRANT_TTL_SECONDS": (types.GRANT_TTL_SECONDS, "300.0"),
    "READING_FLOOR_BASE_SECONDS": (types.READING_FLOOR_BASE_SECONDS, "2.0"),
    "READING_FLOOR_SECONDS_PER_KIB": (types.READING_FLOOR_SECONDS_PER_KIB, "2.0"),
    "MAX_GRANTS_PER_SESSION": (types.MAX_GRANTS_PER_SESSION, "20"),
    "MAX_CALL_ARGUMENT_CHARS": (types.MAX_CALL_ARGUMENT_CHARS, "4 000"),
    "MIN_GRANT_KEY_BYTES": (types.MIN_GRANT_KEY_BYTES, "32"),
    "MAX_FRAME_BYTES": (pump.MAX_FRAME_BYTES, "1 000 000"),
}


def declared_refusals() -> set[str]:
    return {
        value.event
        for value in vars(errors).values()
        if isinstance(value, type)
        and issubclass(value, errors.Refusal)
        and hasattr(value, "event")
    }


def emitted_events() -> set[str]:
    found: set[str] = set()
    for path in (ROOT / "pirx").rglob("*.py"):
        text = path.read_text()
        found |= set(re.findall(r'append\(\s*"([a-z_]+\.[a-z_]+)"', text))
        found |= set(re.findall(r'append\(\s*\n\s*"([a-z_]+\.[a-z_]+)"', text))
    return found


def main() -> int:
    manual = MANUAL.read_text()
    cited = set(re.findall(r"`([a-z_]+\.[a-z_]+)`", manual))
    problems: list[str] = []

    for name, (actual, quoted) in QUOTED.items():
        rows = [line for line in manual.splitlines() if line.startswith(f"| `{name}`")]
        if not rows:
            problems.append(f"{name} is not in the manual's constants table")
        elif f"| {quoted} |" not in rows[0]:
            problems.append(f"{name}: manual row {rows[0]!r} does not say {quoted!r}")
        elif str(actual).replace("_", "") not in quoted.replace(" ", ""):
            problems.append(f"{name}: code is {actual}, manual quotes {quoted}")

    for event in sorted(declared_refusals() - cited):
        problems.append(f"refusal {event} exists but the manual does not list it")
    for event in sorted(emitted_events() - cited):
        if not event.startswith("refusal."):
            problems.append(f"event {event} is emitted but the manual does not list it")

    # The worked arithmetic in section 12 is checkable, so it is checked.
    if "3.742" in manual and round(reading_floor_seconds(892), 3) != 3.742:
        problems.append("the manual's worked floor example no longer matches the code")

    if problems:
        sys.stderr.write("manual audit FAILED:\n")
        for problem in problems:
            sys.stderr.write(f"  - {problem}\n")
        return 1
    sys.stdout.write("manual audit clean\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
