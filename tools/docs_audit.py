"""Docs audit: the check the brief has claimed since 0.1.0.0 and never had.

Brief section 8 lists a docs audit in the local gate, and FAMILY.md 3.5 rests
the vendoring rule on it. Neither existed as code for four versions - the
project enforced "claims are measured" against its own source while shipping
an unmeasured claim about its own process (review finding F31).

What it checks, all internal to this repository - **never** the other repo's
state, per FAMILY.md section 1:

  1. every document with a canonical home declares a version in its header;
  2. STATUS.json's pins match the versions those documents declare;
  3. every shipped version named in README's version plan has a review file;
  4. the harness catalogue's row count matches its own declared assertion;
  5. every threat-model row PT1..PTn exists, with no gaps or duplicates;
  6. README's "You are here" position marker names the version STATUS.json
     declares, so the reader's orientation cannot outlive a bump;
  7. README's badges carry numbers that match reality - a badge is a claim
     rendered in colour, and a stale one is read by everyone who never opens
     the file behind it.

Exit status is 0 when clean, 1 otherwise, so it slots into the gate beside
ruff, mypy, and pytest. Failures print the specific mismatch, because an
audit that says "docs inconsistent" costs more time than it saves.

Does NOT:
  - read cve-digest, fetch anything, or check whether a vendored document has
    drifted from its canonical home. That question is answered by a human at
    exchange time and the consequence is stated in FAMILY.md rather than
    papered over with automation.
  - rewrite anything. It reports; a person fixes.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"

#: STATUS.json key -> (document, regex capturing its declared version)
PINNED = {
    "family_doc": (DOCS / "FAMILY.md", r"^Document:\s+FAMILY\.md, version (\S+)"),
    "brief": (
        DOCS / "PIRX-PROJECT-BRIEF.md",
        r"^Brief version:\s+(\S+)",
    ),
    "architecture": (
        DOCS / "ARCHITECTURE.md",
        r"^Document:\s+docs/ARCHITECTURE\.md, version (\S+)",
    ),
}


def declared_version(path: Path, pattern: str) -> str | None:
    if not path.exists():
        return None
    for line in path.read_text().splitlines()[:20]:
        match = re.search(pattern, line.strip())
        if match:
            return match.group(1)
    return None


def check_pins(problems: list[str]) -> None:
    status = json.loads((ROOT / "STATUS.json").read_text())
    for key, (path, pattern) in PINNED.items():
        pinned = status.get(key)
        found = declared_version(path, pattern)
        if found is None:
            problems.append(
                f"{path.relative_to(ROOT)}: no version in header "
                f"(STATUS.json pins {key}={pinned!r})"
            )
        elif pinned != found:
            problems.append(
                f"STATUS.json {key}={pinned!r} but "
                f"{path.relative_to(ROOT)} declares {found!r}"
            )


def check_reviews(problems: list[str]) -> None:
    """Every version marked shipped in README's plan needs a review file."""
    readme = (ROOT / "README.md").read_text()
    shipped = set(re.findall(r"\|\s*(0\.\d+\.\d+\.\d+)\s*\|[^|]*\*\*Shipped", readme))
    have = {
        match.group(1)
        for path in (DOCS / "reviews").glob("*.md")
        if (match := re.match(r"(\d+\.\d+\.\d+\.\d+)-", path.name))
    }
    for version in sorted(shipped - have):
        problems.append(f"README marks {version} shipped but no review file exists")


def check_catalogue(problems: list[str]) -> None:
    catalogue = ROOT / "tests" / "harness" / "CATALOGUE.md"
    rows = [
        line
        for line in catalogue.read_text().splitlines()
        if line.startswith("| A") and "`test_" in line
    ]
    suite = (ROOT / "tests" / "harness" / "test_attacks.py").read_text()
    match = re.search(r"len\(rows\) == (\d+)", suite)
    if match is None:
        problems.append("test_attacks.py no longer asserts a catalogue row count")
    elif int(match.group(1)) != len(rows):
        problems.append(
            f"CATALOGUE.md has {len(rows)} rows but the suite asserts "
            f"{match.group(1)}"
        )


def check_you_are_here(problems: list[str]) -> None:
    """README's position marker must name the version STATUS.json declares.

    A "current version" written in prose is a claim the code does not
    produce, and it goes stale on the first bump that forgets it (P7). This
    pins it: the marker moves with the bump or the gate goes red. Exactly one
    marker may exist, because two would let a reader find the stale one.
    """
    status = json.loads((ROOT / "STATUS.json").read_text())
    readme = (ROOT / "README.md").read_text()
    markers = re.findall(r"\*\*You are here: (\d+\.\d+\.\d+\.\d+)\.\*\*", readme)
    if not markers:
        problems.append("README has no 'You are here: <version>' marker")
    elif len(markers) > 1:
        problems.append(f"README has {len(markers)} position markers; expected one")
    elif markers[0] != status["version"]:
        problems.append(
            f"README says 'You are here: {markers[0]}' but STATUS.json "
            f"declares version {status['version']!r}"
        )


def check_badges(problems: list[str]) -> None:
    """README badges carry numbers, and a number in a badge is a claim.

    Checked here: the ones derivable without running the suite. The test-count
    badge needs a real collection (parametrised tests mean a grep undercounts
    by 25), so it is checked in `tests/test_docs_audit.py` where pytest exists.
    """
    readme = (ROOT / "README.md").read_text()
    status = json.loads((ROOT / "STATUS.json").read_text())

    version = re.search(r"badge/version-([0-9.]+)-", readme)
    if not version:
        problems.append("README has no version badge")
    elif version.group(1) != status["version"]:
        problems.append(
            f"version badge says {version.group(1)}, "
            f"STATUS.json says {status['version']}"
        )

    attacks = re.search(r"badge/hostile%20attacks-(\d+)-", readme)
    real_attacks = len(
        [
            line
            for line in (ROOT / "tests/harness/CATALOGUE.md").read_text().splitlines()
            if line.startswith("| A")
        ]
    )
    if not attacks:
        problems.append("README has no hostile-attacks badge")
    elif int(attacks.group(1)) != real_attacks:
        problems.append(
            f"attacks badge says {attacks.group(1)}, catalogue has {real_attacks}"
        )

    rows = re.search(r"badge/threat%20rows-PT1--PT(\d+)-", readme)
    real_rows = len(
        re.findall(r"^## PT(\d+)", (ROOT / "docs/THREAT-MODEL.md").read_text(), re.M)
    )
    if not rows:
        problems.append("README has no threat-rows badge")
    elif int(rows.group(1)) != real_rows:
        problems.append(
            f"threat-rows badge says PT{rows.group(1)}, model has {real_rows} rows"
        )


def check_threat_numbering(problems: list[str]) -> None:
    """PT ids are never renumbered or repurposed, so the set must be 1..n."""
    text = (DOCS / "THREAT-MODEL.md").read_text()
    ids = [int(n) for n in re.findall(r"^## PT(\d+)", text, re.MULTILINE)]
    if not ids:
        problems.append("THREAT-MODEL.md contains no PT sections")
        return
    expected = list(range(1, max(ids) + 1))
    if sorted(ids) != expected:
        missing = sorted(set(expected) - set(ids))
        duplicated = sorted({n for n in ids if ids.count(n) > 1})
        problems.append(
            f"THREAT-MODEL.md PT numbering: missing={missing} "
            f"duplicated={duplicated}"
        )


def main() -> int:
    problems: list[str] = []
    check_pins(problems)
    check_reviews(problems)
    check_catalogue(problems)
    check_threat_numbering(problems)
    check_you_are_here(problems)
    check_badges(problems)

    if problems:
        print("docs audit FAILED:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print("docs audit clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
