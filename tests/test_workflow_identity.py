"""Which jobs in this repository can mint an identity token, pinned.

A job holding `id-token: write` can obtain a token that names this repository,
so the set of such jobs is a security property of the repository rather than
of one workflow (PT22). A job that acquires the permission without an entry in
the threat model fails here instead of being noticed in review, and the shape
PT22 relies on for the Pages deploy job is held to what the entry says.
Ported from cve-digest's test of the same name (its T17).

Read as text, not as YAML: the workflows are written in a regular shape and
the suite carries no YAML parser. A workflow that leaves that shape fails the
parse below loudly rather than passing by accident.
"""

from __future__ import annotations

import re
from pathlib import Path

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"

# Every holder, with the threat row that admits it.
HOLDERS = {("pages.yml", "deploy"): "PT22"}


def code_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if not line.lstrip().startswith("#")]


def jobs(text: str) -> dict[str, list[str]]:
    """Job name to its lines, for the two-space keys under a top-level `jobs:`."""
    found: dict[str, list[str]] = {}
    current: str | None = None
    inside = False
    for line in code_lines(text):
        if line.startswith("jobs:"):
            inside = True
            continue
        if not inside:
            continue
        key = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if key:
            current = key.group(1)
            found[current] = []
        elif line.strip() and not line.startswith(" "):
            inside, current = False, None
        elif current:
            found[current].append(line)
    assert found, "no jobs parsed; the workflow left the shape this test reads"
    return found


def grants_token(lines: list[str]) -> bool:
    """`id-token: write` however it is followed, or `write-all`, which
    includes it. A comment after the value does not hide it."""
    return any(
        re.match(r"^\s*id-token:\s*write\b", line)
        or re.match(r"^\s*permissions:\s*write-all\b", line)
        for line in lines
    )


def permissions(lines: list[str]) -> set[str]:
    """A job's permission lines, as `name: value` with comments dropped."""
    found: set[str] = set()
    inside = False
    for line in lines:
        if re.match(r"^    permissions:\s*$", line):
            inside = True
            continue
        if inside and re.match(r"^      \S", line):
            found.add(line.split("#", 1)[0].strip())
        elif inside:
            inside = False
    return found


def pages() -> dict[str, list[str]]:
    return jobs((WORKFLOWS / "pages.yml").read_text(encoding="utf-8"))


def test_only_the_recorded_jobs_can_mint_an_identity_token() -> None:
    holders: set[tuple[str, str]] = set()
    for path in sorted(WORKFLOWS.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        above_jobs = code_lines(text.split("\njobs:")[0])
        assert not grants_token(above_jobs), f"{path.name} grants id-token to every job"
        holders |= {
            (path.name, job) for job, lines in jobs(text).items() if grants_token(lines)
        }
    assert holders == set(HOLDERS)


def test_every_action_in_every_workflow_is_pinned_by_commit() -> None:
    unpinned = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        for line in code_lines(path.read_text(encoding="utf-8")):
            used = re.search(r"uses:\s*(\S+)", line)
            if used and not re.fullmatch(
                r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", used.group(1)
            ):
                unpinned.append(f"{path.name}: {used.group(1)}")
    assert unpinned == []


def test_the_token_check_sees_the_forms_that_hide_it() -> None:
    """The two forms a review found the first version of this check missed."""
    assert grants_token(["      id-token: write # deploy"])
    assert grants_token(["    permissions: write-all"])
    assert grants_token(["permissions: write-all"])
    assert not grants_token(["      id-token: none", "      contents: read"])


def test_each_pages_job_holds_exactly_the_permissions_pt22_names() -> None:
    jobs_ = pages()
    assert permissions(jobs_["build"]) == {"contents: read"}
    assert permissions(jobs_["deploy"]) == {"pages: write", "id-token: write"}


def test_the_pages_deploy_job_runs_one_first_party_action_and_nothing_else() -> None:
    lines = pages()["deploy"]
    uses = [line for line in lines if "uses:" in line]
    assert len(uses) == 1 and "uses: actions/deploy-pages@" in uses[0]
    assert not any(re.match(r"^\s+(- )?run:", line) for line in lines)
    assert any(line.strip() == "if: github.ref == 'refs/heads/main'" for line in lines)
    assert any(line.strip() == "name: github-pages" for line in lines)


def test_the_pages_build_job_holds_no_token_and_keeps_no_credential() -> None:
    lines = pages()["build"]
    assert not grants_token(lines)
    assert any(line.strip() == "persist-credentials: false" for line in lines)
    assert any("--require-hashes -r requirements-docs.txt" in line for line in lines)


def test_the_pages_workflow_never_runs_on_a_pull_request() -> None:
    text = (WORKFLOWS / "pages.yml").read_text(encoding="utf-8")
    head = code_lines(text.split("\njobs:")[0])
    assert not any(re.match(r"^\s+pull_request(_target)?\s*:", line) for line in head)


def test_the_test_job_installs_the_site_parser_by_hash() -> None:
    """tests/test_site.py needs the parser. Installed without hashes, the gate
    would run an index's choice of it beside the code under test."""
    lines = jobs((WORKFLOWS / "gate.yml").read_text(encoding="utf-8"))["tests"]
    installs = [line.strip() for line in lines if "requirements-docs.txt" in line]
    assert installs == ["- run: pip install --require-hashes -r requirements-docs.txt"]
