"""The docs audit runs in the local gate as well as CI.

Brief section 8 lists it in the local gate; a check that only runs in CI is a
check a developer meets after pushing, which is the wrong end of the loop.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_docs_audit_passes() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "docs_audit.py")],
        capture_output=True, text=True, cwd=ROOT,
    )
    assert result.returncode == 0, result.stderr


def test_docs_audit_detects_a_pin_mismatch(tmp_path: Path) -> None:
    """The audit's own failure mode is measured, not assumed - a check nobody
    has seen fail is not a measured control (the F9 lesson, applied to the
    audit itself)."""
    import json
    import shutil

    work = tmp_path / "repo"
    shutil.copytree(
        ROOT, work,
        ignore=shutil.ignore_patterns(
            ".git", "__pycache__", ".venv", "*.jsonl",
            ".mypy_cache", ".pytest_cache", ".ruff_cache",
        ),
    )
    status = json.loads((work / "STATUS.json").read_text())
    status["architecture"] = "99.9"
    (work / "STATUS.json").write_text(json.dumps(status, indent=2))

    result = subprocess.run(
        [sys.executable, str(work / "tools" / "docs_audit.py")],
        capture_output=True, text=True, cwd=work,
    )
    assert result.returncode == 1
    assert "architecture" in result.stderr


def test_docs_audit_detects_a_stale_position_marker(tmp_path: Path) -> None:
    """The 'You are here' marker is the one line in README a reader trusts
    for orientation, so its failure mode is measured like any other."""
    import shutil

    work = tmp_path / "repo"
    shutil.copytree(
        ROOT, work,
        ignore=shutil.ignore_patterns(
            ".git", "__pycache__", ".venv", "*.jsonl",
            ".mypy_cache", ".pytest_cache", ".ruff_cache",
        ),
    )
    readme = work / "README.md"
    readme.write_text(
        readme.read_text().replace("**You are here: ", "**You are here: 9.9.9.9 not ")
    )

    result = subprocess.run(
        [sys.executable, str(work / "tools" / "docs_audit.py")],
        capture_output=True, text=True, cwd=work,
    )
    assert result.returncode == 1
    assert "You are here" in result.stderr or "position marker" in result.stderr


def test_manual_audit_passes() -> None:
    """The manual quotes constants, refusal names, and event names. Every one
    is a fact about the code, and a manual whose facts drift is worse than no
    manual: an operator trusts it exactly where they cannot check."""
    result = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "manual_audit.py")],
        capture_output=True, text=True, cwd=ROOT,
    )
    assert result.returncode == 0, result.stderr


def test_manual_audit_detects_a_drifted_constant(tmp_path: Path) -> None:
    """The tripwire's own failure mode is measured (the F9 lesson)."""
    import shutil

    work = tmp_path / "repo"
    shutil.copytree(
        ROOT, work,
        ignore=shutil.ignore_patterns(
            ".git", "__pycache__", ".venv", "*.jsonl",
            ".mypy_cache", ".pytest_cache", ".ruff_cache",
        ),
    )
    manual = work / "docs" / "MANUAL.md"
    manual.write_text(
        manual.read_text().replace(
            "| `GRANT_TTL_SECONDS` | 300.0 |", "| `GRANT_TTL_SECONDS` | 900.0 |"
        )
    )
    result = subprocess.run(
        [sys.executable, str(work / "tools" / "manual_audit.py")],
        capture_output=True, text=True, cwd=work,
    )
    assert result.returncode == 1
    assert "GRANT_TTL_SECONDS" in result.stderr
