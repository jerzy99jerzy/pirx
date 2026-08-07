"""The test that defines version 0.1.0.0.

Two claims, both measured rather than asserted:

1. The production registry is empty, so nothing can be executed.
2. No module outside the allowlist imports a network or filesystem-write
   facility, so nothing can write even if something forgot to ask.

**What this is and is not.** The scrape is a regression tripwire for the
honest mistake - a new code path that forgets a grant argument, or an import
added without thinking. It is not a proof against a determined author:
``getattr``, ``importlib``, ``subprocess``, or a wrapper library defeat any
static check, and this docstring exists so no reader mistakes the green tick
for a guarantee (family practice P7, PT7 as worded in brief v1.2).
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from pirx.errors import UnregisteredActionRefusal
from pirx.registry import PRODUCTION_REGISTRY, Registry

PACKAGE = Path(__file__).resolve().parent.parent / "pirx"

#: Modules permitted to reach the outside world, and what each may reach.
#: Empty for network in 0.1.0.0: there is no adapter yet, and the first one
#: arrives with the first capability at 0.3.0.0.
NETWORK_ALLOWLIST: frozenset[str] = frozenset()
FILE_WRITE_ALLOWLIST: frozenset[str] = frozenset({"ledger.py", "cli.py"})

NETWORK_MODULES = {
    "socket", "ssl", "http", "urllib", "urllib3", "requests", "httpx",
    "aiohttp", "ftplib", "smtplib", "telnetlib", "asyncio", "xmlrpc",
}
FILE_WRITE_CALLS = {"open", "write_text", "write_bytes", "mkdir", "unlink", "rename"}
DYNAMIC_IMPORT_NAMES = {"importlib", "__import__"}
SUBPROCESS_MODULES = {"subprocess", "os", "shutil", "ctypes", "multiprocessing"}


def modules() -> list[Path]:
    return sorted(p for p in PACKAGE.glob("*.py") if p.name != "__init__.py")


def imported_roots(tree: ast.AST) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def called_attrs(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                names.add(func.id)
            elif isinstance(func, ast.Attribute):
                names.add(func.attr)
    return names


# --- Claim 1: the registry is empty -----------------------------------------


def test_production_registry_is_empty() -> None:
    assert len(PRODUCTION_REGISTRY) == 0
    assert PRODUCTION_REGISTRY.actions() == ()


def test_every_known_intent_is_refused_by_the_production_registry() -> None:
    from pirx.registry import KNOWN_INTENTS

    for action in KNOWN_INTENTS:
        with pytest.raises(UnregisteredActionRefusal) as caught:
            PRODUCTION_REGISTRY.require(action)
        assert caught.value.details["registered"] == []


def test_a_registry_cannot_be_grown_after_construction() -> None:
    registry = Registry({})
    assert not hasattr(registry, "register")
    assert not hasattr(registry, "add")


# --- Claim 2: the import allowlist ------------------------------------------


def test_no_network_imports_outside_the_allowlist() -> None:
    offenders: list[str] = []
    for path in modules():
        if path.name in NETWORK_ALLOWLIST:
            continue
        hits = imported_roots(ast.parse(path.read_text())) & NETWORK_MODULES
        if hits:
            offenders.append(f"{path.name}: {sorted(hits)}")
    assert not offenders, f"network reach outside allowlist: {offenders}"


def test_no_process_or_shell_reach_anywhere() -> None:
    offenders: list[str] = []
    for path in modules():
        hits = imported_roots(ast.parse(path.read_text())) & SUBPROCESS_MODULES
        if hits:
            offenders.append(f"{path.name}: {sorted(hits)}")
    assert not offenders, f"process reach present: {offenders}"


def test_no_dynamic_imports_that_would_defeat_the_scrape() -> None:
    offenders: list[str] = []
    for path in modules():
        tree = ast.parse(path.read_text())
        hits = (imported_roots(tree) | called_attrs(tree)) & DYNAMIC_IMPORT_NAMES
        if hits:
            offenders.append(f"{path.name}: {sorted(hits)}")
    assert not offenders, f"dynamic import present: {offenders}"


def test_file_writes_only_in_the_allowlisted_modules() -> None:
    offenders: list[str] = []
    for path in modules():
        if path.name in FILE_WRITE_ALLOWLIST:
            continue
        hits = called_attrs(ast.parse(path.read_text())) & FILE_WRITE_CALLS
        if hits:
            offenders.append(f"{path.name}: {sorted(hits)}")
    assert not offenders, f"file write outside allowlist: {offenders}"


def test_allowlist_is_minimal_and_named() -> None:
    """The allowlist itself is reviewed: it may only contain modules that
    exist, so a stale entry cannot silently widen the surface."""
    present = {p.name for p in modules()}
    assert present >= NETWORK_ALLOWLIST
    assert present >= FILE_WRITE_ALLOWLIST


# --- Claim 2b: refusals are never suppressed --------------------------------


def test_only_the_runner_catches_refusals() -> None:
    """A caught refusal outside the runner is a warning wearing a refusal's
    name (P11). ``cli.py`` is the single sanctioned catch site."""
    offenders: list[str] = []
    for path in modules():
        if path.name == "cli.py":
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.ExceptHandler):
                names = ast.dump(node.type) if node.type else "bare"
                if "Refusal" in names:
                    offenders.append(f"{path.name}:{node.lineno}")
    assert not offenders, f"refusal caught outside the runner: {offenders}"
