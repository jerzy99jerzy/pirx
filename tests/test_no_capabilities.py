"""The tests that define the write surface.

Two claims, both measured rather than asserted:

1. The production registry contains exactly the reviewed set of actions, and
   nothing else can be executed. Through 0.2.0.0 that set was empty; from
   0.3.0.0 it holds one entry, and the test asserts the *exact* set rather
   than a count, so an addition is a deliberate edit here.
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
#: One network module from 0.3.0.0: the ticket adapter. Paths are relative to
#: the package root, because the scrape walks subpackages - it globbed only
#: `pirx/*.py` until 0.3.0.0, which would have left `adapters/` unchecked at
#: precisely the moment the first network import landed (review finding F11).
NETWORK_ALLOWLIST: frozenset[str] = frozenset({"adapters/jira.py"})
#: Only the ledger writes to disk. Sharpened in 0.2.0.0 (review finding F5):
#: `cli.py` was previously allowlisted because the scrape could not tell
#: `read_bytes` from `write_bytes`. It now can, so the runner is held to the
#: same rule as everything else.
FILE_WRITE_ALLOWLIST: frozenset[str] = frozenset({"ledger.py"})

NETWORK_MODULES = {
    "socket", "ssl", "http", "urllib", "urllib3", "requests", "httpx",
    "aiohttp", "ftplib", "smtplib", "telnetlib", "asyncio", "xmlrpc",
}
FILE_WRITE_CALLS = {"write_text", "write_bytes", "mkdir", "unlink", "rename",
                    "touch", "rmdir", "replace", "chmod", "symlink_to"}
WRITE_MODE_CHARS = set("wax+")
DYNAMIC_IMPORT_NAMES = {"importlib", "__import__"}

#: Whole modules whose presence is process reach regardless of what is used.
SUBPROCESS_MODULES = {"subprocess", "shutil", "ctypes", "multiprocessing", "pty"}

#: `os` is not on that list, because `os.environ` is not process reach and
#: banning the module outright would have pushed credential reading into a
#: worse place. The dangerous surface is named instead (review finding F12).
OS_PROCESS_ATTRS = {
    "system", "popen", "fork", "forkpty", "kill", "killpg", "abort",
    "execv", "execve", "execvp", "execvpe", "execl", "execle", "execlp",
    "spawnv", "spawnve", "spawnl", "spawnlp", "posix_spawn",
}


def modules() -> list[Path]:
    """Every module in the package, including subpackages.

    `rglob`, not `glob`: the 0.1.0.0 version looked only at the top level,
    which would have silently exempted `adapters/` the moment it appeared.
    A scrape with a blind spot is worse than no scrape, because the green
    tick is read as coverage.
    """
    return sorted(
        p for p in PACKAGE.rglob("*.py") if p.name != "__init__.py"
    )


def rel(path: Path) -> str:
    return path.relative_to(PACKAGE).as_posix()


def imported_roots(tree: ast.AST) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def write_mode_opens(tree: ast.AST) -> list[int]:
    """Line numbers of ``open(...)`` calls that request writing.

    Reading a file is not a write surface. Distinguishing them is what closes
    review finding F5; a scrape that flags `read_bytes` teaches the reader to
    widen the allowlist, which is the opposite of what an allowlist is for.

    Fails closed: an unresolvable mode argument counts as a write, because a
    check that guesses in the permissive direction is not a check.
    """
    unresolved = object()
    hits: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else (
            func.attr if isinstance(func, ast.Attribute) else ""
        )
        if name != "open":
            continue
        # Builtin form is open(file, mode); Path method form is p.open(mode).
        # Getting this wrong in the permissive direction would silently
        # un-check every method-style write, so the two are handled apart.
        mode_index = 1 if isinstance(func, ast.Name) else 0
        mode: object = None  # absent mode means the default, which is read
        if len(node.args) > mode_index:
            arg = node.args[mode_index]
            mode = arg.value if isinstance(arg, ast.Constant) else unresolved
        for kw in node.keywords:
            if kw.arg == "mode":
                mode = (
                    kw.value.value
                    if isinstance(kw.value, ast.Constant)
                    else unresolved
                )
        writes = mode is unresolved or (
            isinstance(mode, str) and bool(set(mode) & WRITE_MODE_CHARS)
        )
        if writes:
            hits.append(node.lineno)
    return hits


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


#: The reviewed write surface. Changing this literal is the whole point: it
#: means someone deliberately widened what Pirx can do, in a diff.
REVIEWED_ACTIONS = ("ticket.comment",)


def test_production_registry_holds_exactly_the_reviewed_actions() -> None:
    assert PRODUCTION_REGISTRY.actions() == REVIEWED_ACTIONS


def test_an_unregistered_action_is_refused() -> None:
    for action in ("ticket.close", "ticket.assign", "host.patch", ""):
        with pytest.raises(UnregisteredActionRefusal) as caught:
            PRODUCTION_REGISTRY.require(action)
        assert caught.value.details["registered"] == list(REVIEWED_ACTIONS)


def test_every_known_intent_is_registered() -> None:
    """The proposer's intent constants and the registry must not drift: an
    intent with no entry proposes actions that can only ever refuse, and an
    entry with no intent is a capability nothing can reach."""
    from pirx.registry import KNOWN_INTENTS

    assert set(KNOWN_INTENTS) == set(REVIEWED_ACTIONS)


def test_every_registered_action_names_an_adapter() -> None:
    for action in PRODUCTION_REGISTRY.actions():
        assert PRODUCTION_REGISTRY.require(action).adapter


def test_a_registry_cannot_be_grown_after_construction() -> None:
    registry = Registry({})
    assert not hasattr(registry, "register")
    assert not hasattr(registry, "add")


# --- Claim 2: the import allowlist ------------------------------------------


def test_no_network_imports_outside_the_allowlist() -> None:
    offenders: list[str] = []
    for path in modules():
        if rel(path) in NETWORK_ALLOWLIST:
            continue
        hits = imported_roots(ast.parse(path.read_text())) & NETWORK_MODULES
        if hits:
            offenders.append(f"{rel(path)}: {sorted(hits)}")
    assert not offenders, f"network reach outside allowlist: {offenders}"


def test_no_process_or_shell_reach_anywhere() -> None:
    """No module may spawn a process. `os` is judged by attribute, not by
    import, so reading `os.environ` stays legal and `os.system` does not."""
    offenders: list[str] = []
    for path in modules():
        tree = ast.parse(path.read_text())
        hits = sorted(imported_roots(tree) & SUBPROCESS_MODULES)
        os_hits = sorted(called_attrs(tree) & OS_PROCESS_ATTRS)
        if hits or os_hits:
            offenders.append(f"{rel(path)}: modules={hits} os={os_hits}")
    assert not offenders, f"process reach present: {offenders}"


def test_the_scrape_sees_subpackages() -> None:
    """Guards the blind spot itself: if `adapters/` ever stops being scanned,
    this fails before the network check silently starts passing."""
    scanned = {rel(p) for p in modules()}
    assert "adapters/jira.py" in scanned
    assert "adapters/protocol.py" in scanned
    assert any("/" not in name for name in scanned)


def test_no_dynamic_imports_that_would_defeat_the_scrape() -> None:
    offenders: list[str] = []
    for path in modules():
        tree = ast.parse(path.read_text())
        hits = (imported_roots(tree) | called_attrs(tree)) & DYNAMIC_IMPORT_NAMES
        if hits:
            offenders.append(f"{rel(path)}: {sorted(hits)}")
    assert not offenders, f"dynamic import present: {offenders}"


def test_file_writes_only_in_the_allowlisted_modules() -> None:
    offenders: list[str] = []
    for path in modules():
        if rel(path) in FILE_WRITE_ALLOWLIST:
            continue
        tree = ast.parse(path.read_text())
        hits = sorted(called_attrs(tree) & FILE_WRITE_CALLS)
        opens = write_mode_opens(tree)
        if hits or opens:
            offenders.append(f"{rel(path)}: calls={hits} write_opens={opens}")
    assert not offenders, f"file write outside allowlist: {offenders}"


def test_the_scrape_can_tell_a_read_from_a_write() -> None:
    """The distinguishing capability itself is tested, because an allowlist
    narrowed on the strength of a check nobody verified is worse than a wide
    one honestly labelled."""
    reader = ast.parse("p.open(); q.open('r'); Path(x).read_bytes()")
    writer = ast.parse("p.open('ab'); q.open(mode='w')")
    assert write_mode_opens(reader) == []
    assert len(write_mode_opens(writer)) == 2


def test_allowlist_is_minimal_and_named() -> None:
    """The allowlist itself is reviewed: it may only contain modules that
    exist, so a stale entry cannot silently widen the surface."""
    present = {rel(p) for p in modules()}
    assert present >= NETWORK_ALLOWLIST, (
        f"stale network allowlist entry; package holds {sorted(present)}"
    )
    assert present >= FILE_WRITE_ALLOWLIST


# --- Claim 2b: refusals are never suppressed --------------------------------


def test_refusals_are_recorded_or_terminal_never_swallowed() -> None:
    """A refusal may be caught outside the runner **only to record it**, and
    such a handler must end in a bare ``raise``.

    Sharpened in 0.2.0.0: the earlier rule ("only the runner may catch") was
    too blunt once `session.py` needed to write refusal events. Recording is
    not suppression; swallowing is. This checks the property that actually
    matters - control flow still terminates at the caller - instead of the
    proxy that happened to hold in 0.1.0.0 (P11).
    """
    offenders: list[str] = []
    for path in modules():
        if rel(path) == "cli.py":
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.ExceptHandler):
                continue
            handled = ast.dump(node.type) if node.type else "bare"
            if "Refusal" not in handled:
                continue
            last = node.body[-1]
            reraises = isinstance(last, ast.Raise) and last.exc is None
            if not reraises:
                offenders.append(f"{rel(path)}:{node.lineno}")
    assert not offenders, f"refusal caught without re-raise: {offenders}"


def test_the_runner_is_the_only_terminal_catch_site() -> None:
    """Exactly one module may end a refusal's life. If a second appears, the
    question 'where do refusals go' has two answers, which is one too many."""
    terminal: list[str] = []
    for path in modules():
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.ExceptHandler) or node.type is None:
                continue
            if "Refusal" not in ast.dump(node.type):
                continue
            last = node.body[-1]
            if not (isinstance(last, ast.Raise) and last.exc is None):
                terminal.append(rel(path))
    assert set(terminal) == {"cli.py"}, f"terminal catch sites: {sorted(set(terminal))}"
