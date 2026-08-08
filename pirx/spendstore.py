"""The durable spend record: one file per burnt nonce, in one directory.

Through 0.6.0.0 the spent-set was an in-process ``set``, which was correct
while approval and execution lived in one process and dishonest the moment
they did not. 0.7.0.0 splits them - the gate holds the call, a human approves
on a separate surface - so the coupled pair the brief has owed since section
9 lands here, in one version, together: **an HMAC over the grant scope and a
durable spend store.** A stateless-verifiable grant with no durable spend
record is replayable across restarts, and a durable spend record without a
verifiable grant protects nothing (family practice P5).

The mechanism is deliberately the dullest one that is correct: `open` with
`O_CREAT | O_EXCL` on a file named for the nonce. The kernel decides who won,
so two gate processes racing the same grant produce exactly one winner
without a lock file, a database, or a lease protocol. `O_EXCL` is the whole
concurrency design.

Does NOT:
  - store the grant. Only the fact that a nonce is burnt. A store holding
    grants would be a place from which authority could be read back out.
  - expire entries. A spend record that is garbage-collected is a replay
    window with a timer on it. Pruning is an operator decision made against
    the ledger, and it is not automated here.
  - work across hosts. One directory, one filesystem. A shared store is the
    first networked transport, which is PT14's named trigger, not a quiet
    upgrade.
"""

from __future__ import annotations

import os
from pathlib import Path

from .errors import SpentGrantRefusal
from .types import GrantNonce

#: Nonces are hex; anything else is a caller bug or a traversal attempt, and
#: both are refused before a path is built from the value.
_NONCE_CHARS = set("0123456789abcdef")


def _validate(nonce: GrantNonce) -> str:
    text = str(nonce)
    if not text or len(text) > 64 or not set(text) <= _NONCE_CHARS:
        raise ValueError("nonce is not lowercase hex of a sane length")
    return text


class SpendStore:
    """Single-use enforcement that survives the process."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)

    def _path(self, nonce: GrantNonce) -> Path:
        return self.directory / _validate(nonce)

    def is_spent(self, nonce: GrantNonce) -> bool:
        """Advisory only. The authoritative answer is what ``spend`` returns.

        A caller that checks this and then acts has a race; a caller that
        calls ``spend`` does not. The method exists for reporting, and
        `reconcile` is its only intended reader.
        """
        return self._path(nonce).exists()

    def spend(self, nonce: GrantNonce) -> None:
        """Burn the nonce, or refuse. Atomic against concurrent callers.

        Returns nothing on success: there is no value here worth carrying,
        and a boolean return would invite a caller to ignore it.
        """
        path = self._path(nonce)
        try:
            handle = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise SpentGrantRefusal(
                "grant already spent", nonce=str(nonce)
            ) from exc
        try:
            os.fsync(handle)
        finally:
            os.close(handle)
        # The record must survive a power loss as firmly as the ledger entry
        # that will reference it, so the directory entry is synced too - on
        # most filesystems the file's own fsync does not guarantee the name
        # is durable.
        dir_fd = os.open(self.directory, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    def count(self) -> int:
        return sum(1 for _ in self.directory.iterdir())
