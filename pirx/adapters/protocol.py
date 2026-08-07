"""The ticket adapter protocol and its transport seam.

Three functions, no more. A capability calls `comment` to write,
`find_comment` to answer "did this land" during reconciliation, and
`healthcheck` to fail early rather than mid-action.

Does NOT:
  - retry. Retry policy belongs to the human holding the ledger, because a
    retry that reuses authority is PT8 by another name.
  - interpret ticket state. Pirx appends; it does not read workflow, assess
    status, or decide whether a ticket deserves a comment.
  - own credentials beyond holding what it was given. There is no credential
    discovery, no keychain read, no environment scan inside an adapter.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ..types import TargetId


@dataclass(frozen=True, slots=True)
class CommentRef:
    """A comment that exists in the target system."""

    ticket_id: TargetId
    comment_id: str
    url: str


@dataclass(frozen=True, slots=True)
class HttpResponse:
    status: int
    body: bytes


class HttpTransport(Protocol):
    """The seam that keeps adapters testable without a network.

    An adapter builds a request and hands it here. Tests inject a transport
    that records and replies; production injects one that speaks HTTP. The
    request-building logic - headers, URL, payload shape, idempotency
    trailer - is therefore measured, while reachability is not, and the
    threat model says which is which.
    """

    def send(
        self, method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> HttpResponse: ...


class TicketAdapter(Protocol):
    def comment(
        self, ticket_id: TargetId, body: str, idempotency_key: str
    ) -> CommentRef: ...

    def find_comment(
        self, ticket_id: TargetId, idempotency_key: str
    ) -> CommentRef | None: ...

    def healthcheck(self) -> bool: ...
