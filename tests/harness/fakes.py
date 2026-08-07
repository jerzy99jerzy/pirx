"""Test doubles for the adapter seam.

A recording adapter and a recording transport, so attacks can exercise the
write path without a network. The transport double is the honest one: it
proves the *request Pirx builds* is correct, which is the part this codebase
controls. Reachability of a real Jira is not tested here and is named as such
in the threat model rather than implied by a green tick.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from pirx.adapters.jira import AdapterError
from pirx.adapters.protocol import CommentRef, HttpResponse
from pirx.types import TargetId


@dataclass
class RecordingAdapter:
    """Accepts comments and remembers them by idempotency key."""

    landed: dict[str, CommentRef] = field(default_factory=dict)
    calls: list[tuple[str, str]] = field(default_factory=list)
    fail_with: str | None = None
    #: Called at the moment `comment` runs, so a test can observe what the
    #: ledger already held *before* the write - the property "intent is
    #: recorded before the action" is otherwise unmeasurable from the
    #: outside, and asserting on final ordering silently accepts a write
    #: that happened first.
    observe: Callable[[], list[str]] | None = None
    observed_before_write: list[str] = field(default_factory=list)
    #: Simulates a crash *after* the target system accepted the write, which
    #: is the case reconciliation exists for.
    vanish_after_write: bool = False

    def comment(
        self, ticket_id: TargetId, body: str, idempotency_key: str
    ) -> CommentRef:
        self.calls.append((str(ticket_id), idempotency_key))
        if self.observe is not None:
            self.observed_before_write = self.observe()
        if self.fail_with is not None:
            raise AdapterError(self.fail_with, status=500)
        ref = CommentRef(
            ticket_id=ticket_id,
            comment_id=f"c{len(self.landed) + 1}",
            url=f"https://tickets.example/{ticket_id}/c{len(self.landed) + 1}",
        )
        self.landed[idempotency_key] = ref
        if self.vanish_after_write:
            raise KeyboardInterrupt("simulated crash after the write landed")
        return ref

    def find_comment(
        self, ticket_id: TargetId, idempotency_key: str
    ) -> CommentRef | None:
        return self.landed.get(idempotency_key)

    def healthcheck(self) -> bool:
        return self.fail_with is None


@dataclass
class RecordingTransport:
    """Captures the HTTP requests an adapter builds."""

    responses: list[HttpResponse] = field(default_factory=list)
    sent: list[dict[str, object]] = field(default_factory=list)

    def send(
        self, method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> HttpResponse:
        self.sent.append(
            {"method": method, "url": url, "headers": headers, "body": body}
        )
        if self.responses:
            return self.responses.pop(0)
        return HttpResponse(status=201, body=b'{"id": "10001", "self": "u"}')
