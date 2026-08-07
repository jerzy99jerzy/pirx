"""Jira Cloud adapter: append a comment to an existing issue.

Chosen first because Rappaport already speaks Jira, which makes the first
capability a comment on an issue Rappaport itself created - a real
integration rather than a demo.

This is the **only** module in the package that imports a network facility.
The import-allowlist scrape treats that as the definition of the write world:
any other module reaching `urllib` fails the build.

Idempotency: Jira has no native idempotency key for comment creation, so the
key travels two ways. It is sent as an `X-Idempotency-Key` header for any
proxy or gateway that honours it, and - the load-bearing one - embedded in
the comment body as a structured trailer, so `find_comment` can answer "did
this land" by searching the issue's own comments. That makes reconciliation
work on a system that offers no help.

**Provenance of the API shape.** Endpoint, ADF body structure, and the v3
requirement that `body` be a document rather than a string were verified
against Atlassian's published REST v3 documentation on 2026-08-07. What
remains untested is whether a live tenant accepts these requests (review
finding F15); the shape itself is no longer a memory claim.

**Known limitation, not a bug (F30).** `find_comment` reads one page of the
issue's comments. Jira paginates that collection - default 50 - so on an
issue with a long comment history, reconciliation can report "did NOT land"
for a comment that landed. Accepted for now because the write surface is
comments Pirx itself just created, so the target is near the tail; the honest
consequence is that a false negative sends a human to issue a fresh grant for
work already done, which is the safe direction to be wrong in. Trigger for
fixing: the first reconciliation that reports a false negative, or the first
adapter for a system with a smaller page size.

Does NOT:
  - paginate. See F30 above; one page, and the limitation is named rather
    than hidden behind a loop nobody tested.
  - create, transition, close, or assign issues. Appending to an existing
    issue is the whole surface; a wider one would make Pirx a second, worse
    change-control system.
  - discover credentials. The token is passed in by the caller, once.
  - retry, back off, or queue. One call, one outcome, recorded.
  - parse issue content for meaning. It searches its own trailer, nothing
    else.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from urllib import error as urlerror
from urllib import request as urlrequest

from ..types import TargetId
from .protocol import CommentRef, HttpResponse, HttpTransport

#: Structured trailer appended to every comment body. The reconciliation
#: story depends on this string being stable, so it is a constant, and
#: changing it is a breaking change to reconciliation of older comments.
IDEMPOTENCY_TRAILER = "pirx-idempotency-key"

#: Seconds. A constant, not configuration: a timeout that can be raised in a
#: hurry is a hang waiting for an incident (P6).
REQUEST_TIMEOUT = 15.0


class UrllibTransport:
    """Production transport. Stdlib only - no dependency to audit."""

    def send(
        self, method: str, url: str, headers: dict[str, str], body: bytes | None
    ) -> HttpResponse:
        req = urlrequest.Request(url, data=body, headers=headers, method=method)
        try:
            with urlrequest.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                return HttpResponse(status=resp.status, body=resp.read())
        except urlerror.HTTPError as exc:
            return HttpResponse(status=exc.code, body=exc.read())


@dataclass(frozen=True, slots=True)
class JiraCredentials:
    base_url: str
    email: str
    api_token: str

    def auth_header(self) -> str:
        raw = f"{self.email}:{self.api_token}".encode()
        return "Basic " + base64.b64encode(raw).decode("ascii")


def trailer_for(idempotency_key: str) -> str:
    return f"\n\n[{IDEMPOTENCY_TRAILER}: {idempotency_key}]"


class JiraAdapter:
    def __init__(
        self, credentials: JiraCredentials, transport: HttpTransport
    ) -> None:
        self._creds = credentials
        self._transport = transport

    def _headers(self, idempotency_key: str | None = None) -> dict[str, str]:
        headers = {
            "Authorization": self._creds.auth_header(),
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if idempotency_key is not None:
            headers["X-Idempotency-Key"] = idempotency_key
        return headers

    def _issue_url(self, ticket_id: TargetId, suffix: str = "") -> str:
        base = self._creds.base_url.rstrip("/")
        return f"{base}/rest/api/3/issue/{ticket_id}/comment{suffix}"

    def comment(
        self, ticket_id: TargetId, body: str, idempotency_key: str
    ) -> CommentRef:
        payload = {
            "body": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {
                                "type": "text",
                                "text": body + trailer_for(idempotency_key),
                            }
                        ],
                    }
                ],
            }
        }
        response = self._transport.send(
            "POST",
            self._issue_url(ticket_id),
            self._headers(idempotency_key),
            json.dumps(payload).encode("utf-8"),
        )
        if response.status not in (200, 201):
            raise AdapterError(
                f"jira comment failed with status {response.status}",
                status=response.status,
            )
        data = json.loads(response.body.decode("utf-8"))
        return CommentRef(
            ticket_id=ticket_id,
            comment_id=str(data.get("id", "")),
            url=str(data.get("self", "")),
        )

    def find_comment(
        self, ticket_id: TargetId, idempotency_key: str
    ) -> CommentRef | None:
        """Search the issue's comments for our own trailer.

        Reconciliation reads; it never writes and never re-executes.
        """
        response = self._transport.send(
            "GET", self._issue_url(ticket_id), self._headers(), None
        )
        if response.status != 200:
            raise AdapterError(
                f"jira comment lookup failed with status {response.status}",
                status=response.status,
            )
        data = json.loads(response.body.decode("utf-8"))
        needle = f"{IDEMPOTENCY_TRAILER}: {idempotency_key}"
        for comment in data.get("comments", []):
            if needle in json.dumps(comment.get("body", "")):
                return CommentRef(
                    ticket_id=ticket_id,
                    comment_id=str(comment.get("id", "")),
                    url=str(comment.get("self", "")),
                )
        return None

    def healthcheck(self) -> bool:
        base = self._creds.base_url.rstrip("/")
        response = self._transport.send(
            "GET", f"{base}/rest/api/3/myself", self._headers(), None
        )
        return response.status == 200


class AdapterError(Exception):
    """A target system said no, or said something unparseable.

    Deliberately **not** a `Refusal`: a refusal is Pirx declining to act. This
    is the far side failing, which is a different fact and gets a different
    ledger event.
    """

    def __init__(self, message: str, **details: object) -> None:
        super().__init__(message)
        self.message = message
        self.details = details
