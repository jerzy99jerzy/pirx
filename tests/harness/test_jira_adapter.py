"""Jira adapter tests, against an injected transport.

What is measured here: the request Pirx builds - method, URL, headers, body
shape, idempotency trailer - and how it maps responses to outcomes. What is
**not** measured: that a real Jira accepts any of it. Reachability needs a
Jira; this suite needs to run in CI in under a second. The threat model says
which is which rather than letting a green tick imply both.
"""

from __future__ import annotations

import base64
import json

import pytest
from fakes import RecordingTransport

from pirx.adapters.jira import (
    IDEMPOTENCY_TRAILER,
    AdapterError,
    JiraAdapter,
    JiraCredentials,
)
from pirx.adapters.protocol import HttpResponse
from pirx.types import TargetId

CREDS = JiraCredentials(
    base_url="https://example.atlassian.net/", email="a@b.c", api_token="tok"
)
TICKET = TargetId("SEC-412")
KEY = "a" * 64


def adapter(transport: RecordingTransport) -> JiraAdapter:
    return JiraAdapter(CREDS, transport)


def test_comment_posts_to_the_issue_comment_endpoint() -> None:
    transport = RecordingTransport()
    adapter(transport).comment(TICKET, "body text", KEY)
    sent = transport.sent[0]
    assert sent["method"] == "POST"
    assert sent["url"] == (
        "https://example.atlassian.net/rest/api/3/issue/SEC-412/comment"
    )


def test_trailing_slash_in_base_url_does_not_double() -> None:
    transport = RecordingTransport()
    adapter(transport).comment(TICKET, "b", KEY)
    assert "//rest" not in str(transport.sent[0]["url"])


def test_idempotency_key_travels_in_the_header_and_the_body() -> None:
    """The header is for anything upstream that honours it; the body trailer
    is the load-bearing one, because Jira offers no native idempotency and
    reconciliation must work anyway."""
    transport = RecordingTransport()
    adapter(transport).comment(TICKET, "body text", KEY)
    sent = transport.sent[0]
    headers = sent["headers"]
    assert isinstance(headers, dict)
    assert headers["X-Idempotency-Key"] == KEY
    body = json.loads(str(sent["body"], "utf-8"))
    text = body["body"]["content"][0]["content"][0]["text"]
    assert f"[{IDEMPOTENCY_TRAILER}: {KEY}]" in text
    assert text.startswith("body text")


def test_credentials_are_encoded_as_basic_auth() -> None:
    transport = RecordingTransport()
    adapter(transport).comment(TICKET, "b", KEY)
    headers = transport.sent[0]["headers"]
    assert isinstance(headers, dict)
    value = headers["Authorization"]
    assert value.startswith("Basic ")
    decoded = base64.b64decode(value.removeprefix("Basic ")).decode()
    assert decoded == "a@b.c:tok"


def test_the_token_never_appears_in_a_url_or_a_body() -> None:
    """Credentials belong in one header. A token in a query string ends up in
    proxy logs, and a token in a body ends up in a ticket."""
    transport = RecordingTransport(
        responses=[HttpResponse(201, b'{"id": "1", "self": "u"}'),
                   HttpResponse(200, b'{"comments": []}')]
    )
    api = adapter(transport)
    api.comment(TICKET, "b", KEY)
    api.find_comment(TICKET, KEY)
    for sent in transport.sent:
        assert "tok" not in str(sent["url"])
        assert b"tok" not in (sent["body"] or b"")


@pytest.mark.parametrize("status", [400, 401, 403, 404, 429, 500, 503])
def test_non_success_status_raises_adapter_error_not_a_refusal(
    status: int,
) -> None:
    """A target system failing is not Pirx declining. Different fact,
    different type, different ledger event."""
    transport = RecordingTransport(responses=[HttpResponse(status, b"{}")])
    with pytest.raises(AdapterError) as caught:
        adapter(transport).comment(TICKET, "b", KEY)
    assert caught.value.details["status"] == status


def test_find_comment_matches_only_its_own_trailer() -> None:
    payload = {
        "comments": [
            {"id": "1", "body": "unrelated human comment"},
            {"id": "2", "body": f"something [{IDEMPOTENCY_TRAILER}: {KEY}]"},
        ]
    }
    transport = RecordingTransport(
        responses=[HttpResponse(200, json.dumps(payload).encode())]
    )
    found = adapter(transport).find_comment(TICKET, KEY)
    assert found is not None
    assert found.comment_id == "2"


def test_find_comment_returns_none_when_the_key_is_absent() -> None:
    payload = {"comments": [{"id": "1", "body": "no key here"}]}
    transport = RecordingTransport(
        responses=[HttpResponse(200, json.dumps(payload).encode())]
    )
    assert adapter(transport).find_comment(TICKET, KEY) is None


def test_find_comment_never_writes() -> None:
    transport = RecordingTransport(
        responses=[HttpResponse(200, b'{"comments": []}')]
    )
    adapter(transport).find_comment(TICKET, KEY)
    assert all(sent["method"] == "GET" for sent in transport.sent)


def test_healthcheck_is_a_read_of_the_caller_identity() -> None:
    transport = RecordingTransport(responses=[HttpResponse(200, b"{}")])
    assert adapter(transport).healthcheck() is True
    assert transport.sent[0]["method"] == "GET"
    assert str(transport.sent[0]["url"]).endswith("/rest/api/3/myself")
