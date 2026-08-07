"""Parse and validate a ``cve-digest.verdict/1`` payload as hostile input.

This is the only module that ever sees a raw dict. Everything downstream
receives frozen dataclasses, so malformed data cannot exist past this
boundary: the types that represent a verdict cannot be constructed from
invalid values.

Does NOT:
  - interpret prose. ``triage_note`` and ``recommended_action`` become
    ``UntrustedProse`` and are never parsed for intent, matched for keywords,
    or used to fill an action parameter (PT2).
  - authenticate the origin of the payload. A well-formed payload from an
    attacker who can write to the transport is indistinguishable from a real
    one. That is PT14: accepted, with a named trigger (first networked
    transport), not an oversight.
  - coerce. An unknown schema id is refused, not upgraded; an out-of-range
    score is refused, not clamped.
  - trust the producer's own de-duplication. A ``cve_id`` present in both
    ``verdicts`` and ``review_lane`` survives only in the review lane, and
    the collision is recorded (PT11).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from .errors import BoundsRefusal, EnumRefusal, MalformedIdRefusal, SchemaRefusal
from .types import (
    ACCEPTED_VERDICT_SCHEMA,
    MAX_PROSE_CHARS,
    CveId,
    UntrustedProse,
    VerdictId,
)

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")

PRIORITIES = frozenset({"P1", "P2", "P3"})
ESTATE_STATES = frozenset({"present", "absent", "unknown"})
VEX_STATUSES = frozenset(
    {"affected", "not_affected", "fixed", "under_investigation"}
)


@dataclass(frozen=True, slots=True)
class Verdict:
    cve_id: CveId
    priority: str
    in_kev: bool
    epss: float
    cvss: float | None
    cvss_pending: bool
    estate_state: str
    vex_status: str
    score: float
    triage_note: UntrustedProse
    recommended_action: UntrustedProse
    nvd_url: str

    @property
    def verdict_id(self) -> VerdictId:
        return VerdictId(f"{ACCEPTED_VERDICT_SCHEMA}#{self.cve_id}")


@dataclass(frozen=True, slots=True)
class VerdictBundle:
    schema: str
    verdicts: tuple[Verdict, ...]
    review_lane: tuple[CveId, ...]
    notices: tuple[str, ...]
    collisions: tuple[CveId, ...]
    truncated: tuple[CveId, ...]


def _require(condition: bool, exc: type, message: str, **details: Any) -> None:
    if not condition:
        raise exc(message, **details)


def _as_bool(value: Any, field: str, cve: str) -> bool:
    """Check and narrow. Helpers return the value so validation is visible to
    a type checker as well as at runtime; a checker that cannot see the
    refusal will not stop the bug the refusal exists for."""
    if not isinstance(value, bool):
        raise BoundsRefusal(f"{field} is not a boolean", cve_id=cve)
    return value


def _as_number(value: Any, field: str, cve: str, low: float, high: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BoundsRefusal(f"{field} is not a number", cve_id=cve)
    number = float(value)
    if not low <= number <= high:
        raise BoundsRefusal(
            f"{field} out of range", cve_id=cve, value=str(number),
            low=low, high=high,
        )
    return number


def _as_list(value: Any, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise SchemaRefusal(f"{field} is not a list", field=field)
    return value


def _as_enum(value: Any, allowed: frozenset[str], field: str, cve: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise EnumRefusal(f"unenumerated {field}", cve_id=cve, value=str(value))
    return value


def _prose(raw: Any, field: str, cve: str, truncated: set[str]) -> UntrustedProse:
    _require(
        isinstance(raw, str), BoundsRefusal, f"{field} is not a string", cve_id=cve
    )
    text = str(raw)
    if len(text) > MAX_PROSE_CHARS:
        truncated.add(cve)
        text = text[:MAX_PROSE_CHARS]
    return UntrustedProse(text)


def _verdict(raw: Any, truncated: set[str]) -> Verdict:
    _require(isinstance(raw, dict), SchemaRefusal, "verdict is not an object")
    item: dict[str, Any] = raw

    cve = item.get("cve_id")
    _require(
        isinstance(cve, str) and bool(CVE_PATTERN.match(cve)),
        MalformedIdRefusal,
        "malformed cve_id",
        cve_id=str(cve),
    )
    cve_id = str(cve)

    priority = _as_enum(item.get("priority"), PRIORITIES, "priority", cve_id)
    estate = _as_enum(
        item.get("estate_state"), ESTATE_STATES, "estate_state", cve_id
    )
    vex = _as_enum(item.get("vex_status"), VEX_STATUSES, "vex_status", cve_id)

    epss = _as_number(item.get("epss"), "epss", cve_id, 0.0, 1.0)
    score = _as_number(item.get("score"), "score", cve_id, 0.0, 100.0)

    cvss_pending = _as_bool(item.get("cvss_pending"), "cvss_pending", cve_id)
    cvss_raw = item.get("cvss")
    if cvss_pending:
        _require(
            cvss_raw is None, BoundsRefusal,
            "cvss present while cvss_pending is true", cve_id=cve_id,
        )
        cvss: float | None = None
    else:
        cvss = _as_number(cvss_raw, "cvss", cve_id, 0.0, 10.0)

    in_kev = _as_bool(item.get("in_kev"), "in_kev", cve_id)

    nvd_url = item.get("nvd_url")
    _require(
        isinstance(nvd_url, str) and nvd_url.startswith("https://nvd.nist.gov/"),
        BoundsRefusal, "nvd_url outside expected origin", cve_id=cve_id,
    )

    return Verdict(
        cve_id=CveId(cve_id),
        priority=priority,
        in_kev=in_kev,
        epss=epss,
        cvss=cvss,
        cvss_pending=cvss_pending,
        estate_state=estate,
        vex_status=vex,
        score=score,
        triage_note=_prose(item.get("triage_note"), "triage_note", cve_id, truncated),
        recommended_action=_prose(
            item.get("recommended_action"), "recommended_action", cve_id, truncated
        ),
        nvd_url=str(nvd_url),
    )


def parse(payload: bytes) -> VerdictBundle:
    """Bytes to ``VerdictBundle``, or a typed refusal."""
    try:
        raw = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SchemaRefusal("payload is not valid UTF-8 JSON", detail=str(exc)) from exc

    _require(isinstance(raw, dict), SchemaRefusal, "payload root is not an object")
    body: dict[str, Any] = raw

    schema = body.get("schema")
    _require(
        schema == ACCEPTED_VERDICT_SCHEMA, SchemaRefusal,
        "unaccepted schema id", found=str(schema),
        accepted=ACCEPTED_VERDICT_SCHEMA,
    )

    raw_verdicts = _as_list(body.get("verdicts"), "verdicts")
    raw_lane = _as_list(body.get("review_lane", []), "review_lane")
    raw_notices = _as_list(body.get("notices", []), "notices")

    lane: list[CveId] = []
    for entry in raw_lane:
        candidate = entry.get("cve_id") if isinstance(entry, dict) else entry
        _require(
            isinstance(candidate, str) and bool(CVE_PATTERN.match(candidate)),
            MalformedIdRefusal, "malformed cve_id in review_lane",
            cve_id=str(candidate),
        )
        lane.append(CveId(str(candidate)))
    lane_set = set(lane)

    truncated: set[str] = set()
    parsed = [_verdict(entry, truncated) for entry in raw_verdicts]

    # The review lane wins on collision. This is a rule, not an assumption
    # about the producer's behaviour, and the collision is reported.
    collisions = tuple(v.cve_id for v in parsed if v.cve_id in lane_set)
    kept = tuple(v for v in parsed if v.cve_id not in lane_set)

    return VerdictBundle(
        schema=str(schema),
        verdicts=kept,
        review_lane=tuple(lane),
        notices=tuple(str(n) for n in raw_notices),
        collisions=collisions,
        truncated=tuple(CveId(c) for c in sorted(truncated)),
    )
