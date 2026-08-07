"""The capability registry: the complete write surface, as data.

**One entry from 0.3.0.0.** ``PRODUCTION_REGISTRY`` held zero entries through
0.1.0.0 and 0.2.0.0 so that "nothing can write anything" was established, and
attacked by the harness, *before* the first capability existed rather than
retrofitted around one (family practice P3). The first entry is
``ticket.comment``: the smallest genuine write - visible, reversible, and
useless to an attacker who obtains it.

The registry names actions; it does not hold adapters. Wiring an adapter is
the runner's job, where it is visible, and a registered action with no
adapter refuses rather than falling back to anything.

Does NOT:
  - load entries from configuration, environment, plugins, or entry points.
    Registration is a code change reviewed like one. A registry that can grow
    at runtime is a write surface nobody reviewed (P6 applied to capability
    surface).
  - execute anything. A ``CapabilityEntry`` names an action and, from
    0.3.0.0, points at an adapter function; in this version the type exists
    and the mapping is empty.
  - validate proposals. A proposal naming an unregistered action is legal to
    build and to show a human; it is refused at spend, which is what makes
    the 0.1.0.0 end-to-end demonstration honest.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from .errors import UnregisteredActionRefusal

#: Action names the deterministic proposer may emit. A code constant, not a
#: derived value: even with no model in the loop, an action name never comes
#: from producer prose (PT2).
KNOWN_INTENTS: tuple[str, ...] = ("ticket.comment",)


@dataclass(frozen=True, slots=True)
class CapabilityEntry:
    action: str
    description: str
    #: Which adapter family this action needs. Data, not a callable: the
    #: registry stays inert and inspectable.
    adapter: str


class Registry:
    """An immutable mapping from action name to capability entry."""

    def __init__(self, entries: Mapping[str, CapabilityEntry] | None = None) -> None:
        self._entries: dict[str, CapabilityEntry] = dict(entries or {})

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, action: object) -> bool:
        return action in self._entries

    def actions(self) -> tuple[str, ...]:
        return tuple(sorted(self._entries))

    def require(self, action: str) -> CapabilityEntry:
        entry = self._entries.get(action)
        if entry is None:
            raise UnregisteredActionRefusal(
                "action is not registered", action=action,
                registered=list(self.actions()),
            )
        return entry


#: The write surface of this version. Every entry is reviewed like the code
#: change it is; there is no path that adds one at runtime.
PRODUCTION_REGISTRY = Registry(
    {
        "ticket.comment": CapabilityEntry(
            action="ticket.comment",
            description=(
                "Append a comment to an existing ticket. Does not create, "
                "transition, assign, or close anything."
            ),
            adapter="ticket",
        )
    }
)
