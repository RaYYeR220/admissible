"""Assembling a gate from a store and a chain.

`gate.py` deliberately knows nothing about Sibyl Memory or about web3 -- it talks
to three narrow protocols so it can be scored offline against canned evidence.
This module is where those protocols meet the real thing, and it is kept
separate so that the security-critical file stays readable on its own.
"""

from __future__ import annotations

from typing import Any

from .flagged import FlaggedActors
from .gate import AdmissionGate
from .store import AdmissibleStore


class StoreHistory:
    """Answers the gate's two history questions out of Sibyl's own journal.

    Both answers come from the append-only journal rather than from the entity
    rows, which matters: entity rows are current state and can be overwritten,
    while the journal is the part an attacker who reaches the store still cannot
    quietly rewrite.
    """

    def __init__(self, store: AdmissibleStore) -> None:
        self._store = store
        self._superseded: dict[str, str] | None = None
        self._recorded: dict[str, str] | None = None

    def superseding_digest(self, digest: str) -> str | None:
        """The digest that invalidated this one, if a supersede ever recorded it."""
        if self._superseded is None:
            self._superseded = {
                record["superseded_digest"]: record.get("digest", "")
                for record in self._store.journal(op="supersede")
                if record.get("superseded_digest")
            }
        return self._superseded.get(digest) or None

    def recorded_at(self, digest: str) -> str | None:
        """When this store journalled the memory, by our clock rather than its own.

        Read out of Sibyl's append-only journal. Entity rows are current state
        and can be overwritten; the journal is the part an attacker who reaches
        the store still cannot quietly rewrite, which is why the honest half of
        the backdating comparison comes from here.
        """
        if self._recorded is None:
            self._recorded = {}
            # Oldest first, so the earliest record of a digest is the one kept:
            # re-remembering a claim later must not launder its original age.
            for record in reversed(self._store.journal(limit=100000)):
                key = record.get("digest")
                ts = record.get("ts")
                if key and ts:
                    self._recorded.setdefault(key, ts)
        return self._recorded.get(digest)

    def invalidate(self) -> None:
        """Drop caches after a write.

        The gate is consulted many times per decision and the journal is a JSON
        blob scan, so the lookups are memoised per gate. Anything that writes to
        the journal has to say so.
        """
        self._superseded = None
        self._recorded = None


def build_gate(
    store: AdmissibleStore,
    chain: Any | None = None,
    *,
    flags: FlaggedActors | None = None,
    **kwargs: Any,
) -> tuple[AdmissionGate, StoreHistory]:
    """The gate an agent should actually use, plus the history it caches.

    The history object is returned rather than hidden so the caller can
    invalidate it after writing -- an agent that flags an actor mid-decision
    needs the next verdict to see the flag.
    """
    history = StoreHistory(store)
    gate = AdmissionGate(
        chain=chain,
        flags=flags if flags is not None else FlaggedActors(store),
        history=history,
        **kwargs,
    )
    return gate, history
