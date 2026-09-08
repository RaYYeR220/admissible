"""Bi-temporal replay: what we knew then, and what was true then.

Two clocks, two questions:

* :meth:`Timeline.as_of` -- *transaction time*. "Show me the memory as the agent
  held it on 3 March." This is the one that matters after the fact, when
  somebody asks why a payment was authorised. Judging a past decision against
  present knowledge is hindsight, and hindsight is not evidence.
* :meth:`Timeline.valid_at` -- *valid time*. "Which record claims to describe
  1 February?" A correction written today about last month is a different thing
  from a record written last month, and both clocks have to be readable or the
  distinction is unrecoverable.

WHAT IS RECONSTRUCTIBLE, AND WHAT IS NOT
----------------------------------------
Sibyl's ``entities`` table holds exactly one row per ``(category, name)``:
``set_entity`` updates in place. So history has to come from two other places,
and each has a different completeness guarantee.

* ``archived_entities`` holds **full bodies** of versions that were archived.
  :meth:`AdmissibleStore.supersede` archives before it overwrites, so every
  supersession leaves a complete, replayable version behind. These are
  reconstructible in full.
* ``journal_events`` holds a **record of every write** -- digest, tier, source,
  actor, ``observed_at`` -- but not the body. A version that was overwritten by
  a bare :meth:`AdmissibleStore.remember` (rather than ``supersede``) is proven
  to have existed and is identified by digest, but its claim is gone.

That gap is real and this module refuses to paper over it.
:meth:`Timeline.unreconstructible` lists exactly those digests, and
:meth:`Timeline.as_of` returns ``None`` rather than the nearest surviving
version when the honest answer is "we held something else then and cannot show
you what". A replay that quietly substitutes a neighbouring version is worse
than no replay, because it looks like an answer.

Not reconstructible at all, and not pretended otherwise: writes made by anything
other than this package (Sibyl's own ``set_entity`` callers leave no journal
record of ours), and the ordering of two versions written inside the same
millisecond with the same ``observed_at`` -- SQLite's timestamps stop there.
Write order is preserved through ``archived_at`` + ``rowid``, which is why
:meth:`Timeline.history` is ordered by persistence rather than by claim.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .envelope import Envelope, utcnow
from .store import AdmissibleStore, MalformedMemory


@dataclass(frozen=True, slots=True)
class Version:
    """One recovered version of a memory, with how we recovered it."""

    envelope: Envelope
    #: ``"archive"`` or ``"current"`` -- which table the body came from.
    origin: str
    #: When the row was persisted (``archived_at`` / ``updated_at``). Distinct
    #: from ``observed_at``, which is what the envelope claims about itself.
    recorded_at: str


class Timeline:
    """Replay one memory across both clocks."""

    def __init__(self, store: AdmissibleStore) -> None:
        self._store = store

    # ------------------------------------------------------------------
    def versions(self, category: str, name: str) -> list[Version]:
        """Every recoverable version, in the order it was persisted.

        Persistence order rather than ``observed_at`` order on purpose:
        ``observed_at`` is a claim the writer makes about itself, and a
        back-dated envelope would silently reorder history. ``archived_at`` and
        ``rowid`` are ours.
        """
        out: list[Version] = []
        for row in self._store.archived(category, name):
            parsed = self._store.parse_body(category, name, row["body"])
            if isinstance(parsed, Envelope):
                out.append(Version(parsed, "archive", row["archived_at"]))
        current = self._store.recall(category, name)
        if isinstance(current, Envelope):
            row = self._store.client.get_entity(category, name)
            out.append(Version(current, "current", row["updated_at"]))
        return out

    def history(self, category: str, name: str) -> list[Envelope]:
        """:meth:`versions` without the bookkeeping. Oldest first."""
        return [v.envelope for v in self.versions(category, name)]

    # ------------------------------------------------------------------
    def as_of(self, category: str, name: str, when: str) -> Envelope | None:
        """The envelope as the agent held it at transaction time ``when``.

        Walks the ``supersedes`` chain backwards from the current record: each
        link names its predecessor by digest, so the walk follows what the
        writer actually asserted rather than re-deriving an order from
        timestamps. Stops at the first version we had already learned by
        ``when`` (``Envelope.was_known_at``).

        Returns ``None`` when we knew nothing yet -- and also when the chain
        runs into a version whose body did not survive (see the module note on
        bare overwrites). Both are honest "cannot show you", and conflating them
        with "nothing existed" is why the distinction is spelled out in
        :meth:`unreconstructible`.
        """
        versions = self.versions(category, name)
        if not versions:
            return None
        by_digest = {v.envelope.digest: v.envelope for v in versions}

        head = versions[-1].envelope
        seen: set[str] = set()
        while True:
            if head.was_known_at(when):
                return head
            previous = head.provenance.supersedes
            if previous is None or previous in seen or previous not in by_digest:
                # Either we have reached the first version we hold (nothing was
                # known at `when`), or the chain points at a body we no longer
                # have. Neither justifies handing back a different version.
                return None
            seen.add(previous)
            head = by_digest[previous]

    def valid_at(
        self,
        category: str,
        name: str,
        when: str,
        *,
        as_of: str | None = None,
    ) -> Envelope | None:
        """The version that claims to describe valid time ``when``.

        ``as_of`` restricts the search to what we had learned by that
        transaction time, which is how you ask the full bi-temporal question:
        "on 1 February, what would we have said about 15 January?". It defaults
        to now, i.e. our best current understanding of the past.

        When several versions cover ``when``, the most recently persisted one
        wins: a later record about the same window is a correction.
        """
        cutoff = as_of or utcnow()
        best: Envelope | None = None
        for version in self.versions(category, name):
            env = version.envelope
            if not env.was_known_at(cutoff):
                continue
            if env.is_valid_at(when):
                best = env
        return best

    # ------------------------------------------------------------------
    def unreconstructible(self, category: str, name: str) -> list[dict[str, Any]]:
        """Journal records whose body we can no longer produce, oldest first.

        This is the honesty surface. Each entry proves a version existed, names
        its digest, its tier, its source and its actor -- everything except the
        claim itself. If this list is non-empty, :meth:`history` is a subset of
        what happened and any replay across that window is incomplete.
        """
        recoverable = {v.envelope.digest for v in self.versions(category, name)}
        records = self._store.journal(category=category, name=name)
        lost = [
            rec
            for rec in records
            if rec.get("digest") and rec["digest"] not in recoverable
        ]
        lost.reverse()  # journal reads newest-first; history reads oldest-first
        return lost

    def malformed(self, category: str, name: str) -> list[MalformedMemory]:
        """Stored versions that are not parseable envelopes.

        Separate from :meth:`unreconstructible`: those are bodies we no longer
        have, these are bodies we have and cannot trust.
        """
        out: list[MalformedMemory] = []
        for row in self._store.archived(category, name):
            parsed = self._store.parse_body(category, name, row["body"])
            if isinstance(parsed, MalformedMemory):
                out.append(parsed)
        current = self._store.recall(category, name)
        if isinstance(current, MalformedMemory):
            out.append(current)
        return out


# ----------------------------------------------------------------------
# Module-level convenience: the shape the rest of the codebase reads best.
# ----------------------------------------------------------------------
def as_of(
    store: AdmissibleStore, category: str, name: str, when: str
) -> Envelope | None:
    """See :meth:`Timeline.as_of`."""
    return Timeline(store).as_of(category, name, when)


def valid_at(
    store: AdmissibleStore,
    category: str,
    name: str,
    when: str,
    *,
    as_of: str | None = None,
) -> Envelope | None:
    """See :meth:`Timeline.valid_at`."""
    return Timeline(store).valid_at(category, name, when, as_of=as_of)


def history(store: AdmissibleStore, category: str, name: str) -> list[Envelope]:
    """See :meth:`Timeline.history`."""
    return Timeline(store).history(category, name)
