"""The store: every write journalled, every read tolerant, nothing ever deleted.

``AdmissibleStore`` is a thin skin over ``MemoryClient``. Thin on purpose --
the envelope already lives inside Sibyl's own ``entities.body``, so this class
adds discipline rather than a second storage layer:

* **Every write leaves a trace.** ``remember`` writes the entity *and* appends a
  journal event naming the digest, the tier, the source and the actor. The
  entity table holds one row per name and is overwritten in place; the journal
  is append-only. When a dispute happens the journal is the thing you show,
  which is why we pay for it on every write rather than on interesting writes.
* **A bad memory is a verdict, not an exception.** ``recall`` never raises on a
  body it cannot parse. A poisoned or tampered row comes back as
  :class:`MalformedMemory`, whose ``.verdict`` is ``VerdictCode.MALFORMED``.
  An agent deciding whether to pay must be able to route that answer, not catch it.
* **Invalidation is non-destructive.** ``supersede`` archives the old record with
  a reason and writes the new one linked back to it by digest.
  ``delete_entity`` is never called anywhere in this package.

Search comes in two flavours on purpose. ``search`` goes through
``multi_record_search`` -- Sibyl's retrieve-then-verify path with the abstention
gate that collapses injected / unsupported queries to nothing. ``unsafe_search``
goes through plain ``search()`` and skips that gate. Both exist so the
difference is a name in a diff rather than a footnote in a design doc.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Iterator

from sibyl_memory_client import DEFAULT_TENANT, MemoryClient
from sibyl_memory_client.exceptions import NotFoundError
from sibyl_memory_client.multi_record import multi_record_search
from sibyl_memory_client.storage import loads, new_id
from sibyl_memory_client.verdicts import Verdict as SibylVerdict
from sibyl_memory_client.verdicts import explain as sibyl_explain

from .envelope import Envelope
from .verdicts import Verdict, VerdictCode, refuse

#: Key under ``journal_events.extra`` that marks an event as ours. Sibyl's
#: journal is shared with anything else writing to this database, so our reader
#: keys off a namespace instead of guessing from shape.
JOURNAL_KEY = "admissible"

#: Bumped when the journal record shape changes incompatibly. Readers that meet
#: a version they do not know skip the record rather than misread it.
JOURNAL_VERSION = 1

#: Sibyl clamps every limit to MAX_LIMIT. Naming it here keeps "everything"
#: honest: this is a bounded read, not an unbounded one.
_ALL = 10_000


@dataclass(frozen=True, slots=True)
class MalformedMemory:
    """A stored row that is not a provenance envelope.

    The sentinel :meth:`AdmissibleStore.recall` returns instead of raising. It
    carries enough to explain the refusal (which row, why) and deliberately
    keeps the offending body so a human can look, but it is *not* an
    ``Envelope``: nothing downstream can mistake it for a usable claim, because
    it has no ``.claim`` and no ``.tier``.
    """

    category: str
    name: str
    reason: str
    body: Any

    @property
    def verdict(self) -> Verdict:
        """The refusal, in the same currency the rest of the gate speaks."""
        return refuse(
            VerdictCode.MALFORMED,
            "body",
            category=self.category,
            name=self.name,
            reason=self.reason,
        )


@dataclass(frozen=True, slots=True)
class SearchOutcome:
    """Hits plus the reason there are that many of them.

    Sibyl's own search contract says an empty result must name its cause. We
    keep that promise rather than flattening it to a list, and we add one bit
    Sibyl cannot know: whether the abstention gate was armed for this call.
    """

    query: str
    hits: list[dict[str, Any]]
    #: Sibyl's verdict object, passed through untouched. ``None`` only if a
    #: future Sibyl stops stamping one.
    sibyl_verdict: SibylVerdict | None
    #: True when the call went through ``multi_record_search``'s verify stage.
    gated: bool

    @property
    def code(self) -> str:
        """Sibyl's verdict code as a plain string: ``ok``, ``no_match``, ...."""
        return self.sibyl_verdict.code.value if self.sibyl_verdict else "unknown"

    @property
    def explain(self) -> str:
        if self.sibyl_verdict is None:  # pragma: no cover - defensive
            return "The search backend returned no verdict."
        return sibyl_explain(self.sibyl_verdict)

    def __len__(self) -> int:
        return len(self.hits)

    def __iter__(self) -> Iterator[dict[str, Any]]:
        return iter(self.hits)

    def __getitem__(self, index: int) -> dict[str, Any]:
        return self.hits[index]

    def __bool__(self) -> bool:
        return bool(self.hits)


class AdmissibleStore:
    """Provenance-aware access to one Sibyl Memory database."""

    def __init__(self, client: MemoryClient) -> None:
        self._client = client

    @classmethod
    def open(
        cls,
        path: str | Path = "~/.sibyl-memory/memory.db",
        *,
        tenant_id: str = DEFAULT_TENANT,
        tier: str = "free",
    ) -> "AdmissibleStore":
        """Open (or create) a store at ``path``.

        Deliberately the same defaults as ``MemoryClient.local``: an agent that
        already has a Sibyl store gets its history for free, and a second
        process opening the same file sees everything the first one wrote. That
        is the cold-start property the whole design rests on.
        """
        return cls(MemoryClient.local(str(path), tenant_id=tenant_id, tier=tier))

    # ------------------------------------------------------------------
    # Handles
    # ------------------------------------------------------------------
    @property
    def client(self) -> MemoryClient:
        """The underlying Sibyl client. Public because we extend, not wrap-and-hide."""
        return self._client

    @property
    def tenant_id(self) -> str:
        return self._client.get_tenant()

    @property
    def db_path(self) -> Path:
        return self._client.storage.db_path

    def close(self) -> None:
        self._client.storage.close()

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------
    def remember(
        self,
        category: str,
        name: str,
        envelope: Envelope,
        *,
        status: str | None = None,
    ) -> dict[str, Any]:
        """Store an envelope and journal the fact that we did.

        Returns the Sibyl entity row, plus ``journal_event_id`` so a caller can
        cite the audit entry for this exact write without re-reading the journal.
        """
        row = self._client.set_entity(category, name, envelope.to_body(), status=status)
        event_id = self._journal(
            "remember",
            envelope=envelope,
            category=category,
            name=name,
            entity_id=row.get("id"),
        )
        return {**row, "journal_event_id": event_id}

    def supersede(
        self,
        category: str,
        name: str,
        new_envelope: Envelope,
        *,
        status: str | None = None,
    ) -> dict[str, Any]:
        """Replace a memory without destroying the one it replaces.

        Order matters and is the reason this is not two lines of caller code:
        ``set_entity`` overwrites in place, so the old body has to reach the
        archive *before* the new one lands. ``archive_entity`` then deletes the
        entity row, and ``entity_relations`` cascades off it -- so the edges are
        captured first and re-pointed at the new row afterwards. Superseding a
        claim must not silently erase who vouched for it.

        The new envelope's ``supersedes`` is forced to the old digest. A
        supersession that does not name what it supersedes is not one.
        """
        old = self.recall(category, name)
        if old is None:
            raise NotFoundError(
                f"cannot supersede {category}/{name}: no such entity for tenant {self.tenant_id}"
            )

        old_digest = old.digest if isinstance(old, Envelope) else None
        reason = (
            f"superseded by {new_envelope.digest}"
            if old_digest
            else f"superseded by {new_envelope.digest} (previous body was not a valid envelope)"
        )

        entity_id = self._client.get_entity(category, name)["id"]
        edges = self._capture_relations(entity_id)

        linked = Envelope(
            claim=new_envelope.claim,
            provenance=replace(new_envelope.provenance, supersedes=old_digest),
        )

        self._client.archive_entity(category, name, reason=reason)
        row = self._client.set_entity(category, name, linked.to_body(), status=status)
        self._rehome_relations(edges, entity_id, row["id"])

        event_id = self._journal(
            "supersede",
            envelope=linked,
            category=category,
            name=name,
            entity_id=row["id"],
            superseded_digest=old_digest,
        )
        return {
            **row,
            "journal_event_id": event_id,
            "superseded_digest": old_digest,
            "digest": linked.digest,
        }

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------
    def recall(self, category: str, name: str) -> Envelope | MalformedMemory | None:
        """Read one memory.

        Three answers, no exceptions: the envelope, a :class:`MalformedMemory`
        when the stored body is not one (unparseable, or a claim edited under a
        sealed digest), or ``None`` when there is nothing there. A missing
        memory and a poisoned memory are different facts and the gate treats
        them differently, so they get different return values.
        """
        try:
            row = self._client.get_entity(category, name)
        except NotFoundError:
            return None
        return self.parse_body(category, name, row["body"])

    def recall_many(
        self,
        category: str | None = None,
        *,
        limit: int = 100,
        status: str | None = None,
        include_malformed: bool = False,
    ) -> list[Envelope] | list[Envelope | MalformedMemory]:
        """Read a page of memories, newest-updated first.

        Malformed rows are dropped by default: a bulk read is usually feeding a
        ranking or a summary, and a sentinel in that list would have to be
        special-cased by every caller. Pass ``include_malformed=True`` when the
        caller is an auditor rather than a consumer.
        """
        out: list[Any] = []
        for row in self._client.list_entities(category, status=status, limit=limit):
            parsed = self.parse_body(row["category"], row["name"], row["body"])
            if isinstance(parsed, MalformedMemory) and not include_malformed:
                continue
            out.append(parsed)
        return out

    def archived(self, category: str, name: str) -> list[dict[str, Any]]:
        """Every archived version of one name, oldest first.

        Reads ``archived_entities`` directly: Sibyl writes that table in
        ``archive_entity`` but ships no reader for it, and without a reader
        "non-destructive" is an unverifiable claim.
        """
        with self._client.storage.connection() as conn:
            rows = conn.execute(
                "SELECT id, original_entity_id, category, name, body, archived_at, archive_reason "
                "FROM archived_entities "
                "WHERE tenant_id = ? AND category = ? AND name = ? "
                "ORDER BY archived_at ASC, rowid ASC",
                (self.tenant_id, category, name),
            ).fetchall()
        return [
            {
                "id": r["id"],
                "original_entity_id": r["original_entity_id"],
                "category": r["category"],
                "name": r["name"],
                "body": loads(r["body"]),
                "archived_at": r["archived_at"],
                "archive_reason": r["archive_reason"],
            }
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------
    def search(self, query: str, *, limit: int = 10) -> SearchOutcome:
        """Search through Sibyl's gated retrieve-then-verify path.

        This is the default because the abstention gate is a security control,
        not a relevance tweak: a query carrying a token with zero corpus support
        returns nothing and says ``abstained_on``, which is precisely what
        collapses a prompt-injected retrieval into a refusal. The verdict rides
        out with the hits so a caller can tell "no such memory" from "the gate
        stopped this".
        """
        results = multi_record_search(self._client, query, limit=limit)
        return SearchOutcome(
            query=query,
            hits=list(results),
            sibyl_verdict=getattr(results, "verdict", None),
            gated=True,
        )

    def unsafe_search(
        self,
        query: str,
        *,
        limit: int = 20,
        prefix: bool = False,
        tiers: tuple[str, ...] | None = None,
    ) -> SearchOutcome:
        """Raw FTS5 search. **This bypasses Sibyl's injection gate.**

        ``MemoryClient.search`` is a policy-free primitive: no abstention, no
        coverage floor, no anchor gate. Whatever lexically matches comes back,
        including a record planted specifically to be retrieved. Use it for
        operator tooling and diagnostics -- never on the path where retrieved
        text reaches a model or authorises a payment. The name is long and ugly
        so that a code review notices it.
        """
        results = self._client.search(query, limit=limit, prefix=prefix, tiers=tiers)
        return SearchOutcome(
            query=query,
            hits=list(results),
            sibyl_verdict=getattr(results, "verdict", None),
            gated=False,
        )

    # ------------------------------------------------------------------
    # Journal
    # ------------------------------------------------------------------
    def journal(
        self,
        *,
        op: str | None = None,
        category: str | None = None,
        name: str | None = None,
        counterparty: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = _ALL,
    ) -> list[dict[str, Any]]:
        """Our records out of Sibyl's journal, newest first.

        Each returned dict is the ``extra["admissible"]`` payload with the
        event's ``event_id`` and ``ts`` merged in. Filtering happens in Python:
        the journal is a JSON blob column, and a hackathon-scale store is a few
        thousand rows. If that stops being true, the filter belongs in SQL over
        ``json_extract``, not in a second index.
        """
        out: list[dict[str, Any]] = []
        for event in self._client.read_events(limit=limit, since=since, until=until):
            extra = event.get("extra")
            if not isinstance(extra, dict):
                continue
            rec = extra.get(JOURNAL_KEY)
            if not isinstance(rec, dict) or rec.get("v") != JOURNAL_VERSION:
                continue
            if op is not None and rec.get("op") != op:
                continue
            if category is not None and rec.get("category") != category:
                continue
            if name is not None and rec.get("name") != name:
                continue
            if counterparty is not None and rec.get("counterparty") != counterparty:
                continue
            out.append({**rec, "event_id": event["id"], "ts": event["ts"]})
        return out

    def journal_write(self, op: str, **fields: Any) -> str:
        """Append one namespaced record to Sibyl's journal.

        Public so ``flagged`` and ``relations`` can journal their own writes
        through the same door instead of inventing a second audit trail.
        """
        return self._journal(op, **fields)

    def parse_body(
        self, category: str, name: str, body: Any
    ) -> Envelope | MalformedMemory:
        """Turn a stored body into an envelope or the malformed sentinel.

        Public because ``timeline`` reads bodies out of ``archived_entities``,
        which never went through ``recall``, and both paths must fail the same
        way. One parser, one refusal.
        """
        try:
            return Envelope.from_body(body)
        except (ValueError, KeyError, TypeError) as exc:
            return MalformedMemory(
                category=category, name=name, reason=str(exc), body=body
            )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _journal(
        self,
        op: str,
        *,
        envelope: Envelope | None = None,
        **fields: Any,
    ) -> str:
        """Build and append one journal record.

        ``acted`` carries what happened, ``evaluated`` carries the provenance we
        judged it on, and ``extra`` carries the machine-readable record. The
        first two are there so Sibyl's own FTS5 index over the journal finds
        these events by digest or by actor without us adding an index.
        """
        record: dict[str, Any] = {"v": JOURNAL_VERSION, "op": op}
        if envelope is not None:
            prov = envelope.provenance
            record.update(
                digest=envelope.digest,
                tier=prov.tier.value,
                source=prov.source,
                actor_address=prov.actor_address,
                actor_handle=prov.actor_handle,
                observed_at=prov.observed_at,
                supersedes=prov.supersedes,
            )
            counterparty = envelope.claim.get("counterparty")
            if isinstance(counterparty, str):
                record["counterparty"] = counterparty
        record.update({k: v for k, v in fields.items() if v is not None})

        acted = [f"{op} {record.get('category', '')}/{record.get('name', '')}".strip()]
        if record.get("digest"):
            acted.append(record["digest"])
        evaluated = {
            k: record[k]
            for k in ("tier", "source", "actor_address", "actor_handle", "observed_at")
            if record.get(k)
        }
        return self._client.write_event(
            acted=acted,
            evaluated=evaluated or None,
            extra={JOURNAL_KEY: record},
        )

    # -- relation rescue across a supersede -----------------------------
    #
    # These two helpers talk to ``entity_relations`` with raw SQL rather than
    # going through ``relations.Relations``, only to keep the import acyclic
    # (relations builds on the store). The table is the seam this package
    # exists to open; see ``relations.py`` for the documented API.
    def _capture_relations(self, entity_id: str) -> list[dict[str, Any]]:
        with self._client.storage.connection() as conn:
            rows = conn.execute(
                "SELECT id, from_id, to_id, relation_type, metadata, created_at "
                "FROM entity_relations WHERE tenant_id = ? AND (from_id = ? OR to_id = ?)",
                (self.tenant_id, entity_id, entity_id),
            ).fetchall()
        return [dict(r) for r in rows]

    def _rehome_relations(
        self, edges: list[dict[str, Any]], old_id: str, new_id_: str
    ) -> None:
        if not edges:
            return
        with self._client.storage.transaction() as conn:
            for edge in edges:
                conn.execute(
                    "INSERT INTO entity_relations "
                    "(id, tenant_id, from_id, to_id, relation_type, metadata, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        new_id(),
                        self.tenant_id,
                        new_id_ if edge["from_id"] == old_id else edge["from_id"],
                        new_id_ if edge["to_id"] == old_id else edge["to_id"],
                        edge["relation_type"],
                        edge["metadata"],
                        # Keep the original timestamp: re-homing an edge is
                        # bookkeeping, not a new assertion about when it was made.
                        edge["created_at"],
                    ),
                )
