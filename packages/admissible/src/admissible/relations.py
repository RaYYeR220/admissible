"""The relations graph.

The second table Sibyl declares and never exposes:

    CREATE TABLE IF NOT EXISTS entity_relations (
      id, tenant_id, from_id, to_id, relation_type, metadata, created_at)

with two indexes ready for traversal in both directions -- and zero references
in ``client.py`` or ``storage.py``. The rows can only get there if something
writes them, and nothing in the SDK does.

Why we want it: provenance is not a property of one record. "Who vouched for
this counterparty" and "which claims did that actor source" are *edges*, and
without them a fraud signal stops at the record it landed on. With them, one
flagged address propagates:

    A --vouched_for--> B, and B is flagged
    => A is contaminated
    => and every claim A --sourced--> is contaminated too

That is :meth:`Relations.contaminated_by`, and it is the difference between
blocking one address and unwinding a ring.

Edges point at ``entities.id``, which is a UUID the caller never sees, so the
public surface is ``(category, name)`` pairs -- :class:`EntityRef` -- resolved
on the way in. That also means a ref that does not exist is an error rather than
a dangling edge: ``entity_relations`` has a foreign key, and we would rather
fail at ``relate`` than discover it at traversal time.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Any, Iterable, NamedTuple, Sequence

from sibyl_memory_client.storage import dumps, loads, new_id

from .store import AdmissibleStore

#: A vouches for B: A put its own reputation behind B.
VOUCHED_FOR = "vouched_for"
#: A sourced claim C: C exists because A asserted it.
SOURCED = "sourced"

#: Accepted traversal directions. Edges are directed and the direction carries
#: meaning, so "which way" is never inferred from the relation type.
_DIRECTIONS = ("out", "in", "both")


class EntityRef(NamedTuple):
    """A stable, human-readable handle on an entity.

    ``entities.id`` is a UUID minted at insert time and reminted whenever a row
    is archived and rewritten, so it is the wrong thing to hold. The pair the
    UNIQUE constraint is built on is the right thing.
    """

    category: str
    name: str


Ref = EntityRef | tuple[str, str]


@dataclass(frozen=True, slots=True)
class Relation:
    """One edge, with both endpoints resolved back to refs."""

    id: str
    from_ref: EntityRef
    to_ref: EntityRef
    relation_type: str
    metadata: dict[str, Any] | None
    created_at: str


def _as_ref(ref: Ref) -> EntityRef:
    if isinstance(ref, EntityRef):
        return ref
    category, name = ref
    return EntityRef(category, name)


class Relations:
    """Typed edges between entities, plus the traversals that make them pay."""

    def __init__(self, store: AdmissibleStore) -> None:
        self._store = store

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------
    def relate(
        self,
        from_ref: Ref,
        to_ref: Ref,
        relation_type: str,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Add an edge. Returns the new relation id.

        Raises ``LookupError`` if either endpoint is unknown. The foreign keys
        would raise anyway, but a message naming the missing ref is worth more
        than ``FOREIGN KEY constraint failed``.
        """
        src, dst = _as_ref(from_ref), _as_ref(to_ref)
        from_id = self._resolve(src)
        to_id = self._resolve(dst)
        rel_id = new_id()

        with self._store.client.storage.transaction() as conn:
            conn.execute(
                "INSERT INTO entity_relations "
                "(id, tenant_id, from_id, to_id, relation_type, metadata) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    rel_id,
                    self._store.tenant_id,
                    from_id,
                    to_id,
                    relation_type,
                    dumps(metadata) if metadata is not None else None,
                ),
            )

        self._store.journal_write(
            "relate",
            relation_id=rel_id,
            relation_type=relation_type,
            from_category=src.category,
            from_name=src.name,
            to_category=dst.category,
            to_name=dst.name,
        )
        return rel_id

    def unrelate(self, relation_id: str) -> bool:
        """Remove one edge. Journalled, because retracting a vouch is a decision."""
        with self._store.client.storage.transaction() as conn:
            cur = conn.execute(
                "DELETE FROM entity_relations WHERE id = ? AND tenant_id = ?",
                (relation_id, self._store.tenant_id),
            )
            removed = cur.rowcount > 0
        if removed:
            self._store.journal_write("unrelate", relation_id=relation_id)
        return removed

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------
    def edges(
        self,
        ref: Ref,
        *,
        relation_type: str | None = None,
        direction: str = "out",
    ) -> list[Relation]:
        """Edges touching ``ref``, with type and metadata intact."""
        if direction not in _DIRECTIONS:
            raise ValueError(f"direction must be one of {_DIRECTIONS}, got {direction!r}")
        node = self._resolve(_as_ref(ref))
        return self._edges_by_id(node, relation_type=relation_type, direction=direction)

    def neighbors(
        self,
        ref: Ref,
        relation_type: str | None = None,
        direction: str = "out",
    ) -> list[EntityRef]:
        """The refs on the other end of :meth:`edges`, de-duplicated.

        Ordering is oldest edge first, which is the order the assertions were
        made -- stable across runs, and the order a reviewer reads them in.
        """
        me = _as_ref(ref)
        out: list[EntityRef] = []
        for edge in self.edges(me, relation_type=relation_type, direction=direction):
            other = edge.to_ref if edge.from_ref == me else edge.from_ref
            if other not in out:
                out.append(other)
        return out

    def vouchers_of(self, ref: Ref) -> list[EntityRef]:
        """Who put their name behind this entity."""
        return self.neighbors(ref, VOUCHED_FOR, direction="in")

    # ------------------------------------------------------------------
    # The payoff
    # ------------------------------------------------------------------
    def contaminated_by(
        self,
        flagged_address: str,
        *,
        actor_category: str = "actor",
        vouch_types: Sequence[str] = (VOUCHED_FOR,),
        source_types: Sequence[str] = (SOURCED,),
        max_depth: int | None = None,
    ) -> list[EntityRef]:
        """Everything downstream of a flagged actor. Laundering-ring detection.

        Contamination is directional, and the two directions are not the same:

        * along a **vouch**, it flows *backwards*. If B is dirty, whoever vouched
          for B either did not check or did not care, and both are disqualifying.
        * along a **sourcing**, it flows *forwards*. A claim is only as clean as
          the actor who asserted it.

        Composed, those two rules walk a ring: the flagged address reaches its
        vouchers, and the vouchers reach everything they ever sourced. Result is
        breadth-first from the flagged actor, so items nearer the flag come
        first, and it excludes the origin -- the caller already knows about that
        one, and a set that contains its own seed is awkward to act on.

        The actor node is looked up at ``(actor_category, <normalised address>)``,
        the same normalisation :mod:`admissible.flagged` uses, so a flag and a
        graph node agree on what the address is. An address with no node raises
        ``LookupError``: returning an empty list would read as "clean", and
        "we have never heard of them" is not clean.
        """
        seed = self.actor_node(flagged_address, actor_category=actor_category)
        seed_id = self._resolve(seed)

        vouch = tuple(vouch_types)
        source = tuple(source_types)

        seen: set[str] = {seed_id}
        found: list[EntityRef] = []
        frontier: deque[tuple[str, int]] = deque([(seed_id, 0)])

        while frontier:
            node_id, depth = frontier.popleft()
            if max_depth is not None and depth >= max_depth:
                continue
            for next_id, ref in self._contaminated_from(node_id, vouch, source):
                if next_id in seen:
                    continue
                seen.add(next_id)
                found.append(ref)
                frontier.append((next_id, depth + 1))
        return found

    def actor_node(self, address: str, *, actor_category: str = "actor") -> EntityRef:
        """Resolve an address to its graph node, or raise ``LookupError``.

        Tries the normalised form first and the given form second, so a store
        that recorded checksummed addresses still resolves.
        """
        from .flagged import _norm_actor  # local: flagged builds on store, not on us

        candidates = [c for c in (_norm_actor(address), address) if c]
        for candidate in candidates:
            ref = EntityRef(actor_category, candidate)
            if self._try_resolve(ref) is not None:
                return ref
        raise LookupError(
            f"no {actor_category!r} entity for {address!r}: "
            "the graph has never heard of this actor, which is not the same as it being clean"
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _contaminated_from(
        self, node_id: str, vouch_types: tuple[str, ...], source_types: tuple[str, ...]
    ) -> list[tuple[str, EntityRef]]:
        """One hop of the contamination rules from a single node."""
        out: list[tuple[str, EntityRef]] = []
        for rel_type in vouch_types:
            for edge_id, ref in self._adjacent(node_id, rel_type, "in"):
                out.append((edge_id, ref))
        for rel_type in source_types:
            for edge_id, ref in self._adjacent(node_id, rel_type, "out"):
                out.append((edge_id, ref))
        return out

    def _adjacent(
        self, node_id: str, relation_type: str, direction: str
    ) -> list[tuple[str, EntityRef]]:
        column, other = ("to_id", "from_id") if direction == "in" else ("from_id", "to_id")
        with self._store.client.storage.connection() as conn:
            rows = conn.execute(
                f"SELECT e.id AS other_id, e.category, e.name "
                f"FROM entity_relations r JOIN entities e ON e.id = r.{other} "
                f"WHERE r.tenant_id = ? AND r.{column} = ? AND r.relation_type = ? "
                "ORDER BY r.created_at ASC, r.rowid ASC",
                (self._store.tenant_id, node_id, relation_type),
            ).fetchall()
        return [(r["other_id"], EntityRef(r["category"], r["name"])) for r in rows]

    def _edges_by_id(
        self, node_id: str, *, relation_type: str | None, direction: str
    ) -> list[Relation]:
        if direction == "out":
            where = "r.from_id = ?"
            params: list[Any] = [node_id]
        elif direction == "in":
            where = "r.to_id = ?"
            params = [node_id]
        else:
            where = "(r.from_id = ? OR r.to_id = ?)"
            params = [node_id, node_id]
        if relation_type is not None:
            where += " AND r.relation_type = ?"
            params.append(relation_type)

        with self._store.client.storage.connection() as conn:
            rows = conn.execute(
                "SELECT r.id, r.relation_type, r.metadata, r.created_at, "
                "       f.category AS from_category, f.name AS from_name, "
                "       t.category AS to_category, t.name AS to_name "
                "FROM entity_relations r "
                "JOIN entities f ON f.id = r.from_id "
                "JOIN entities t ON t.id = r.to_id "
                f"WHERE r.tenant_id = ? AND {where} "
                "ORDER BY r.created_at ASC, r.rowid ASC",
                (self._store.tenant_id, *params),
            ).fetchall()
        return [
            Relation(
                id=r["id"],
                from_ref=EntityRef(r["from_category"], r["from_name"]),
                to_ref=EntityRef(r["to_category"], r["to_name"]),
                relation_type=r["relation_type"],
                metadata=loads(r["metadata"]),
                created_at=r["created_at"],
            )
            for r in rows
        ]

    def _try_resolve(self, ref: EntityRef) -> str | None:
        with self._store.client.storage.connection() as conn:
            row = conn.execute(
                "SELECT id FROM entities WHERE tenant_id = ? AND category = ? AND name = ?",
                (self._store.tenant_id, ref.category, ref.name),
            ).fetchone()
        return row["id"] if row else None

    def _resolve(self, ref: EntityRef) -> str:
        entity_id = self._try_resolve(ref)
        if entity_id is None:
            raise LookupError(f"no entity {ref.category}/{ref.name} for this tenant")
        return entity_id


def refs(pairs: Iterable[Ref]) -> list[EntityRef]:
    """Normalise a mixed iterable of tuples and refs. Convenience for callers."""
    return [_as_ref(p) for p in pairs]
