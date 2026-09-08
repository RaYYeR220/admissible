"""The relations graph: the second table Sibyl declares and never exposes."""

from __future__ import annotations

import pytest

from admissible.relations import SOURCED, VOUCHED_FOR, EntityRef, Relations
from admissible.store import AdmissibleStore

from admissible_fixtures import envelope

ALICE = "0xAAaA000000000000000000000000000000000001"
BOB = "0xBbBb000000000000000000000000000000000002"


def _actor(store, address: str) -> EntityRef:
    """Actors are entities like anything else; the node id is the address, lowered."""
    ref = EntityRef("actor", address.lower())
    store.remember(ref.category, ref.name, envelope({"address": address}))
    return ref


def test_relate_writes_a_row_in_sibyls_entity_relations_table(store):
    a = _actor(store, ALICE)
    b = _actor(store, BOB)
    rel = Relations(store)
    rel_id = rel.relate(a, b, VOUCHED_FOR, metadata={"since": "2026-01-01"})

    with store.client.storage.connection() as conn:
        row = conn.execute(
            "SELECT id, relation_type FROM entity_relations WHERE id = ?", (rel_id,)
        ).fetchone()
    assert row is not None
    assert row["relation_type"] == VOUCHED_FOR


def test_relate_refuses_an_unknown_endpoint(store):
    a = _actor(store, ALICE)
    with pytest.raises(LookupError):
        Relations(store).relate(a, ("actor", "ghost"), VOUCHED_FOR)


def test_neighbors_respects_direction(store):
    a = _actor(store, ALICE)
    b = _actor(store, BOB)
    rel = Relations(store)
    rel.relate(a, b, VOUCHED_FOR)

    assert rel.neighbors(a, direction="out") == [b]
    assert rel.neighbors(a, direction="in") == []
    assert rel.neighbors(b, direction="in") == [a]
    assert rel.neighbors(b, direction="both") == [a]


def test_neighbors_filters_by_relation_type(store):
    a = _actor(store, ALICE)
    b = _actor(store, BOB)
    claim = EntityRef("interaction", "job-1")
    store.remember(claim.category, claim.name, envelope({"counterparty": BOB}))

    rel = Relations(store)
    rel.relate(a, b, VOUCHED_FOR)
    rel.relate(a, claim, SOURCED)

    assert rel.neighbors(a, VOUCHED_FOR) == [b]
    assert rel.neighbors(a, SOURCED) == [claim]
    assert len(rel.neighbors(a)) == 2


def test_vouchers_of_reads_the_incoming_vouch_edges(store):
    a = _actor(store, ALICE)
    b = _actor(store, BOB)
    rel = Relations(store)
    rel.relate(a, b, VOUCHED_FOR)
    assert rel.vouchers_of(b) == [a]
    assert rel.vouchers_of(a) == []


def test_contaminated_by_finds_a_two_hop_laundering_ring(store):
    """Alice vouched for Bob. Bob turns out to be flagged.

    Everything Alice sourced is now suspect, and so is Alice. Two hops from the
    flagged address: one backwards along ``vouched_for``, one forwards along
    ``sourced``.
    """
    alice = _actor(store, ALICE)
    bob = _actor(store, BOB)
    claim = EntityRef("interaction", "job-1")
    store.remember(claim.category, claim.name, envelope({"counterparty": "acme.eth"}))
    unrelated = EntityRef("interaction", "job-2")
    store.remember(unrelated.category, unrelated.name, envelope({"counterparty": "other.eth"}))

    rel = Relations(store)
    rel.relate(alice, bob, VOUCHED_FOR)
    rel.relate(alice, claim, SOURCED)

    hit = rel.contaminated_by(BOB)
    assert alice in hit
    assert claim in hit
    assert unrelated not in hit
    assert bob not in hit  # the origin is not its own contamination


def test_contaminated_by_respects_max_depth(store):
    alice = _actor(store, ALICE)
    bob = _actor(store, BOB)
    claim = EntityRef("interaction", "job-1")
    store.remember(claim.category, claim.name, envelope({"counterparty": "acme.eth"}))

    rel = Relations(store)
    rel.relate(alice, bob, VOUCHED_FOR)
    rel.relate(alice, claim, SOURCED)

    assert rel.contaminated_by(BOB, max_depth=1) == [alice]


def test_contaminated_by_is_case_insensitive_on_the_address(store):
    alice = _actor(store, ALICE)
    _actor(store, BOB)
    Relations(store).relate(alice, ("actor", BOB.lower()), VOUCHED_FOR)
    assert Relations(store).contaminated_by(BOB.upper()) == [alice]


def test_contaminated_by_refuses_an_actor_it_has_never_heard_of(store):
    """An empty list would read as 'clean'. An unknown actor is not clean."""
    with pytest.raises(LookupError):
        Relations(store).contaminated_by("0x" + "de" * 20)


def test_relations_survive_a_supersede(store):
    """Superseding replaces the entity row, and ON DELETE CASCADE would take the
    edges with it. The graph is evidence; it must outlive the version."""
    alice = _actor(store, ALICE)
    claim = EntityRef("interaction", "job-1")
    store.remember(claim.category, claim.name, envelope({"rate": "5"}))
    Relations(store).relate(alice, claim, SOURCED)

    store.supersede(claim.category, claim.name, envelope({"rate": "7"}))

    assert Relations(store).neighbors(alice, SOURCED) == [claim]


def test_relations_survive_a_cold_start(db_path):
    writer = AdmissibleStore.open(db_path)
    alice = _actor(writer, ALICE)
    bob = _actor(writer, BOB)
    Relations(writer).relate(alice, bob, VOUCHED_FOR)
    writer.close()

    reader = AdmissibleStore.open(db_path)
    try:
        assert Relations(reader).vouchers_of(bob) == [alice]
    finally:
        reader.close()
