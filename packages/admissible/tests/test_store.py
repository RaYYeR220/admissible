"""AdmissibleStore: journalled writes, tolerant reads, non-destructive invalidation."""

from __future__ import annotations

import pytest
from sibyl_memory_client.exceptions import NotFoundError

from admissible.envelope import Envelope, Evidence, Tier
from admissible.store import (
    JOURNAL_KEY,
    AdmissibleStore,
    MalformedMemory,
)
from admissible.verdicts import VerdictCode

from admissible_fixtures import envelope


def test_remember_roundtrips_the_envelope(store):
    env = envelope({"counterparty": "acme.eth", "amount": "10", "outcome": "settled"})
    store.remember("interaction", "job-1", env)

    got = store.recall("interaction", "job-1")
    assert isinstance(got, Envelope)
    assert got.digest == env.digest
    assert got.tier is Tier.WITNESSED
    assert got.claim["counterparty"] == "acme.eth"


def test_remember_is_journalled_with_digest_tier_source_and_actor(store):
    env = envelope(
        {"counterparty": "acme.eth"},
        tier=Tier.ATTESTED,
        source="x402:settlement",
        actor_address="0xAbC0000000000000000000000000000000000001",
        actor_handle="acme",
    )
    store.remember("interaction", "job-1", env)

    records = store.journal(op="remember")
    assert len(records) == 1
    rec = records[0]
    assert rec["digest"] == env.digest
    assert rec["tier"] == "ATTESTED"
    assert rec["source"] == "x402:settlement"
    assert rec["actor_address"] == "0xAbC0000000000000000000000000000000000001"
    assert rec["actor_handle"] == "acme"
    assert rec["category"] == "interaction"
    assert rec["name"] == "job-1"
    assert rec["event_id"]


def test_journal_event_is_visible_through_sibyls_own_reader(store):
    """We write through write_event, so Sibyl's read_events must see it too.

    If this ever fails we have quietly forked the journal.
    """
    store.remember("interaction", "job-1", envelope({"counterparty": "acme.eth"}))
    raw = store.client.read_events(limit=10)
    assert len(raw) == 1
    assert JOURNAL_KEY in raw[0]["extra"]


def test_recall_missing_returns_none(store):
    assert store.recall("interaction", "nope") is None


def test_recall_of_a_malformed_body_does_not_raise(store):
    """A poisoned row is a refusal, not a crash.

    Written straight through the Sibyl client so the body is real stored data,
    not a mock: ``set_entity`` happily accepts any JSON object.
    """
    store.client.set_entity("interaction", "junk", {"totally": "not an envelope"})

    got = store.recall("interaction", "junk")
    assert isinstance(got, MalformedMemory)
    assert got.category == "interaction"
    assert got.name == "junk"
    assert got.reason
    assert got.verdict.code is VerdictCode.MALFORMED
    assert not got.verdict.admits


def test_recall_detects_a_tampered_claim(store):
    """Editing the claim under a sealed digest must surface as MALFORMED."""
    env = envelope({"counterparty": "acme.eth", "amount": "10"})
    store.remember("interaction", "job-1", env)

    body = store.client.get_entity("interaction", "job-1")["body"]
    body["claim"]["amount"] = "10000"
    store.client.set_entity("interaction", "job-1", body)

    got = store.recall("interaction", "job-1")
    assert isinstance(got, MalformedMemory)
    assert "digest mismatch" in got.reason


def test_recall_many_skips_malformed_by_default(store):
    store.remember("interaction", "job-1", envelope({"counterparty": "a"}))
    store.client.set_entity("interaction", "junk", {"not": "an envelope"})

    good = store.recall_many("interaction")
    assert [e.claim["counterparty"] for e in good] == ["a"]

    everything = store.recall_many("interaction", include_malformed=True)
    assert len(everything) == 2
    assert sum(isinstance(x, MalformedMemory) for x in everything) == 1


def test_cold_start_a_fresh_store_on_the_same_file_reads_the_same_facts(db_path):
    """The hackathon's cold-start requirement, at the store level.

    Nothing survives in process memory between these two objects: the second
    store opens the same SQLite file from scratch.
    """
    writer = AdmissibleStore.open(db_path)
    env = envelope({"counterparty": "acme.eth", "outcome": "settled"}, tier=Tier.ATTESTED)
    writer.remember("interaction", "job-1", env)
    writer.close()

    reader = AdmissibleStore.open(db_path)
    try:
        got = reader.recall("interaction", "job-1")
        assert isinstance(got, Envelope)
        assert got.digest == env.digest
        assert got.tier is Tier.ATTESTED
        assert len(reader.journal(op="remember")) == 1
    finally:
        reader.close()


def test_supersede_archives_the_old_record_and_links_the_chain(store):
    old = envelope({"counterparty": "acme.eth", "rate": "5"}, observed_at="2026-01-01T00:00:00.000Z")
    store.remember("terms", "acme-rate", old)

    new = envelope({"counterparty": "acme.eth", "rate": "7"}, observed_at="2026-02-01T00:00:00.000Z")
    result = store.supersede("terms", "acme-rate", new)

    current = store.recall("terms", "acme-rate")
    assert isinstance(current, Envelope)
    assert current.claim["rate"] == "7"
    assert current.provenance.supersedes == old.digest
    assert result["superseded_digest"] == old.digest

    # The old record is archived, not deleted, and still carries its body.
    archived = store.archived("terms", "acme-rate")
    assert len(archived) == 1
    assert archived[0]["body"]["claim"]["rate"] == "5"
    # The reason names what replaced it, so the archive row points forward and
    # the new record's `supersedes` points back. The chain reads both ways.
    assert archived[0]["archive_reason"] == f"superseded by {new.digest}"


def test_supersede_never_hard_deletes(store):
    store.remember("terms", "acme-rate", envelope({"rate": "5"}))
    store.supersede("terms", "acme-rate", envelope({"rate": "7"}))

    with store.client.storage.connection() as conn:
        n = conn.execute("SELECT COUNT(*) AS n FROM archived_entities").fetchone()["n"]
    assert n == 1


def test_supersede_of_an_unknown_entity_refuses(store):
    with pytest.raises(NotFoundError):
        store.supersede("terms", "ghost", envelope({"rate": "7"}))


def test_search_uses_the_gated_path_and_exposes_sibyls_verdict(store):
    store.remember(
        "interaction",
        "job-1",
        envelope({"counterparty": "acme.eth", "note": "settled invoice for hosting"}),
    )
    out = store.search("hosting invoice")
    assert out.gated is True
    assert out.code in {"ok", "no_match", "gated", "abstained_on", "empty_store"}
    assert out.sibyl_verdict is not None
    assert out.explain


def test_search_abstains_on_a_word_the_store_has_never_seen(store):
    """The gate is the whole point: an unsupported token yields nothing, with a cause."""
    store.remember("interaction", "job-1", envelope({"counterparty": "acme.eth"}))
    out = store.search("zzzqqx nonexistent token")
    assert len(out) == 0
    assert out.code != "ok"


def test_unsafe_search_is_ungated_and_says_so(store):
    store.remember("interaction", "job-1", envelope({"counterparty": "acme.eth"}))
    out = store.unsafe_search("acme")
    assert out.gated is False
    assert len(out) >= 1
    assert "bypass" in AdmissibleStore.unsafe_search.__doc__.lower()


def test_evidence_survives_the_roundtrip(store):
    ev = Evidence(chain_id=8453, tx_hash="0x" + "11" * 32, kind="x402:settlement")
    env = envelope({"counterparty": "acme.eth"}, tier=Tier.ATTESTED, evidence=ev)
    store.remember("interaction", "job-1", env)

    got = store.recall("interaction", "job-1")
    assert got.provenance.evidence.tx_hash == ev.tx_hash
    assert got.provenance.evidence.chain_id == 8453
