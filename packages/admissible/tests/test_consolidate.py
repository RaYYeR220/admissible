"""Consolidation: many interactions folded into one dossier, deterministically."""

from __future__ import annotations

from admissible.consolidate import consolidate, summarize
from admissible.envelope import Envelope, Evidence, Tier
from admissible.store import AdmissibleStore

from admissible_fixtures import envelope

CP = "acme.eth"


def _three_jobs(store):
    store.remember(
        "interaction",
        "job-1",
        envelope(
            {"counterparty": CP, "outcome": "settled", "amount": "100.50", "asset": "USDC"},
            tier=Tier.ATTESTED,
            source="x402:settlement",
            observed_at="2026-01-01T00:00:00.000Z",
            evidence=Evidence(chain_id=8453, tx_hash="0x" + "11" * 32, kind="x402:settlement"),
        ),
    )
    store.remember(
        "interaction",
        "job-2",
        envelope(
            {"counterparty": CP, "outcome": "settled", "amount": "49.50", "asset": "USDC"},
            tier=Tier.WITNESSED,
            observed_at="2026-02-01T00:00:00.000Z",
        ),
    )
    store.remember(
        "interaction",
        "job-3",
        envelope(
            {"counterparty": CP, "outcome": "disputed", "amount": "10", "asset": "USDC"},
            tier=Tier.HEARSAY,
            source="peer:reference",
            observed_at="2026-03-01T00:00:00.000Z",
        ),
    )
    store.remember(
        "interaction",
        "other-1",
        envelope({"counterparty": "someone.eth", "outcome": "settled", "amount": "999", "asset": "USDC"}),
    )


def test_consolidate_counts_outcomes_and_totals(store):
    _three_jobs(store)
    dossier = consolidate(store, CP)

    assert isinstance(dossier, Envelope)
    claim = dossier.claim
    assert claim["counterparty"] == CP
    assert claim["interactions"] == 3
    assert claim["outcomes"] == {"disputed": 1, "settled": 2}
    assert claim["totals"] == {"USDC": "160.00"}
    assert claim["attested_totals"] == {"USDC": "100.50"}


def test_consolidate_records_the_window_and_the_tier_histogram(store):
    _three_jobs(store)
    claim = consolidate(store, CP).claim

    assert claim["first_seen"] == "2026-01-01T00:00:00.000Z"
    assert claim["last_seen"] == "2026-03-01T00:00:00.000Z"
    assert claim["tiers"] == {"ATTESTED": 1, "HEARSAY": 1, "WITNESSED": 1}
    assert claim["sources"] == {"agent:self": 1, "peer:reference": 1, "x402:settlement": 1}


def test_consolidate_keeps_the_strongest_evidence(store):
    _three_jobs(store)
    claim = consolidate(store, CP).claim
    assert claim["strongest_evidence"]["tx_hash"] == "0x" + "11" * 32
    assert claim["strongest_evidence"]["kind"] == "x402:settlement"


def test_the_dossier_is_as_weak_as_its_weakest_input(store):
    """An aggregate mixes tiers, so it fails closed at the bottom of the range."""
    _three_jobs(store)
    assert consolidate(store, CP).tier is Tier.HEARSAY


def test_a_purely_attested_dossier_stays_attested(store):
    store.remember(
        "interaction",
        "job-1",
        envelope(
            {"counterparty": CP, "outcome": "settled", "amount": "5", "asset": "USDC"},
            tier=Tier.ATTESTED,
            source="x402:settlement",
        ),
    )
    assert consolidate(store, CP).tier is Tier.ATTESTED


def test_consolidate_is_deterministic(store):
    _three_jobs(store)
    a = consolidate(store, CP, now="2026-04-01T00:00:00.000Z")
    b = consolidate(store, CP, now="2026-04-01T00:00:00.000Z")
    assert a.digest == b.digest
    assert a.to_body() == b.to_body()


def test_consolidate_writes_the_dossier_entity_and_journals_it(store):
    _three_jobs(store)
    dossier = consolidate(store, CP)

    stored = store.recall("dossier", CP)
    assert isinstance(stored, Envelope)
    assert stored.digest == dossier.digest
    assert any(r["name"] == CP for r in store.journal(op="remember"))


def test_consolidate_can_be_asked_not_to_write(store):
    _three_jobs(store)
    consolidate(store, CP, write=False)
    assert store.recall("dossier", CP) is None


def test_consolidate_counts_journal_events_it_could_not_open(store):
    """Journal records are part of the fold even when the entity is long gone."""
    _three_jobs(store)
    claim = consolidate(store, CP).claim
    assert claim["journal_events"] == 3


def test_consolidate_of_an_unknown_counterparty_is_an_empty_hearsay_dossier(store):
    dossier = consolidate(store, "nobody.eth", write=False)
    assert dossier.claim["interactions"] == 0
    assert dossier.claim["totals"] == {}
    assert dossier.tier is Tier.HEARSAY
    assert dossier.claim["first_seen"] is None


def test_summarize_is_one_deterministic_human_line(store):
    _three_jobs(store)
    dossier = consolidate(store, CP, now="2026-04-01T00:00:00.000Z")

    line = summarize(dossier)
    assert line == summarize(dossier)
    assert "\n" not in line
    assert CP in line
    assert "3 interactions" in line
    assert "160.00 USDC" in line
    assert "settled 2" in line
    assert "HEARSAY" in line


def test_summarize_handles_the_empty_dossier(store):
    line = summarize(consolidate(store, "nobody.eth", write=False))
    assert "no recorded interactions" in line


def test_consolidate_survives_a_cold_start(db_path):
    writer = AdmissibleStore.open(db_path)
    _three_jobs(writer)
    first = consolidate(writer, CP, now="2026-04-01T00:00:00.000Z")
    writer.close()

    reader = AdmissibleStore.open(db_path)
    try:
        again = consolidate(reader, CP, now="2026-04-01T00:00:00.000Z")
        assert again.digest == first.digest
    finally:
        reader.close()
