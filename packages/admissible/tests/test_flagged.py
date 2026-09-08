"""The FLAGGED tier: a table Sibyl declares and never exposes."""

from __future__ import annotations

import pytest

from admissible.flagged import FlaggedActors
from admissible.store import AdmissibleStore

ADDR = "0xAbC0000000000000000000000000000000000001"


def test_flag_actor_returns_an_id_and_is_readable_back(store):
    flags = FlaggedActors(store)
    flag_id = flags.flag_actor(
        address=ADDR,
        reason="paid for a job that never settled",
        evidence={"job": "job-7", "tx": None},
    )
    assert isinstance(flag_id, str) and flag_id

    rec = flags.is_flagged(ADDR)
    assert rec is not None
    assert rec.id == flag_id
    assert rec.reason.startswith("paid for a job")
    assert rec.evidence["job"] == "job-7"
    assert rec.is_active


def test_lookup_is_case_insensitive_but_the_given_form_is_preserved(store):
    flags = FlaggedActors(store)
    flags.flag_actor(address=ADDR, reason="fraud", evidence={})

    assert flags.is_flagged(ADDR.lower()) is not None
    assert flags.is_flagged(ADDR.upper()) is not None
    assert flags.is_flagged(ADDR).actor_address == ADDR  # exactly as handed to us


def test_handles_are_flaggable_too(store):
    flags = FlaggedActors(store)
    flags.flag_actor(handle="Rug.Puller", reason="social engineering", evidence={})
    assert flags.is_flagged("rug.puller") is not None
    assert flags.is_flagged("someone-else") is None


def test_flag_requires_an_identifier(store):
    flags = FlaggedActors(store)
    with pytest.raises(ValueError):
        flags.flag_actor(reason="vibes", evidence={})


def test_every_flag_writes_a_journal_event(store):
    flags = FlaggedActors(store)
    flag_id = flags.flag_actor(address=ADDR, reason="fraud", evidence={"job": "job-7"})

    records = store.journal(op="flag")
    assert len(records) == 1
    assert records[0]["flag_id"] == flag_id
    assert records[0]["actor_address"] == ADDR
    assert records[0]["reason"] == "fraud"


def test_unflag_is_non_destructive_and_journalled(store):
    flags = FlaggedActors(store)
    flag_id = flags.flag_actor(address=ADDR, reason="fraud", evidence={})

    assert flags.unflag(flag_id, "chargeback reversed, the dispute was ours") is True
    assert flags.is_flagged(ADDR) is None
    assert flags.list_flags() == []

    revoked = flags.list_flags(include_revoked=True)
    assert len(revoked) == 1
    assert revoked[0].revoked_at
    assert "chargeback" in revoked[0].revoked_reason
    assert not revoked[0].is_active

    assert len(store.journal(op="unflag")) == 1


def test_unflag_of_an_unknown_id_is_false(store):
    assert FlaggedActors(store).unflag("no-such-id", "typo") is False


def test_list_flags_is_newest_first(store):
    flags = FlaggedActors(store)
    a = flags.flag_actor(handle="first", reason="a", evidence={}, flagged_at="2026-01-01T00:00:00.000Z")
    b = flags.flag_actor(handle="second", reason="b", evidence={}, flagged_at="2026-02-01T00:00:00.000Z")
    assert [f.id for f in flags.list_flags()] == [b, a]


def test_flag_survives_a_cold_start(db_path):
    """The requirement: a fresh client on the same file must see the flag.

    Nothing is cached in the process. This is the whole point of writing the
    FLAGGED tier into Sibyl's own table rather than into a side file.
    """
    writer = AdmissibleStore.open(db_path)
    flag_id = FlaggedActors(writer).flag_actor(
        address=ADDR, reason="drained an escrow", evidence={"chain_id": 8453}
    )
    writer.close()

    reader = AdmissibleStore.open(db_path)
    try:
        rec = FlaggedActors(reader).is_flagged(ADDR.lower())
        assert rec is not None
        assert rec.id == flag_id
        assert rec.evidence["chain_id"] == 8453
    finally:
        reader.close()


def test_flags_land_in_sibyls_own_table(store):
    """Not a side table. The row is in flagged_actors, where the schema put it."""
    FlaggedActors(store).flag_actor(address=ADDR, reason="fraud", evidence={})
    with store.client.storage.connection() as conn:
        row = conn.execute(
            "SELECT actor_address, actor_handle, reason FROM flagged_actors"
        ).fetchone()
    assert row["actor_address"] == ADDR
    assert row["actor_handle"] is None
    assert row["reason"] == "fraud"
