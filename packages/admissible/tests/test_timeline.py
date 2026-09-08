"""Bi-temporal replay: what did we know then, and what was true then."""

from __future__ import annotations

from admissible.envelope import Envelope
from admissible.timeline import Timeline, as_of, valid_at

from conftest import envelope

T1 = "2026-01-01T00:00:00.000Z"
T2 = "2026-02-01T00:00:00.000Z"
T3 = "2026-03-01T00:00:00.000Z"


def _two_versions(store):
    old = envelope({"counterparty": "acme.eth", "rate": "5"}, observed_at=T1)
    store.remember("terms", "acme-rate", old)
    new = envelope({"counterparty": "acme.eth", "rate": "7"}, observed_at=T2)
    store.supersede("terms", "acme-rate", new)
    return old, new


def test_as_of_returns_the_old_value_for_a_past_timestamp(store):
    old, new = _two_versions(store)

    past = as_of(store, "terms", "acme-rate", "2026-01-15T00:00:00.000Z")
    assert isinstance(past, Envelope)
    assert past.claim["rate"] == "5"
    assert past.digest == old.digest


def test_as_of_returns_the_current_value_for_now(store):
    _old, new = _two_versions(store)
    assert as_of(store, "terms", "acme-rate", T3).digest == new.digest


def test_as_of_before_we_knew_anything_is_none(store):
    _two_versions(store)
    assert as_of(store, "terms", "acme-rate", "2025-12-01T00:00:00.000Z") is None


def test_as_of_walks_a_three_link_chain(store):
    store.remember("terms", "r", envelope({"rate": "5"}, observed_at=T1))
    store.supersede("terms", "r", envelope({"rate": "7"}, observed_at=T2))
    store.supersede("terms", "r", envelope({"rate": "9"}, observed_at=T3))

    assert as_of(store, "terms", "r", "2026-01-15T00:00:00.000Z").claim["rate"] == "5"
    assert as_of(store, "terms", "r", "2026-02-15T00:00:00.000Z").claim["rate"] == "7"
    assert as_of(store, "terms", "r", "2026-04-01T00:00:00.000Z").claim["rate"] == "9"


def test_history_is_oldest_first_and_complete(store):
    _two_versions(store)
    hist = Timeline(store).history("terms", "acme-rate")
    assert [e.claim["rate"] for e in hist] == ["5", "7"]


def test_valid_at_reads_the_other_clock(store):
    """Valid time is not transaction time.

    Both records were learned today; they describe different windows of the past.
    """
    store.remember(
        "terms",
        "acme-rate",
        envelope({"rate": "5"}, observed_at=T3, valid_from=T1, valid_to=T2),
    )
    store.supersede(
        "terms",
        "acme-rate",
        envelope({"rate": "7"}, observed_at=T3, valid_from=T2),
    )

    tl = Timeline(store)
    assert tl.valid_at("terms", "acme-rate", "2026-01-15T00:00:00.000Z").claim["rate"] == "5"
    assert tl.valid_at("terms", "acme-rate", "2026-02-15T00:00:00.000Z").claim["rate"] == "7"
    assert tl.valid_at("terms", "acme-rate", "2025-06-01T00:00:00.000Z") is None


def test_valid_at_can_be_asked_as_of_a_past_knowledge_state(store):
    """The full bi-temporal question: what would we have said on date X about date Y?"""
    store.remember(
        "terms", "acme-rate", envelope({"rate": "5"}, observed_at=T1, valid_from=T1)
    )
    store.supersede(
        "terms", "acme-rate", envelope({"rate": "7"}, observed_at=T3, valid_from=T1)
    )

    # Asked today, the answer for January is the corrected record.
    assert valid_at(store, "terms", "acme-rate", "2026-01-15T00:00:00.000Z").claim["rate"] == "7"
    # Asked as we knew things in February, it is still the original.
    got = valid_at(store, "terms", "acme-rate", "2026-01-15T00:00:00.000Z", as_of=T2)
    assert got.claim["rate"] == "5"


def test_as_of_on_an_unknown_entity_is_none(store):
    assert as_of(store, "terms", "ghost", T3) is None


def test_a_bare_overwrite_is_recorded_but_not_reconstructible(store):
    """The honest limit.

    ``set_entity`` updates in place, so a ``remember`` over a live name destroys
    the previous body. The journal still proves a version existed and names its
    digest; the body is gone. ``unreconstructible`` is where we admit that
    rather than silently returning a shorter history.
    """
    first = envelope({"rate": "5"}, observed_at=T1)
    store.remember("terms", "r", first)
    store.remember("terms", "r", envelope({"rate": "7"}, observed_at=T2))

    hist = Timeline(store).history("terms", "r")
    assert [e.claim["rate"] for e in hist] == ["7"]

    lost = Timeline(store).unreconstructible("terms", "r")
    assert [rec["digest"] for rec in lost] == [first.digest]

    # And the replay says so instead of pretending the old value is the current one.
    assert as_of(store, "terms", "r", "2026-01-15T00:00:00.000Z") is None


def test_timeline_survives_a_cold_start(db_path):
    from admissible.store import AdmissibleStore

    writer = AdmissibleStore.open(db_path)
    _two_versions(writer)
    writer.close()

    reader = AdmissibleStore.open(db_path)
    try:
        assert as_of(reader, "terms", "acme-rate", "2026-01-15T00:00:00.000Z").claim["rate"] == "5"
    finally:
        reader.close()
