"""Reflection has to change something, or it is a log line with extra steps.

The rubric word is "dynamic", and the honest test of it is not that a number was
written but that a later decision came out differently because of it. So these
tests do the full loop: read the agent's own past decisions, compute a posture,
persist it, and then show a request that would have been escrowed being refused
-- with nothing else changed.

The bounds are tested too, and they matter more than the movement. An adaptive
risk parameter that can raise its own appetite is a ladder an attacker climbs
one rung at a time; this one is bounded above by the library constant it
replaces.
"""

from __future__ import annotations

import pytest
from admissible.envelope import Envelope, Evidence, Provenance, Tier
from admissible.policy import STRANGER_CEILING_USD, WITNESSED_WEIGHT
from admissible.store import AdmissibleStore
from apps.addresses import OUR_AGENT, SIBYLCAP, SIBYLCAP_HANDLE, STRANGER, STRANGER_HANDLE
from apps.agent.posture import (
    MAX_WITNESSED_WEIGHT,
    POSTURE_CATEGORY,
    POSTURE_NAME,
    Posture,
    compute_posture,
    load_posture,
    store_posture,
)
from apps.agent.rails import SimulatedRail
from apps.agent.runtime import BuyerAgent
from apps.counterparty import CounterpartyAgent, Job, promote_to_attested, record_outcome
from apps.poisoner import PoisonerAgent
from apps.recorded_chain import RecordedChain

UNKNOWN = "0x0000000000000000000000000000000000000001"


def _seed(agent: BuyerAgent) -> None:
    seller = CounterpartyAgent()
    for service, tx_hash in (
        ("lookup", "0x" + "66" * 32),
        ("research-brief", "0x" + "55" * 32),
    ):
        amount = seller.quote(service)
        job = Job(service=service, payload="seed", requested_usd=amount)
        category, name, _ = record_outcome(agent.store, seller.perform(job))
        promote_to_attested(
            agent.store,
            category,
            name,
            counterparty=seller.address,
            amount_usd=amount,
            tx_hash=tx_hash,
            service=service,
        )
    agent.history.invalidate()


def test_an_agent_with_no_history_uses_the_library_defaults(store) -> None:
    """A first run has observed nothing and must behave exactly like the constants."""
    posture = load_posture(store)
    assert posture.stranger_ceiling_usd == STRANGER_CEILING_USD
    assert posture.witnessed_weight == WITNESSED_WEIGHT
    assert posture.decisions == 0


def test_reflection_reads_past_decisions_and_persists_a_changed_posture(agent) -> None:
    _seed(agent)
    poisoner = PoisonerAgent()

    paid = agent.hire(SIBYLCAP, 0.25, service="research-brief", handle=SIBYLCAP_HANDLE)
    assert paid.action == "pay"
    assert paid.posture_after["decisions"] == 1
    assert paid.posture_after["laundering_decisions"] == 0

    poisoner.launder_all(
        agent.store, Job(service="research-brief", payload="x", requested_usd=0.25)
    )
    agent.history.invalidate()
    refused = agent.hire(STRANGER, 0.25, service="research-brief", handle=STRANGER_HANDLE)

    assert refused.action == "refuse"
    after = refused.posture_after
    assert after["decisions"] == 2
    assert after["laundering_decisions"] == 1
    assert after["forgery_rate"] == pytest.approx(0.5)
    # Two decisions, one of which met fabricated evidence: the unsecured line a
    # stranger draws closes entirely.
    assert after["stranger_ceiling_usd"] == 0.0

    # And it is in the store, not just in the return value.
    assert load_posture(agent.store).stranger_ceiling_usd == 0.0


def test_the_new_posture_changes_a_later_decision(agent) -> None:
    """The claim that makes reflection real: same request, different answer.

    The probe is a counterparty the agent has never heard of, so nothing about
    the memories differs between the two calls. Only the parameter does."""
    _seed(agent)
    before = load_posture(agent.store)
    would_have = before.policy().decide(UNKNOWN, 0.20, [])
    assert would_have.action == "escrow"
    assert would_have.unsecured_usd == pytest.approx(STRANGER_CEILING_USD)

    PoisonerAgent().launder_all(
        agent.store, Job(service="research-brief", payload="x", requested_usd=0.25)
    )
    agent.history.invalidate()
    agent.hire(SIBYLCAP, 0.25, service="research-brief", handle=SIBYLCAP_HANDLE)
    agent.hire(STRANGER, 0.25, service="research-brief", handle=STRANGER_HANDLE)

    after = load_posture(agent.store)
    now_does = after.policy().decide(UNKNOWN, 0.20, [])

    assert now_does.action == "refuse"
    assert now_does.unsecured_usd == 0.0


def test_a_later_run_of_the_real_graph_inherits_the_tightened_posture(tmp_path) -> None:
    """Not a probe: the whole agent, in a second process, on the same file."""
    db = tmp_path / "memory.db"
    chain = RecordedChain.load(overlay=tmp_path / "overlay.json")

    first = BuyerAgent(AdmissibleStore.open(db), chain, rail=SimulatedRail(chain))
    _seed(first)
    PoisonerAgent().launder_all(
        first.store, Job(service="research-brief", payload="x", requested_usd=0.25)
    )
    first.history.invalidate()
    first.hire(SIBYLCAP, 0.25, service="research-brief", handle=SIBYLCAP_HANDLE)
    first.hire(STRANGER, 0.25, service="research-brief", handle=STRANGER_HANDLE)
    first.close()

    second = BuyerAgent(AdmissibleStore.open(db), chain, rail=SimulatedRail(chain))
    try:
        assert second.posture().stranger_ceiling_usd == 0.0
        record = second.hire(UNKNOWN, 0.20, service="research-brief")
    finally:
        second.close()

    assert record.action == "refuse"
    assert record.settled_usd == 0.0


def test_the_stranger_ceiling_can_only_tighten(store) -> None:
    """An adaptive risk parameter that can raise itself is a ladder."""
    seller = CounterpartyAgent()
    for index in range(20):
        envelope = Envelope(
            claim={
                "counterparty": seller.address,
                "outcome": "settled",
                "amount_usd": 0.25,
            },
            provenance=Provenance(
                tier=Tier.ATTESTED,
                source="x402:settlement",
                actor_address=OUR_AGENT,
                evidence=Evidence(
                    chain_id=8453, tx_hash="0x" + "55" * 32, kind="x402:settlement"
                ),
            ),
        )
        store.remember("interaction", f"clean-{index}", envelope)
        store.journal_write("decide", counterparty=seller.address, action="pay", laundering=0)

    posture = compute_posture(store)
    assert posture.forgery_rate == 0.0
    assert posture.stranger_ceiling_usd <= STRANGER_CEILING_USD, (
        "a spotless history must not buy a larger unsecured line than the default"
    )


def test_the_witnessed_weight_is_bounded_and_slow_to_rise(store) -> None:
    """One confirmed observation is not a track record.

    Without smoothing, a single promoted memory reads as a promotion rate of 1.0
    and takes the weight straight to its cap."""
    envelope = Envelope(
        claim={"counterparty": SIBYLCAP, "outcome": "settled", "amount_usd": 0.25},
        provenance=Provenance(
            tier=Tier.ATTESTED,
            source="x402:settlement",
            actor_address=OUR_AGENT,
            evidence=Evidence(
                chain_id=8453, tx_hash="0x" + "55" * 32, kind="x402:settlement"
            ),
        ),
    )
    store.remember("interaction", "only-one", envelope)
    posture = compute_posture(store)

    assert posture.promotion_rate == 1.0
    assert WITNESSED_WEIGHT < posture.witnessed_weight < MAX_WITNESSED_WEIGHT
    assert posture.witnessed_weight <= MAX_WITNESSED_WEIGHT


def test_the_posture_supersedes_rather_than_overwrites(store) -> None:
    """Which posture was in force when a payment was authorised has to stay
    answerable, so each one names the one it replaced."""
    from admissible.timeline import Timeline

    store_posture(store, compute_posture(store))
    store.journal_write("decide", counterparty=STRANGER, action="refuse", laundering=1)
    store_posture(store, compute_posture(store))

    history = Timeline(store).history(POSTURE_CATEGORY, POSTURE_NAME)
    assert len(history) == 2
    assert history[1].provenance.supersedes == history[0].digest
    assert history[0].claim["stranger_ceiling_usd"] > history[1].claim["stranger_ceiling_usd"]


def test_the_posture_shows_the_numbers_it_was_computed_from(store) -> None:
    """A parameter nobody can re-derive is indistinguishable from one somebody
    made up, which is the argument the rest of this package makes about money."""
    store.journal_write("decide", counterparty=STRANGER, action="refuse", laundering=1)
    store.journal_write("decide", counterparty=SIBYLCAP, action="pay", laundering=0)
    posture = compute_posture(store)
    claim = posture.to_claim()

    for key in (
        "decisions",
        "laundering_decisions",
        "forgery_rate",
        "interactions",
        "attested_interactions",
        "promotion_rate",
        "reason",
    ):
        assert key in claim
    assert claim["forgery_rate"] == pytest.approx(0.5)
    assert Posture.from_claim(claim).stranger_ceiling_usd == posture.stranger_ceiling_usd
