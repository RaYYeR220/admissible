"""The honest seller, and the promotion from a note to a proof.

The interesting assertion is not that a settled job becomes ATTESTED. It is that
the promotion is a *link* -- the new record names the old one by digest, the old
one is archived rather than edited, and re-offering the pre-promotion version
afterwards is answered SUPERSEDED. A promotion that quietly rewrote a field
would look identical from the outside and would be unauditable.
"""

from __future__ import annotations

import pytest
from admissible.envelope import Envelope, Tier
from admissible.timeline import Timeline
from admissible.verdicts import VerdictCode
from apps.addresses import OUR_AGENT
from apps.agent.state import INTERACTION_CATEGORY
from apps.counterparty import (
    PRICES_USD,
    CounterpartyAgent,
    Job,
    promote_to_attested,
    record_outcome,
)

SETTLEMENT_TX = "0x" + "55" * 32


@pytest.fixture()
def seller() -> CounterpartyAgent:
    return CounterpartyAgent()


@pytest.fixture()
def job() -> Job:
    return Job(
        service="research-brief",
        payload="Summarise the ERC-8004 feedback measurement. It found 1.2 percent.",
        requested_usd=PRICES_USD["research-brief"],
    )


def test_it_does_the_work_deterministically(seller: CounterpartyAgent, job: Job) -> None:
    """Same input, same artifact. A demo whose output varies cannot be diffed."""
    first, second = seller.perform(job), seller.perform(job)
    assert first.delivered
    assert first.artifact == second.artifact
    assert first.artifact["words"] == len(job.payload.split())


def test_it_refuses_to_quote_a_service_it_does_not_sell(seller: CounterpartyAgent) -> None:
    with pytest.raises(KeyError):
        seller.quote("apply-for-a-mortgage")


def test_its_pitch_carries_no_instruction_to_the_reader(seller: CounterpartyAgent) -> None:
    """The structural difference from the adversary is provenance, not tone --
    but the pitch is worth checking, because it is the control the injection
    test is measured against."""
    from apps.agent.narrator import looks_injected

    assert not looks_injected(seller.pitch("research-brief"))


def test_an_observed_job_is_witnessed_and_attributed_to_the_observer(
    store, seller: CounterpartyAgent, job: Job
) -> None:
    """The actor is the buyer, not the seller. A record whose actor is the party
    it flatters is a record with a motive."""
    category, name, envelope = record_outcome(store, seller.perform(job))

    assert envelope.tier is Tier.WITNESSED
    assert envelope.provenance.actor_address == OUR_AGENT
    assert envelope.claim["counterparty"] == seller.address
    assert store.recall(category, name) == envelope


def test_a_settled_payment_promotes_the_record_to_attested(
    store, seller: CounterpartyAgent, job: Job
) -> None:
    category, name, witnessed = record_outcome(store, seller.perform(job))
    attested = promote_to_attested(
        store,
        category,
        name,
        counterparty=seller.address,
        amount_usd=job.requested_usd,
        tx_hash=SETTLEMENT_TX,
        service=job.service,
    )

    current = store.recall(category, name)
    assert isinstance(current, Envelope)
    assert current.tier is Tier.ATTESTED
    assert current.provenance.evidence.tx_hash == SETTLEMENT_TX
    assert current.provenance.supersedes == witnessed.digest, (
        "the promotion must name what it replaced, or it is an edit"
    )
    assert attested.digest == current.digest


def test_the_pre_promotion_version_survives_and_is_replayable(
    store, seller: CounterpartyAgent, job: Job
) -> None:
    """Non-destructive means the old body is still there to be read."""
    category, name, witnessed = record_outcome(store, seller.perform(job))
    promote_to_attested(
        store,
        category,
        name,
        counterparty=seller.address,
        amount_usd=job.requested_usd,
        tx_hash=SETTLEMENT_TX,
        service=job.service,
    )

    history = Timeline(store).history(category, name)
    assert [env.tier for env in history] == [Tier.WITNESSED, Tier.ATTESTED]
    assert history[0].digest == witnessed.digest


def test_replaying_the_pre_promotion_record_is_refused(
    agent, seller: CounterpartyAgent, job: Job
) -> None:
    """The attack the supersession chain exists to make visible."""
    category, name, witnessed = record_outcome(agent.store, seller.perform(job))
    promote_to_attested(
        agent.store,
        category,
        name,
        counterparty=seller.address,
        amount_usd=job.requested_usd,
        tx_hash=SETTLEMENT_TX,
        service=job.service,
    )
    agent.history.invalidate()

    assert agent.gate.admit(witnessed).code is VerdictCode.SUPERSEDED


def test_the_promoted_record_re_derives_from_the_recorded_chain(
    agent, seller: CounterpartyAgent, job: Job
) -> None:
    """The whole point of the promotion: the next run does not take our word."""
    category, name, _ = record_outcome(agent.store, seller.perform(job))
    attested = promote_to_attested(
        agent.store,
        category,
        name,
        counterparty=seller.address,
        amount_usd=job.requested_usd,
        tx_hash=SETTLEMENT_TX,
        service=job.service,
    )
    agent.history.invalidate()

    verdict = agent.gate.admit(attested)
    assert verdict.code is VerdictCode.ADMISSIBLE
    assert verdict.detail["verified_amount_usd"] == pytest.approx(job.requested_usd)


def test_a_promotion_that_misstates_the_amount_fails_its_own_re_derivation(
    agent, seller: CounterpartyAgent, job: Job
) -> None:
    """Better to fail loudly on the next run than to round quietly on this one."""
    category, name, _ = record_outcome(agent.store, seller.perform(job))
    wrong = promote_to_attested(
        agent.store,
        category,
        name,
        counterparty=seller.address,
        amount_usd=job.requested_usd * 10,
        tx_hash=SETTLEMENT_TX,
        service=job.service,
    )
    agent.history.invalidate()

    assert agent.gate.admit(wrong).code is VerdictCode.AMOUNT_MISMATCH


def test_the_interaction_lands_where_consolidation_looks_for_it(
    store, seller: CounterpartyAgent, job: Job
) -> None:
    from admissible.consolidate import INTERACTION_CATEGORY as folded_from

    category, _, _ = record_outcome(store, seller.perform(job))
    assert category == INTERACTION_CATEGORY == folded_from
