"""What memory is worth, measured by taking it away.

These are the demo's beats as assertions. Beat 4 and beat 5 are the two halves
of one claim -- that the store, not the envelope, is what stops the returning
attacker -- and a claim like that is only worth making if the negative case is
also tested. So the same attack is run twice: once against a store that
remembers, once against one that has been deleted, and the outcomes must differ.

The cross-process half is genuine. A second ``AdmissibleStore`` is opened on the
same path after the first is closed, which is what the demo's second invocation
does; a test that reused the open handle would prove nothing about cold start.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from admissible.store import AdmissibleStore
from apps.addresses import POISONER, SIBYLCAP, SIBYLCAP_HANDLE, STRANGER, STRANGER_HANDLE
from apps.agent.rails import SimulatedRail
from apps.agent.runtime import BuyerAgent
from apps.counterparty import CounterpartyAgent, Job, promote_to_attested, record_outcome
from apps.poisoner import PoisonerAgent
from apps.recorded_chain import RecordedChain


def _seed_settled_history(agent: BuyerAgent) -> float:
    """Three real settlements, cited by three attested memories.

    Written with ``observed_at`` now and ``valid_from`` in the past, which is
    what the two clocks are for: we learned it now, it was true earlier.
    Backdating ``observed_at`` instead would trip the gate, correctly.
    """
    seller = CounterpartyAgent()
    total = 0.0
    for service, tx_hash in (
        ("lookup", "0x" + "66" * 32),
        ("research-brief", "0x" + "55" * 32),
        ("deep-report", "0x" + "aa" * 32),
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
            valid_from="2026-08-09T00:00:00.000Z",
        )
        total += amount
    agent.history.invalidate()
    return total


def _open(db: Path, chain: RecordedChain) -> BuyerAgent:
    return BuyerAgent(AdmissibleStore.open(db), chain, rail=SimulatedRail(chain))


def test_re_derivable_history_gets_paid(agent) -> None:
    """The negative control. A gate that refuses everything fails here."""
    total = _seed_settled_history(agent)
    record = agent.hire(
        SIBYLCAP, 0.25, service="research-brief", handle=SIBYLCAP_HANDLE
    )

    assert record.action == "pay"
    assert record.receipt.settled is True
    assert record.settled_usd == pytest.approx(0.25)
    assert record.decision.credit_usd == pytest.approx(total)
    assert len(record.decision.citations()) == 3


def test_a_forged_settlement_refuses_outright_rather_than_escrowing(agent) -> None:
    """Collateral protects against failure, not against fraud.

    An escrow here would be the subtle wrong answer: it looks cautious and it
    still hands money to somebody who just presented a receipt that does not
    exist."""
    _seed_settled_history(agent)
    poisoner = PoisonerAgent()
    poisoner.launder_all(
        agent.store, Job(service="research-brief", payload="x", requested_usd=0.25)
    )
    agent.history.invalidate()

    record = agent.hire(STRANGER, 0.25, service="research-brief", handle=STRANGER_HANDLE)

    assert record.action == "refuse"
    assert record.receipt.settled is False
    assert record.settled_usd == 0.0
    assert record.decision.blocked_by["kind"] == "laundering_attempt"
    assert record.decision.credit_usd == 0.0


def test_a_new_process_refuses_the_returning_attacker_from_the_file(tmp_path) -> None:
    """Beat 4. Nothing is carried between the two agents except the database."""
    db = tmp_path / "memory.db"
    chain = RecordedChain.load(overlay=tmp_path / "overlay.json")
    poisoner = PoisonerAgent()

    first = _open(db, chain)
    _seed_settled_history(first)
    poisoner.launder_all(
        first.store, Job(service="research-brief", payload="x", requested_usd=0.25)
    )
    first.history.invalidate()
    first.hire(STRANGER, 0.25, service="research-brief", handle=STRANGER_HANDLE)
    flags_written = len(first.flags.list_flags())
    first.close()

    # A completely separate handle on the same path, exactly as a second
    # invocation of the demo opens it.
    second = _open(db, chain)
    try:
        assert len(second.flags.list_flags()) == flags_written == 2
        poisoner.return_visit(second.store)
        second.history.invalidate()
        record = second.hire(POISONER, 0.25, service="research-brief")

        assert record.action == "refuse"
        assert record.settled_usd == 0.0
        assert record.decision.blocked_by is not None
    finally:
        second.close()


def test_deleting_the_memory_lets_the_same_attack_through(tmp_path) -> None:
    """Beat 5, and the point of the whole exercise.

    Same code, same chain, same attacker, same five memories. The only thing
    removed is the store, and the payment goes through."""
    db = tmp_path / "memory.db"
    chain = RecordedChain.load(overlay=tmp_path / "overlay.json")
    poisoner = PoisonerAgent()

    remembering = _open(db, chain)
    _seed_settled_history(remembering)
    poisoner.launder_all(
        remembering.store, Job(service="research-brief", payload="x", requested_usd=0.25)
    )
    remembering.history.invalidate()
    remembering.hire(STRANGER, 0.25, service="research-brief", handle=STRANGER_HANDLE)
    poisoner.return_visit(remembering.store)
    remembering.history.invalidate()
    with_memory = remembering.hire(POISONER, 0.25, service="research-brief")
    remembering.close()

    for suffix in ("", "-wal", "-shm", "-journal"):
        candidate = Path(str(db) + suffix)
        if candidate.exists():
            candidate.unlink()
    assert not db.exists()

    forgetting = _open(db, chain)
    try:
        assert forgetting.flags.list_flags() == []
        poisoner.return_visit(forgetting.store)
        forgetting.history.invalidate()
        without_memory = forgetting.hire(POISONER, 0.25, service="research-brief")
    finally:
        forgetting.close()

    assert with_memory.action == "refuse"
    assert with_memory.settled_usd == 0.0
    assert without_memory.action == "pay"
    assert without_memory.settled_usd == pytest.approx(0.25)


def test_deleting_the_memory_also_costs_the_agent_a_legitimate_payment(tmp_path) -> None:
    """The half that is easy to forget: memory is revenue, not only defence.

    The settlements are still on the chain after the store is deleted. The agent
    simply has nothing that knows to cite them, so a counterparty it had paid
    unsecured is now asked to post collateral."""
    db = tmp_path / "memory.db"
    chain = RecordedChain.load(overlay=tmp_path / "overlay.json")

    remembering = _open(db, chain)
    _seed_settled_history(remembering)
    with_memory = remembering.hire(
        SIBYLCAP, 0.25, service="research-brief", handle=SIBYLCAP_HANDLE
    )
    remembering.close()
    db.unlink()

    forgetting = _open(db, chain)
    try:
        without_memory = forgetting.hire(
            SIBYLCAP, 0.25, service="research-brief", handle=SIBYLCAP_HANDLE
        )
    finally:
        forgetting.close()

    assert with_memory.action == "pay"
    assert with_memory.decision.collateral_usd == 0.0
    assert without_memory.action == "escrow"
    assert without_memory.decision.collateral_usd > 0
    assert chain.settlement("0x" + "55" * 32) is not None, (
        "the chain must be untouched: deleting memory is not deleting evidence"
    )


def test_a_settled_payment_re_derives_in_the_next_process(tmp_path) -> None:
    """An agent that pays and then cannot prove it paid has learned nothing.

    The rail writes its settlement through to the chain overlay, so the ATTESTED
    memory the agent wrote about its own payment is re-derivable by a process
    that was not there when it happened."""
    db = tmp_path / "memory.db"
    overlay = tmp_path / "overlay.json"
    chain = RecordedChain.load(overlay=overlay)

    first = _open(db, chain)
    _seed_settled_history(first)
    paid = first.hire(SIBYLCAP, 0.25, service="research-brief", handle=SIBYLCAP_HANDLE)
    first.close()
    assert paid.receipt.tx_hash

    reloaded = RecordedChain.load(overlay=overlay)
    assert reloaded.settlement(paid.receipt.tx_hash) is not None

    second = _open(db, reloaded)
    try:
        again = second.hire(
            SIBYLCAP, 0.25, service="research-brief", handle=SIBYLCAP_HANDLE
        )
        cited = {c["digest"] for c in again.considered if c["weight_usd"] > 0}
    finally:
        second.close()

    assert again.action == "pay"
    assert len(cited) >= 4, "the agent's own settlement should now be one of its citations"
