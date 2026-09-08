"""The adversary, and what each of its vectors actually buys.

The claim being tested is not "the poisoner is caught" -- that would pass with a
gate that refuses everything. It is that each vector produces its own distinct
verdict, that the two which constitute forgery cost the actor its licence to
speak, and that the one which does not is nonetheless reachable through the
relations graph.
"""

from __future__ import annotations

import pytest
from admissible.policy import laundering_attempts
from admissible.relations import VOUCHED_FOR, Relations
from admissible.verdicts import VerdictCode
from apps.addresses import PARTNER, POISONER, STRANGER, STRANGER_HANDLE
from apps.agent.state import ACTOR_CATEGORY
from apps.counterparty import Job
from apps.poisoner import INJECTED_INSTRUCTION, PoisonerAgent


@pytest.fixture()
def job() -> Job:
    return Job(service="research-brief", payload="Summarise the corpus.", requested_usd=0.25)


def _verdict(agent, envelope) -> VerdictCode:
    agent.history.invalidate()
    return agent.gate.admit(envelope).code


def test_each_vector_produces_its_own_verdict(agent, job) -> None:
    """Three mechanisms, three answers. One answer for all three would mean the
    gate is refusing on something they share rather than on what each did."""
    poisoner = PoisonerAgent()
    _, attachment = poisoner.poisoned_job_result(agent.store, job)
    reference = poisoner.peer_reference(agent.store)
    _, injection = poisoner.tool_output_injection(agent.store)

    assert _verdict(agent, attachment.envelope) is VerdictCode.EVIDENCE_NOT_FOUND
    assert _verdict(agent, reference.envelope) is VerdictCode.INADMISSIBLE_HEARSAY
    assert _verdict(agent, injection.envelope) is VerdictCode.COUNTERPARTY_MISMATCH


def test_each_vector_reports_the_verdict_it_expects(agent, job) -> None:
    """The adversary declares what it expects to happen. If the gate disagrees,
    either the attack has changed or the defence has, and both are worth a
    failing test rather than a quiet divergence."""
    poisoner = PoisonerAgent()
    for laundered in poisoner.launder_all(agent.store, job):
        assert _verdict(agent, laundered.envelope).value == laundered.expected_verdict


def test_the_injected_instruction_reaches_the_store_and_changes_nothing(agent) -> None:
    """The payload is in the claim, the model would read it, and the verdict is
    decided on provenance the injection cannot touch."""
    poisoner = PoisonerAgent()
    document, injection = poisoner.tool_output_injection(agent.store)

    assert INJECTED_INSTRUCTION in document["body"]
    assert INJECTED_INSTRUCTION in injection.envelope.claim["note"]
    # The refusal is about who was paid, not about what the note says.
    verdict = agent.gate.admit(injection.envelope)
    assert verdict.code is VerdictCode.COUNTERPARTY_MISMATCH
    assert "note" not in verdict.fields


def test_the_forgeries_are_laundering_and_the_reference_is_not(agent, job) -> None:
    """The distinction that decides whether an actor gets flagged.

    An unsupported assertion is ordinary and carries no weight. A fabricated
    receipt is an attack. Collapsing the two would either flag every optimistic
    peer or flag nobody."""
    poisoner = PoisonerAgent()
    poisoner.launder_all(agent.store, job)
    agent.history.invalidate()

    record = agent.hire(STRANGER, 0.25, service="research-brief", handle=STRANGER_HANDLE)
    codes = {c.verdict.code for c in laundering_attempts(record.decision)}

    assert record.action == "refuse"
    assert VerdictCode.EVIDENCE_NOT_FOUND in codes
    assert VerdictCode.COUNTERPARTY_MISMATCH in codes
    assert VerdictCode.INADMISSIBLE_HEARSAY not in codes


def test_flagging_the_forger_reaches_the_accomplice_that_only_vouched(agent, job) -> None:
    """The payoff of the relations graph.

    The accomplice forges nothing. Every claim it makes is honestly labelled as
    a peer reference and refused as hearsay, which is not a flaggable offence.
    It is reached by walking backwards along the vouch it made, and by nothing
    else."""
    poisoner = PoisonerAgent()
    poisoner.launder_all(agent.store, job)
    agent.history.invalidate()

    assert agent.flags.is_flagged(PARTNER) is None

    record = agent.hire(STRANGER, 0.25, service="research-brief", handle=STRANGER_HANDLE)

    assert agent.flags.is_flagged(POISONER) is not None
    assert agent.flags.is_flagged(PARTNER) is not None, (
        "the accomplice was never caught by a per-claim check and must be reached "
        "through the vouch"
    )
    reached = {(node["category"], node["name"]) for node in record.contaminated}
    assert (ACTOR_CATEGORY, PARTNER.lower()) in reached


def test_the_vouch_edge_exists_before_anyone_is_flagged(agent) -> None:
    """The graph is built by the adversary advertising its own network, not by
    the defence inferring one after the fact."""
    poisoner = PoisonerAgent()
    poisoner.peer_reference(agent.store)

    vouchers = Relations(agent.store).neighbors(
        (ACTOR_CATEGORY, POISONER.lower()), VOUCHED_FOR, direction="in"
    )
    assert (ACTOR_CATEGORY, PARTNER.lower()) in [(v.category, v.name) for v in vouchers]


def test_the_return_visit_is_admitted_and_refused_anyway(agent, job) -> None:
    """The attack no envelope can catch.

    The notes are forged in the buyer's own name -- ``agent:self``, the buyer's
    address -- and the gate admits every one of them, because nothing in an
    envelope distinguishes an observation you made from one somebody typed into
    your store. The payment is refused because the store remembers the address
    that is asking."""
    poisoner = PoisonerAgent()
    poisoner.launder_all(agent.store, job)
    agent.history.invalidate()
    agent.hire(STRANGER, 0.25, service="research-brief", handle=STRANGER_HANDLE)

    planted = poisoner.return_visit(agent.store)
    agent.history.invalidate()
    for laundered in planted:
        assert agent.gate.admit(laundered.envelope).code is VerdictCode.ADMISSIBLE

    record = agent.hire(POISONER, 0.25, service="research-brief")

    assert record.action == "refuse"
    assert record.receipt.settled is False
    assert record.decision.blocked_by is not None
    assert all(c["verdict"]["admits"] for c in record.considered), (
        "every planted memory should be admitted; the refusal is about the "
        "counterparty, not about the claims"
    )


def test_the_poisoner_delivers_real_work(job) -> None:
    """The job is genuinely done. An adversary that fails the work is caught by
    checking the work, which is a defence this system does not need to claim."""
    result = PoisonerAgent().deliver_job(job)
    assert result.delivered
    assert result.artifact["words"] == len(job.payload.split())
    assert result.attachments[0]["about"] == STRANGER
