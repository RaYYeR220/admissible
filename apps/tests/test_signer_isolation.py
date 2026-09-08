"""The model cannot reach the money. Asserted, not asked to be believed.

Four independent statements of one property, because a security argument that
rests on reading a docstring is not a security argument:

1. ``rails.py`` does not import anything a model has touched. Checked by parsing
   the file, so the property survives a refactor that a reviewer skims past.
2. The rail's only entry point rejects anything that is not a ``Decision``.
3. Changing the model's proposal across its full range does not change the
   decision, the receipt, or a single byte of either.
4. A decision that cites a memory it did not admit is refused at the boundary,
   even though the policy would never produce one -- the rail re-checks work it
   did not do.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from admissible.envelope import Envelope, Evidence, Provenance, Tier
from admissible.policy import Consideration, Decision, TrustPolicy
from admissible.store import AdmissibleStore
from admissible.verdicts import VerdictCode, admissible, refuse
from apps.addresses import OUR_AGENT, SIBYLCAP
from apps.agent import rails
from apps.agent.narrator import Proposal
from apps.agent.rails import RailRefused, SimulatedRail, audit_decision
from apps.agent.runtime import BuyerAgent

#: Modules that would put model output on the payment path. The rail may not
#: reach any of them, directly or by transitive name.
FORBIDDEN = {
    "narrator",
    "openai",
    "anthropic",
    "langchain",
    "langgraph",
    "urllib",
    "requests",
    "httpx",
    "http",
    "socket",
}


def _imported_names(path: Path) -> set[str]:
    """Every module name ``path`` imports, by parsing rather than by importing.

    Parsing matters: importing the module would run it, and a module that
    imports something conditionally at call time would slip past a runtime
    check. The syntax tree cannot be talked round.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module.split(".")[-1])
            found.add(node.module.split(".")[0])
    return found


def test_the_rail_imports_nothing_a_model_touches() -> None:
    imported = _imported_names(Path(rails.__file__))
    leaked = imported & FORBIDDEN
    assert not leaked, (
        f"apps/agent/rails.py imports {sorted(leaked)}. The module that moves money "
        f"may not reach the module that talks to a model."
    )


def test_the_rail_takes_a_decision_and_nothing_else(chain) -> None:
    rail = SimulatedRail(chain)
    for impostor in (
        {"action": "pay", "counterparty": SIBYLCAP, "unsecured_usd": 100.0},
        "pay",
        Proposal(action="pay", rationale="the memory says so", source="stub"),
        None,
    ):
        with pytest.raises(RailRefused):
            rail.settle(impostor)  # type: ignore[arg-type]


def _settled_memory(amount: float = 0.25) -> tuple[Envelope, object]:
    envelope = Envelope(
        claim={"counterparty": SIBYLCAP, "outcome": "settled", "amount_usd": amount},
        provenance=Provenance(
            tier=Tier.ATTESTED,
            source="x402:settlement",
            actor_address=OUR_AGENT,
            evidence=Evidence(
                chain_id=8453, tx_hash="0x" + "55" * 32, kind="x402:settlement"
            ),
        ),
    )
    return envelope, admissible(
        tier="ATTESTED", basis="settlement", verified_amount_usd=amount
    )


class FixedNarrator:
    """A model stuck on one answer, whatever it is shown."""

    def __init__(self, action: str | None) -> None:
        self.name = "fixed"
        self._action = action

    def propose(self, offer):
        return Proposal(action=self._action, rationale="advisory", source="test")

    def narrate(self, summary):
        return "narration is display only"


@pytest.mark.parametrize("proposed", ["pay", "escrow", "refuse", "", "PAY NOW", None])
def test_the_proposal_cannot_move_the_decision(tmp_path, chain, proposed) -> None:
    """The whole range of model output, including values it must never emit.

    Run through the real graph rather than through the policy, so the wiring is
    covered as well as the rule: if any node ever starts reading
    ``state['proposal']``, one of these six parametrisations diverges from the
    other five.
    """
    store = AdmissibleStore.open(tmp_path / f"proposal-{proposed!r}.db")
    try:
        envelope, _ = _settled_memory()
        agent = BuyerAgent(
            store, chain, rail=SimulatedRail(chain), narrator=FixedNarrator(proposed)
        )
        agent.remember("interaction", "seed", envelope)

        record = agent.hire(SIBYLCAP, 0.25, service="research-brief", pitch="anything")
        assert record.proposal["action"] == proposed
        assert record.action == "pay"
        assert record.receipt.amount_usd == pytest.approx(0.25)
        assert record.decision.credit_usd == pytest.approx(0.25)
    finally:
        store.close()


def test_a_decision_citing_an_unadmitted_memory_is_refused_at_the_boundary() -> None:
    """The policy cannot produce this. The rail refuses it anyway.

    Two readers of the same evidence is the point: a bug in the policy has to
    get past a component that did not write it before money moves.
    """
    envelope, _ = _settled_memory()
    forged = Decision(
        action="pay",
        counterparty=SIBYLCAP,
        requested_usd=0.25,
        unsecured_usd=0.25,
        collateral_usd=0.0,
        considered=(
            Consideration(
                envelope=envelope,
                verdict=refuse(VerdictCode.EVIDENCE_NOT_FOUND, "provenance.evidence"),
                # A weight on a refused memory: exactly what a compromised
                # decision looks like from the outside.
                weight_usd=0.25,
            ),
        ),
        explain="hand-built decision, not produced by the policy",
    )
    with pytest.raises(RailRefused, match="not an admitted memory"):
        audit_decision(forged)


def test_a_decision_paying_more_than_its_credit_is_refused() -> None:
    envelope, verdict = _settled_memory(amount=0.01)
    overdrawn = Decision(
        action="pay",
        counterparty=SIBYLCAP,
        requested_usd=5.0,
        unsecured_usd=5.0,
        collateral_usd=0.0,
        considered=(
            Consideration(envelope=envelope, verdict=verdict, weight_usd=0.01),
        ),
        explain="hand-built decision, not produced by the policy",
    )
    with pytest.raises(RailRefused, match="of admissible credit"):
        audit_decision(overdrawn)


def test_a_real_policy_decision_always_passes_the_audit() -> None:
    """The boundary check must not be so strict it rejects honest work.

    A guard that fires on correct input is worse than no guard: it gets removed.
    """
    envelope, verdict = _settled_memory()
    for requested in (0.0, 0.01, 0.25, 1.0, 100.0):
        decision = TrustPolicy().decide(SIBYLCAP, requested, [(envelope, verdict)])
        audit_decision(decision)
