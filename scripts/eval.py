"""The graded run: three layers over the same pre-registered corpus.

    python scripts/eval.py
    python scripts/eval.py --json
    python scripts/eval.py --no-graph      # skip the slowest layer

``bench/run.py`` scores one question: does the gate return the right verdict for
one memory? That is necessary and it is not sufficient. A verdict that is
correct and then ignored by the thing holding the wallet has protected nobody.
So this adds the two layers underneath it, against the same corpus, imported
rather than restated -- ``bench.corpus`` and ``bench.run`` are the source of
truth for both the cases and the stubs, and if they change this file changes
with them.

    LAYER 1  verdicts     bench.run, verbatim. Did the gate say the right thing?
    LAYER 2  money        gate -> policy -> payment rail. Did the right thing
                          happen to the money?
    LAYER 3  agent        the full LangGraph agent, over a real store, one case
                          per database. Does the assembled thing agree with
                          layer 2, or did the wiring lose the verdict?

The counterfactual, and why it is not circular
----------------------------------------------
Scoring layer 2 against a hand-written "expected action" per case would be
grading the policy against a table I wrote to match the policy. Instead each
case is run twice through the *same* policy and the *same* rail, and only the
gate differs:

    the real gate            re-derives every memory from the case's chain state
    the credulous gate       admits everything, exactly as an agent with a
                             memory store and no admissibility rule would

Two properties are then measurable rather than asserted:

    an attack is caught       the real path does not pay
    a control is not damaged  the real path takes the same action as the
                              credulous one, so the gate costs nothing on sound
                              memories

and one number falls out of the difference: the money the credulous agent hands
over, which is what each memory was written to unlock. The credulous gate still
honours the tier field, because an agent that stores tiers and reads them is the
realistic baseline -- the weaker straw man would pay more and flatter the result.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "bench"))

from apps import REPO_ROOT  # noqa: E402  -- the import puts packages/admissible/src on the path

import corpus as bench_corpus  # noqa: E402  -- bench/corpus.py, the pre-registered cases
import run as bench_run  # noqa: E402  -- bench/run.py, the gate scorecard and its stubs
from admissible.envelope import Envelope, Provenance, Tier, utcnow  # noqa: E402
from admissible.flagged import FlaggedActors  # noqa: E402
from admissible.gate import AdmissionGate  # noqa: E402
from admissible.policy import Decision, TrustPolicy  # noqa: E402
from admissible.store import AdmissibleStore  # noqa: E402
from admissible.verdicts import Verdict, admissible  # noqa: E402
from apps.agent.rails import RefusingRail  # noqa: E402
from apps.agent.runtime import BuyerAgent  # noqa: E402
from apps.agent.state import TESTIMONIAL_CATEGORY  # noqa: E402
from apps.recorded_chain import usd_to_base_units  # noqa: E402

#: What a memory is asked to unlock when its own claim names no amount. Above
#: the stranger ceiling on purpose: a request a stranger could already cover is
#: not a test of anything.
DEFAULT_REQUEST_USD = 0.25

WIDTH = 84


# ----------------------------------------------------------------------
# The credulous baseline
# ----------------------------------------------------------------------
class CredulousGate:
    """Admits every memory it is shown, and believes the amount it claims.

    This is the agent the corpus was written against: one that stores
    provenance, reads the tier off it, takes the claimed amount as the settled
    amount, and never checks whether either was earned. It is not a straw man --
    it is what almost every published agent memory layer does today, and it is
    why a fabricated settlement is worth writing.

    Believing the claimed amount is the load-bearing part. The real policy draws
    an ATTESTED memory's weight from ``verdict.detail['verified_amount_usd']``,
    a number the gate produces by reading the chain; a baseline that admitted
    everything but reported no verified amount would extend no credit and would
    quietly score as safe. The credulous agent's whole mistake is that the claim
    and the verification are the same field.
    """

    def admit(self, memory: Any) -> Verdict:
        claim = memory.get("claim") if isinstance(memory, dict) else None
        amount = claim.get("amount_usd") if isinstance(claim, dict) else None
        return admissible(
            basis="credulous baseline: the memory says so",
            verified_amount_usd=amount,
        )


def build_reference_gate(case: Any) -> AdmissionGate:
    """A gate wired exactly as ``bench/run.py`` wires it.

    Layer 2 needs the ``Verdict`` objects, not just their codes -- an ATTESTED
    memory's weight comes out of ``verdict.detail``, so a code alone cannot be
    turned back into a decision. ``bench.run.run()`` builds its gate inline and
    returns only codes, so this rebuilds one.

    Every parameter that could drift is imported from the corpus rather than
    retyped: ``NOW`` is the frozen clock the cases were written against and
    ``OUR_AGENT`` is the wallet the settlements are supposed to involve. The one
    remaining risk -- that ``bench/run.py`` starts constructing its gate
    differently -- is measured rather than assumed: layer 2 compares its verdict
    for every case against layer 1's and reports the agreement count, so a drift
    shows up as a number on the scorecard instead of as a silently different
    result.
    """
    return AdmissionGate(
        chain=bench_run.StubChain(case),
        flags=bench_run.StubFlags(case),
        history=bench_run.StubHistory(case),
        self_address=bench_corpus.OUR_AGENT,
        now=lambda: bench_corpus.NOW,
    )


def request_for(case: Any) -> tuple[str, float]:
    """Who the memory is about, and how much it is trying to unlock.

    The amount comes from the claim itself. A memory asserting a $2,500
    settlement is asking to move $2,500, and scoring it against a token request
    would understate exactly the case that matters most.

    Quantised to six decimals on the way out, because a request is money and
    USDC has six decimals. Without it, a claim carrying ``0.1 + 0.2`` asks for
    $0.30000000000000004 while the chain settles $0.30, and the control fails by
    four parts in ten quintillion -- which measures Python's float repr, not the
    gate.
    """
    if case.envelope is None:
        return bench_corpus.STRANGER, DEFAULT_REQUEST_USD
    claim = case.envelope.claim
    counterparty = str(claim.get("counterparty") or bench_corpus.STRANGER)
    try:
        requested = usd_to_base_units(claim.get("amount_usd")) / 10**6
    except (TypeError, ValueError):
        requested = 0.0
    return counterparty, requested if requested > 0 else DEFAULT_REQUEST_USD


# ----------------------------------------------------------------------
# Layer 2: gate -> policy -> rail
# ----------------------------------------------------------------------
@dataclass
class MoneyResult:
    """One case, decided both ways."""

    case_id: str
    family: str
    is_control: bool
    counterparty: str
    requested_usd: float
    real_action: str
    real_settled_usd: float
    real_credit_usd: float
    real_verdict: str
    credulous_action: str
    credulous_settled_usd: float

    @property
    def attack_caught(self) -> bool:
        """An attack is caught when its memory bought nothing.

        Two conditions, and the second is the strict one. No payment is the
        obvious half. The half that matters is that the forged memory extended
        *zero credit* -- because a stranger with no admissible history still
        draws the documented stranger ceiling, and an attack that ends in a
        five-cent escrow has not succeeded at anything; the agent risked what it
        risks on anyone it has never met. Scoring on the settled amount alone
        would count that as a loss and let a real credit line hide inside it.
        """
        return self.is_control or (self.real_action != "pay" and self.real_credit_usd == 0.0)

    @property
    def control_undamaged(self) -> bool:
        """The gate must cost nothing on a sound memory."""
        return not self.is_control or self.real_action == self.credulous_action

    @property
    def money_saved_usd(self) -> float:
        return round(max(0.0, self.credulous_settled_usd - self.real_settled_usd), 6)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.case_id,
            "family": self.family,
            "control": self.is_control,
            "requested_usd": self.requested_usd,
            "real": {
                "action": self.real_action,
                "settled_usd": self.real_settled_usd,
                "verdict": self.real_verdict,
            },
            "credulous": {
                "action": self.credulous_action,
                "settled_usd": self.credulous_settled_usd,
            },
            "attack_caught": self.attack_caught,
            "control_undamaged": self.control_undamaged,
            "money_saved_usd": self.money_saved_usd,
        }


def _decide_and_settle(
    gate: Any, case: Any, counterparty: str, requested: float, flags: Any
) -> tuple[Decision, float, str]:
    """Run one case through a gate, the real policy and the dry-run rail.

    The rail is ``RefusingRail``: it audits the decision at the money boundary
    exactly as the live one does, and settles nothing. Scoring a policy by
    letting it spend is a bad habit even when the money is simulated.
    """
    subject = (
        case.store_state["raw_body"] if case.envelope is None else case.envelope.to_body()
    )
    verdict = gate.admit(subject)
    judged: list[tuple[Envelope, Verdict]] = (
        [(case.envelope, verdict)] if case.envelope is not None else []
    )
    decision = TrustPolicy().decide(
        counterparty,
        requested,
        judged,
        flagged=flags.is_flagged(counterparty),
    )
    # The rail settles nothing and reports what a live one would have moved, so
    # exposure is measured at the same boundary the money would cross.
    receipt = RefusingRail().settle(decision)
    return decision, receipt.amount_usd, verdict.code.value


def run_money_layer() -> list[MoneyResult]:
    results: list[MoneyResult] = []
    for case in bench_corpus.CASES:
        counterparty, requested = request_for(case)
        flags = bench_run.StubFlags(case)
        real_decision, real_settled, verdict = _decide_and_settle(
            build_reference_gate(case), case, counterparty, requested, flags
        )
        # The credulous baseline is shown the same flag lookup. Withholding it
        # would be inventing a weaker opponent than the one the corpus describes.
        cred_decision, cred_settled, _ = _decide_and_settle(
            CredulousGate(), case, counterparty, requested, flags
        )
        results.append(
            MoneyResult(
                case_id=case.id,
                family=case.family,
                is_control=case.is_control,
                counterparty=counterparty,
                requested_usd=requested,
                real_action=real_decision.action,
                real_settled_usd=real_settled,
                real_credit_usd=real_decision.credit_usd,
                real_verdict=verdict,
                credulous_action=cred_decision.action,
                credulous_settled_usd=cred_settled,
            )
        )
    return results


# ----------------------------------------------------------------------
# Layer 3: the assembled agent
# ----------------------------------------------------------------------
@dataclass
class GraphResult:
    """One case run through the whole agent.

    Scored against the same two properties layer 2 uses, not against a
    character-for-character match with layer 2's action. The agent recalls from
    a real store and the store has opinions layer 2 does not: a claim naming no
    counterparty is not a memory *about* anyone and never reaches the policy,
    and a claim carrying a non-finite number cannot be written at all because
    SQLite's ``json_valid`` CHECK rejects it. Both are the system working, and
    both would show as a mismatch under a strict-equality score.

    So: an attack passes when no forged memory bought credit and nothing beyond
    the documented stranger ceiling moved. A control passes when the agent takes
    the same action layer 2 did, because on sound evidence the two layers have
    no excuse to differ.
    """

    case_id: str
    is_control: bool
    expected_action: str
    got_action: str
    settled_usd: float
    credit_usd: float = 0.0
    note: str = ""

    @property
    def exact(self) -> bool:
        return self.got_action == self.expected_action

    @property
    def agreed(self) -> bool:
        if self.got_action == "error":
            return False
        if self.is_control:
            return self.exact
        return self.got_action != "pay" and self.credit_usd == 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.case_id,
            "control": self.is_control,
            "expected_action": self.expected_action,
            "got_action": self.got_action,
            "settled_usd": self.settled_usd,
            "credit_usd": self.credit_usd,
            "exact": self.exact,
            "agreed": self.agreed,
            "note": self.note,
        }


def _for_a_live_store(envelope: Envelope) -> Envelope:
    """Re-stamp the corpus's frozen observation time, and only that one.

    ``bench/corpus.py`` builds its envelopes against a frozen clock
    (``corpus.NOW``) so the scorecard does not drift as real time passes. A live
    store has a real clock and journals every write with it, so a memory whose
    ``observed_at`` is that frozen literal is genuinely months old by the time
    layer 3 runs, and the gate correctly answers BACKDATED -- which would make
    every control fail for a reason that is about the fixture, not the gate.

    So an ``observed_at`` still holding the corpus default is replaced with now:
    a live store learns the memory at the moment it is written. Any case that
    chose its own ``observed_at`` keeps it untouched, which is precisely the set
    of cases whose attack *is* the clock -- backdating, masked backdating, an
    unparseable timestamp. Those must still fail, and they do.

    The digest covers the claim alone, so nothing that keys off it -- the
    feedback-hash stubs especially -- notices.
    """
    if envelope.provenance.observed_at != bench_corpus.NOW:
        return envelope
    return Envelope(
        claim=envelope.claim,
        provenance=replace(envelope.provenance, observed_at=utcnow()),
    )


def _materialise(store: AdmissibleStore, case: Any) -> None:
    """Put the case's declared store state into a real store.

    Each piece of ``store_state`` has a real mechanism behind it, and using the
    mechanism rather than a stub is the whole point of this layer -- a stub that
    reports a supersession proves the gate reads supersessions, and only a real
    ``supersede`` proves the store records them.

    ``flagged``            written through :class:`FlaggedActors` into the
                           ``flagged_actors`` table.
    ``superseded_claims``  the memory is written, superseded by an inert
                           correction, and then written again under a second
                           name. That second row is the replay the attack
                           describes: the store holds a live copy of a claim its
                           own journal records as invalidated.
    ``recorded_at``        needs nothing. The journal stamps the write with the
                           real clock, and the envelope's ``observed_at`` says
                           March, so the drift is genuine rather than declared.
    ``raw_body``          written straight through the client, because the point
                           of the case is a row that is not an envelope.
    """
    for address in case.store_state.get("flagged", []):
        FlaggedActors(store).flag_actor(
            address=address,
            reason="pre-registered corpus state: caught laundering a fabricated settlement",
            evidence={"case": case.id},
        )

    if case.envelope is None:
        body = case.store_state["raw_body"]
        store.client.set_entity(TESTIMONIAL_CATEGORY, f"{case.id}-raw", body)
        return

    envelope = _for_a_live_store(case.envelope)
    name = f"{case.id}-subject"
    if case.store_state.get("superseded_claims"):
        store.remember(TESTIMONIAL_CATEGORY, name, envelope)
        correction = Envelope(
            claim={
                "counterparty": envelope.claim.get("counterparty"),
                "outcome": "retracted",
                "amount_usd": 0.0,
                "note": "the earlier record was withdrawn",
            },
            provenance=Provenance(tier=Tier.HEARSAY, source="agent:self"),
        )
        store.supersede(TESTIMONIAL_CATEGORY, name, correction)
        store.remember(TESTIMONIAL_CATEGORY, f"{case.id}-replay", envelope)
        return

    store.remember(TESTIMONIAL_CATEGORY, name, envelope)


def run_graph_layer(money: list[MoneyResult]) -> list[GraphResult]:
    """Run the whole agent once per case, each against its own fresh database.

    One database per case because the corpus cases are not compatible with each
    other -- half of them are claims about the same stranger, and letting them
    accumulate would test a scenario nobody wrote down.
    """
    by_id = {result.case_id: result for result in money}
    results: list[GraphResult] = []
    workdir = Path(tempfile.mkdtemp(prefix="admissible-eval-"))
    try:
        for case in bench_corpus.CASES:
            expected = by_id[case.id].real_action
            counterparty, requested = request_for(case)
            db = workdir / f"{case.id}.db"
            store = AdmissibleStore.open(db)
            note = ""
            try:
                try:
                    _materialise(store, case)
                except Exception as exc:  # noqa: BLE001 - reported, never hidden
                    # A row the database itself refuses is a real outcome, not a
                    # skipped test. SQLite's json_valid CHECK rejects Infinity
                    # and NaN, so the canonicalisation attack cannot even be
                    # persisted -- the memory never exists for the gate to
                    # refuse, and no money can move on it.
                    note = f"store rejected the row: {type(exc).__name__}"
                agent = BuyerAgent(
                    store,
                    bench_run.StubChain(case),
                    rail=RefusingRail(),
                )
                record = agent.hire(
                    counterparty,
                    requested,
                    service="eval",
                    pitch="",
                    handle=None,
                )
                results.append(
                    GraphResult(
                        case_id=case.id,
                        is_control=case.is_control,
                        expected_action=expected,
                        got_action=record.action,
                        settled_usd=record.receipt.amount_usd,
                        credit_usd=record.decision.credit_usd,
                        note=note,
                    )
                )
            except Exception as exc:  # noqa: BLE001 - reported, never hidden
                results.append(
                    GraphResult(
                        case_id=case.id,
                        is_control=case.is_control,
                        expected_action=expected,
                        got_action="error",
                        settled_usd=0.0,
                        note=f"{type(exc).__name__}: {exc}",
                    )
                )
            finally:
                store.close()
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    return results


# ----------------------------------------------------------------------
# Scoring
# ----------------------------------------------------------------------
@dataclass
class Scorecard:
    verdicts: dict[str, Any]
    money: list[MoneyResult]
    graph: list[GraphResult] = field(default_factory=list)
    graph_ran: bool = True

    @property
    def verdict_agreement(self) -> tuple[int, int]:
        """How often layer 2's gate agreed with layer 1's, out of how many.

        Anything but a full match means ``bench/run.py`` and
        :func:`build_reference_gate` have drifted apart, and every number below
        layer 1 is then describing a different gate than the one layer 1 scored.
        It is checked rather than trusted, and it gates the overall pass.
        """
        by_id = {row["id"]: row["got"] for row in self.verdicts["detail"]}
        agreed = sum(
            1 for r in self.money if by_id.get(r.case_id) == r.real_verdict
        )
        return agreed, len(self.money)

    @property
    def attacks(self) -> list[MoneyResult]:
        return [r for r in self.money if not r.is_control]

    @property
    def controls(self) -> list[MoneyResult]:
        return [r for r in self.money if r.is_control]

    @property
    def attacks_caught(self) -> int:
        return sum(1 for r in self.attacks if r.attack_caught)

    @property
    def false_refusals(self) -> int:
        return sum(1 for r in self.controls if not r.control_undamaged)

    @property
    def money_at_risk_usd(self) -> float:
        """What the credulous agent hands over across all the attacks."""
        return round(sum(r.credulous_settled_usd for r in self.attacks), 6)

    @property
    def money_lost_usd(self) -> float:
        """What this agent hands over across all the attacks.

        Not zero, and it should not be reported as zero. A counterparty nobody
        has ever heard of draws the stranger ceiling, and several attacks end
        with the forged memory carrying no weight and the counterparty being
        treated as exactly what it is: a stranger. That exposure is a documented
        constant, not a breach, and :attr:`credit_bought_by_attacks_usd` is the
        number that says whether any of it was bought by a memory.
        """
        return round(sum(r.real_settled_usd for r in self.attacks), 6)

    @property
    def credit_bought_by_attacks_usd(self) -> float:
        """Credit the attack memories extended. The number that must be zero."""
        return round(sum(r.real_credit_usd for r in self.attacks), 6)

    @property
    def graph_agreed(self) -> int:
        return sum(1 for r in self.graph if r.agreed)

    @property
    def passed(self) -> bool:
        """Every layer, or nothing. A green light on one layer is not a result."""
        agreed, total = self.verdict_agreement
        gate_ok = bool(self.verdicts["pass"]) and agreed == total
        money_ok = self.attacks_caught == len(self.attacks) and self.false_refusals == 0
        graph_ok = (not self.graph_ran) or self.graph_agreed == len(self.graph)
        return gate_ok and money_ok and graph_ok

    def to_dict(self) -> dict[str, Any]:
        agreed, total = self.verdict_agreement
        return {
            "layer_1_verdicts": self.verdicts,
            "layer_2_money": {
                "verdict_agreement_with_layer_1": f"{agreed}/{total}",
                "attacks_total": len(self.attacks),
                "attacks_caught": self.attacks_caught,
                "controls_total": len(self.controls),
                "false_refusals": self.false_refusals,
                "money_at_risk_usd": self.money_at_risk_usd,
                "money_moved_on_attacks_usd": self.money_lost_usd,
                "credit_bought_by_attacks_usd": self.credit_bought_by_attacks_usd,
                "detail": [r.to_dict() for r in self.money],
            },
            "layer_3_agent": {
                "ran": self.graph_ran,
                "cases": len(self.graph),
                "agreed": self.graph_agreed,
                "exact_match_with_layer_2": sum(1 for r in self.graph if r.exact),
                "credit_bought_by_attacks_usd": round(
                    sum(r.credit_usd for r in self.graph if not r.is_control), 6
                ),
                "money_moved_on_attacks_usd": round(
                    sum(r.settled_usd for r in self.graph if not r.is_control), 6
                ),
                "detail": [r.to_dict() for r in self.graph],
            },
            "pass": self.passed,
        }


def render(card: Scorecard) -> None:
    shape = card.verdicts["corpus"]
    print("ADMISSIBLE -- END-TO-END SCORECARD")
    print(
        f"  corpus: {shape['total']} memories | {shape['attacks']} attacks across "
        f"{shape['families']} families | {shape['controls']} negative controls"
    )
    source = Path(bench_corpus.__file__).resolve().relative_to(REPO_ROOT)
    print(f"  cases and expected verdicts come from {source.as_posix()}, unmodified")
    print()

    print("LAYER 1  VERDICTS -- bench/run.py")
    print(
        f"  attacks caught with the exact expected verdict  "
        f"{card.verdicts['attacks_caught_exact']}/{card.verdicts['attacks_total']}"
    )
    print(f"  attacks refused for the wrong reason            "
          f"{card.verdicts['attacks_refused_wrong_reason']}")
    print(f"  attacks missed                                 {card.verdicts['attacks_missed']}")
    print(
        f"  controls admitted                              "
        f"{card.verdicts['controls_admitted']}/{card.verdicts['controls_total']}"
    )
    print()

    print("LAYER 2  MONEY -- gate, policy and the payment rail")
    print(
        f"  {'case':<34}{'kind':<9}{'this gate':<34}{'credulous agent'}"
    )
    print(f"  {'-' * (WIDTH - 2)}")
    for result in card.money:
        kind = "control" if result.is_control else "attack"
        mark = " " if (result.attack_caught and result.control_undamaged) else "!"
        real = result.real_action
        if result.real_settled_usd:
            real += f" ${result.real_settled_usd:,.2f}"
        real += f" ({result.real_verdict})"
        cred = result.credulous_action
        if result.credulous_settled_usd:
            cred += f" ${result.credulous_settled_usd:,.2f}"
        print(f" {mark}{result.case_id:<34}{kind:<9}{real:<34}{cred}")
    agreed, total = card.verdict_agreement
    print()
    print(f"  verdicts agreeing with layer 1     {agreed}/{total}")
    print(f"  attacks that bought no credit      {card.attacks_caught}/{len(card.attacks)}")
    print(f"  controls the gate damaged          {card.false_refusals}/{len(card.controls)}")
    print(f"  credulous agent hands over         ${card.money_at_risk_usd:,.2f}")
    print(f"  this agent hands over              ${card.money_lost_usd:,.2f}")
    print(
        f"  ...of which bought by a memory     "
        f"${card.credit_bought_by_attacks_usd:,.2f}   "
        f"(the rest is the ${bench_stranger_ceiling():.2f} stranger ceiling)"
    )
    print()

    if card.graph_ran:
        print("LAYER 3  AGENT -- the whole LangGraph agent, one store per case")
        for result in card.graph:
            mark = "ok  " if result.agreed else "DIFF"
            note = f"   [{result.note}]" if result.note else ""
            if not result.exact and result.agreed:
                note = note or "   [differs from layer 2, still bought nothing]"
            print(
                f"  [{mark}] {result.case_id:<34} layer 2 said "
                f"{result.expected_action:<7} agent did {result.got_action:<7}{note}"
            )
        print()
        print(f"  cases meeting the safety property  {card.graph_agreed}/{len(card.graph)}")
        print(
            f"  identical action to layer 2        "
            f"{sum(1 for r in card.graph if r.exact)}/{len(card.graph)}"
        )
        print(
            f"  credit bought by attack memories   "
            f"${sum(r.credit_usd for r in card.graph if not r.is_control):,.2f}"
        )
        print()
    else:
        print("LAYER 3  AGENT -- skipped (--no-graph)")
        print()

    print(
        f"  HEADLINE  {len(card.attacks)} attacks would have moved "
        f"${card.money_at_risk_usd:,.2f} through an agent that believes its own memory."
    )
    print(
        f"            Through this one they bought "
        f"${card.credit_bought_by_attacks_usd:,.2f} of credit and moved "
        f"${card.money_lost_usd:,.2f},"
    )
    print(
        f"            all of it the documented ${bench_stranger_ceiling():.2f} "
        f"a stranger draws before it has a history at all."
    )
    print()
    print("  RESULT:", "PASS" if card.passed else "FAIL")


def bench_stranger_ceiling() -> float:
    """The library's own stranger ceiling, read rather than restated."""
    from admissible.policy import STRANGER_CEILING_USD  # noqa: PLC0415

    return STRANGER_CEILING_USD


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--json", action="store_true", help="machine-readable scorecard")
    parser.add_argument(
        "--no-graph", action="store_true", help="skip layer 3, which opens a database per case"
    )
    args = parser.parse_args()

    verdicts = bench_run.scorecard(bench_run.run())
    money = run_money_layer()
    graph = [] if args.no_graph else run_graph_layer(money)
    card = Scorecard(verdicts=verdicts, money=money, graph=graph, graph_ran=not args.no_graph)

    if args.json:
        print(json.dumps(card.to_dict(), indent=2))
    else:
        render(card)
    return 0 if card.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
