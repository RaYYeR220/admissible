"""Score the gate against the adversarial corpus.

Run it:

    python bench/run.py            # human-readable scorecard
    python bench/run.py --json     # machine-readable, for the README badge

Every case is decided offline against stubs built from the case's own declared
chain and store state, so the scorecard is reproducible by anyone with the repo
and no keys, no funds and no network. The live counterpart -- the same gate
pointed at Base mainnet -- is ``scripts/live_proof.py``; this file is the part a
judge can re-run in ten seconds.

Two numbers matter and both are reported:

    caught     attacks correctly refused, and refused for the RIGHT reason
    false      sound memories wrongly refused

A gate that returns "no" to everything gets a perfect catch rate and a terrible
false rate. Reporting only the first would be the easiest lie in this repository,
so the exit code fails on either.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packages" / "admissible" / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from admissible.envelope import Envelope  # noqa: E402
from admissible.gate import (  # noqa: E402
    AdmissionGate,
    ChainUnreachable,
    FeedbackAttribution,
    SettlementFacts,
)
from admissible.verdicts import VerdictCode  # noqa: E402
from corpus import CASES, OUR_AGENT, Case, summary  # noqa: E402


class StubChain:
    """Chain state as the case declares it. No network, no keys.

    Deliberately dumb: it answers exactly what the case says the chain holds,
    which is what makes a failure here a failure of the gate's reasoning rather
    than of an RPC endpoint's mood.
    """

    def __init__(self, case: Case) -> None:
        self._case = case
        self._state = case.chain_state

    def verify_settlement(self, tx_hash: str, chain_id: int) -> SettlementFacts | None:
        if self._state.get("unreachable"):
            raise ChainUnreachable("stubbed outage")
        transfers = self._state.get("transfers", {})
        record = transfers.get(tx_hash)
        if record is None:
            return None
        return SettlementFacts(
            tx_hash=tx_hash,
            token=record["token"],
            sender=record["from"],
            recipient=record["to"],
            value=record["value"],
            block=record["block"],
            # A reverted transaction is a real transaction that moved nothing.
            # The stub can produce one because the gate has to refuse one.
            status=record.get("status", 1),
        )

    def read_feedback_hash(
        self, registry: str, agent_id: int, feedback_index: int, chain_id: int
    ) -> str | None:
        if self._state.get("unreachable"):
            raise ChainUnreachable("stubbed outage")
        if self._state.get("feedback_matches_digest"):
            # The honest case: what was committed onchain is the digest of this
            # very claim, which is the whole point of filling feedbackHash.
            return self._case.envelope.digest
        return self._state.get("feedback_hash")

    def attribute_feedback(
        self, registry: str, agent_id: int, feedback_index: int, chain_id: int
    ) -> FeedbackAttribution | None:
        """Who wrote the record, and what they had paid the agent when they did.

        A matching digest is only half the answer, so the stub has to be able to
        produce the other half: an author, the addresses that are the agent, and
        the settlement behind the review if there is one.
        """
        if self._state.get("unreachable"):
            raise ChainUnreachable("stubbed outage")
        digest = self.read_feedback_hash(registry, agent_id, feedback_index, chain_id)
        if digest is None:
            return None
        paid = self._state.get("feedback_settlement") or {}
        return FeedbackAttribution(
            agent_id=agent_id,
            feedback_index=feedback_index,
            author=self._state.get("feedback_author", ""),
            feedback_hash=digest,
            subject_wallets=tuple(self._state.get("feedback_subject_wallets", ())),
            settlement_tx=paid.get("tx"),
            settlement_token=paid.get("token"),
            settled_value=paid.get("value", 0),
        )


class StubFlags:
    def __init__(self, case: Case) -> None:
        self._flagged = {a.lower() for a in case.store_state.get("flagged", [])}

    def is_flagged(self, identifier: str):
        if identifier.lower() in self._flagged:
            return {"actor": identifier, "reason": "laundered a fabricated settlement"}
        return None


class StubHistory:
    def __init__(self, case: Case) -> None:
        state = case.store_state
        self._superseded = {
            Envelope(claim=c, provenance=case.envelope.provenance).digest
            for c in state.get("superseded_claims", [])
        } if case.envelope is not None else set()
        self._recorded_at = state.get("recorded_at")

    def superseding_digest(self, digest: str) -> str | None:
        return "0x" + "fe" * 32 if digest in self._superseded else None

    def recorded_at(self, digest: str) -> str | None:
        return self._recorded_at


@dataclass
class Result:
    case: Case
    got: VerdictCode
    explain: str

    @property
    def ok(self) -> bool:
        return self.got is self.case.expect


def run() -> list[Result]:
    results: list[Result] = []
    for case in CASES:
        gate = AdmissionGate(
            chain=StubChain(case),
            flags=StubFlags(case),
            history=StubHistory(case),
            # The agent's own wallet. Supplying it is what lets the gate tell
            # "this settlement happened" from "this settlement happened to us",
            # which is the difference between a track record and a counterparty
            # moving money between two addresses it owns.
            self_address=OUR_AGENT,
            # Frozen so the corpus does not silently pass or fail as real time
            # moves through the validity windows the cases declare.
            now=lambda: "2026-09-08T20:00:00.000Z",
        )
        subject = (
            case.store_state["raw_body"]
            if case.envelope is None
            else case.envelope.to_body()
        )
        verdict = gate.admit(subject)
        results.append(Result(case=case, got=verdict.code, explain=str(verdict)))
    return results


def scorecard(results: list[Result]) -> dict:
    attacks = [r for r in results if not r.case.is_control]
    controls = [r for r in results if r.case.is_control]
    caught = [r for r in attacks if r.ok]
    # A refusal for the wrong reason still stopped the payment, so it is tracked
    # separately rather than scored as a clean catch. Being right by accident is
    # not the same as being right.
    wrong_reason = [
        r for r in attacks if not r.ok and r.got is not VerdictCode.ADMISSIBLE
    ]
    missed = [r for r in attacks if r.got is VerdictCode.ADMISSIBLE]
    false_refusals = [r for r in controls if not r.ok]
    return {
        "corpus": summary(),
        "attacks_total": len(attacks),
        "attacks_caught_exact": len(caught),
        "attacks_refused_wrong_reason": len(wrong_reason),
        "attacks_missed": len(missed),
        "controls_total": len(controls),
        "controls_admitted": len(controls) - len(false_refusals),
        "false_refusals": len(false_refusals),
        "pass": not missed and not false_refusals and not wrong_reason,
        "detail": [
            {
                "id": r.case.id,
                "family": r.case.family,
                "expected": r.case.expect.value,
                "got": r.got.value,
                "ok": r.ok,
            }
            for r in results
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args()

    results = run()
    card = scorecard(results)

    if args.json:
        print(json.dumps(card, indent=2))
        return 0 if card["pass"] else 1

    shape = card["corpus"]
    print("ADMISSIBILITY SCORECARD")
    print(
        f"  corpus: {shape['total']} memories | {shape['attacks']} attacks across "
        f"{shape['families']} families | {shape['controls']} negative controls"
    )
    print(f"  {shape['offline_decidable']} of them are refused before any chain call\n")
    for r in results:
        mark = "pass" if r.ok else "FAIL"
        kind = "control" if r.case.is_control else "attack "
        print(f"  [{mark}] {kind} {r.case.id:30s} expected {r.case.expect.value:24s} got {r.got.value}")
    print()
    print(
        f"  attacks caught (exact reason)  {card['attacks_caught_exact']}/{card['attacks_total']}"
    )
    print(f"  attacks refused, wrong reason  {card['attacks_refused_wrong_reason']}")
    print(f"  attacks MISSED                 {card['attacks_missed']}")
    print(
        f"  controls admitted              {card['controls_admitted']}/{card['controls_total']}"
    )
    print(f"  false refusals                 {card['false_refusals']}")
    print()
    print("  RESULT:", "PASS" if card["pass"] else "FAIL")
    return 0 if card["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
