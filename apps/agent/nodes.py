"""The eight nodes.

    perceive -> recall -> admit -> decide -> act -> attest -> reflect -> consolidate

Read the node bodies in order and the security argument reads itself: a model
runs in ``perceive`` and in ``attest``; the gate runs in ``admit``; the policy
runs in ``decide``; the rail runs in ``act`` and is handed exactly one object it
did not author. There is no edge from the first group to the last.

Reads and writes deliberately use two different doors, and the reason is not
tidiness:

* **Reads go through the LangGraph ``BaseStore``** -- ``SibylStore``, the
  first-party adapter -- because that is the memory surface the graph is built
  on and the point of using it. Its search is lexical FTS5, which the recall
  node uses as an extra sweep on top of the structured enumeration.
* **Writes go through ``AdmissibleStore``** because the adapter has no journal,
  and the journal is where the gate gets an honest clock. ``BaseStore.put`` is a
  bare ``set_entity``: it leaves no record of when the store learned something,
  and the backdating check compares a memory's self-asserted ``observed_at``
  against exactly that record. A write that skips the journal is a write with no
  independent timestamp, which is a gift to whoever is writing memories they
  want to look old.

Both doors are the same SQLite file, opened through the same ``MemoryClient``.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Callable

from admissible.consolidate import consolidate as fold_dossier
from admissible.consolidate import summarize
from admissible.envelope import Envelope, Evidence, Provenance, Tier, digest_of, utcnow
from admissible.flagged import FlaggedActors, FlagRecord, _norm_actor
from admissible.gate import AdmissionGate
from admissible.policy import Decision, TrustPolicy, laundering_attempts
from admissible.relations import SOURCED, VOUCHED_FOR, Relations
from admissible.store import AdmissibleStore, MalformedMemory
from admissible.wiring import StoreHistory
from langgraph.store.base import BaseStore

from ..addresses import OUR_AGENT, OUR_HANDLE
from .narrator import Narrator, Offer
from .posture import DECISION_OP, Posture, compute_posture, load_posture, store_posture
from .rails import PaymentRail, Receipt
from .state import (
    ACTOR_CATEGORY,
    DERIVED_CATEGORIES,
    DOSSIER_CATEGORY,
    INTERACTION_CATEGORY,
    RECALL_CATEGORIES,
    BuyerState,
)


@dataclass(frozen=True)
class AgentDeps:
    """Everything the nodes are allowed to touch, named in one place.

    Passed to :func:`build_nodes` and captured in closures rather than carried
    in the graph state. That is what keeps the rail out of reach: it exists in
    exactly one closure, ``act``, and no other node holds a reference to it.
    """

    store: AdmissibleStore
    gate: AdmissionGate
    history: StoreHistory
    flags: FlaggedActors
    relations: Relations
    narrator: Narrator
    rail: PaymentRail
    address: str = OUR_AGENT
    handle: str = OUR_HANDLE


def build_nodes(deps: AgentDeps) -> dict[str, Callable[..., dict[str, Any]]]:
    """Bind the dependencies into the eight node functions."""

    # ------------------------------------------------------------------
    def perceive(state: BuyerState) -> dict[str, Any]:
        """Turn an offer into a structured request, and ask the model what it thinks.

        The pitch is attacker-controlled text and it is handed to the model
        verbatim. That is not an oversight: the design assumes the model can be
        captured, and the demo prints the proposal next to the decision so a
        viewer can watch it happen without anything happening.
        """
        offer = Offer(
            counterparty=state["counterparty"],
            handle=state.get("counterparty_handle"),
            requested_usd=float(state["requested_usd"]),
            service=state.get("service", "unspecified"),
            pitch=state.get("pitch", ""),
        )
        proposal = deps.narrator.propose(offer)
        request = {
            "counterparty": offer.counterparty,
            "handle": offer.handle,
            "requested_usd": offer.requested_usd,
            "service": offer.service,
            "job": state.get("job") or {},
            "at": utcnow(),
        }
        return {
            "request": request,
            "proposal": proposal.to_dict(),
            "log": [
                f"perceive: {offer.service} from {_short(offer.counterparty)} for "
                f"${offer.requested_usd:.2f}; model proposes {proposal.action} "
                f"(advisory, source {proposal.source})"
            ],
        }

    # ------------------------------------------------------------------
    def recall(state: BuyerState, store: BaseStore) -> dict[str, Any]:
        """Pull every memory about this counterparty. Every one, not the good ones.

        Three sweeps, all through the LangGraph store:

        1. Structured enumeration of the interaction, testimonial and dossier
           namespaces, filtered on ``claim.counterparty``.
        2. A lexical FTS5 query on the counterparty's handle and address, which
           is what the adapter is actually good at, and which catches a memory
           filed under a namespace this node does not know about.
        3. The FLAGGED tier and the current trust posture, which are about the
           counterparty and about us respectively.

        Rows that do not parse as envelopes are collected separately rather than
        dropped. A row nobody can read is a fact about the store, and on an
        attack run it is frequently the most interesting fact in it.
        """
        counterparty = state["counterparty"]
        handle = state.get("counterparty_handle")

        seen: set[tuple[str, str]] = set()
        recalled: list[tuple[str, str, Envelope]] = []
        derived: list[tuple[str, str, Envelope]] = []
        malformed: list[dict[str, Any]] = []

        def take(category: str, name: str, body: Any) -> None:
            if (category, name) in seen:
                return
            seen.add((category, name))
            parsed = deps.store.parse_body(category, name, body)
            if isinstance(parsed, MalformedMemory):
                malformed.append(
                    {
                        "category": category,
                        "name": name,
                        "reason": parsed.reason,
                        "verdict": parsed.verdict.to_dict(),
                    }
                )
                return
            if parsed.claim.get("counterparty") != counterparty:
                return
            bucket = derived if category in DERIVED_CATEGORIES else recalled
            bucket.append((category, name, parsed))

        for category in RECALL_CATEGORIES:
            for item in store.search((category,), limit=1000):
                take(category, item.key, item.value)

        lexical = 0
        for needle in [n for n in (handle, counterparty) if n]:
            for item in store.search((), query=needle, limit=50):
                lexical += 1
                take("/".join(item.namespace), item.key, item.value)

        # Oldest observation first, then by location. The order the agent learned
        # things in is the order a reviewer reads them in, and it makes the lead
        # refusal in a decision the first attack that landed rather than whichever
        # row the database happened to hand back first. Ties break on the location
        # so two memories written in the same millisecond still order the same way
        # on every run -- a demo whose headline verdict depends on row order is a
        # demo that flakes.
        for bucket in (recalled, derived):
            bucket.sort(
                key=lambda item: (item[2].provenance.observed_at, item[0], item[1])
            )

        record = deps.flags.is_flagged(counterparty)
        posture = load_posture(deps.store)

        return {
            "recalled": recalled,
            "derived": derived,
            "malformed": malformed,
            "flagged": _flag_dict(record),
            "posture": posture.to_claim(),
            "log": [
                f"recall: {len(recalled)} memories, {len(derived)} derived records, "
                f"{len(malformed)} unreadable rows, {lexical} lexical hits; "
                f"counterparty {'FLAGGED' if record else 'not flagged'}; posture "
                f"ceiling ${posture.stranger_ceiling_usd:.4f}, witnessed weight "
                f"{posture.witnessed_weight}"
            ],
        }

    # ------------------------------------------------------------------
    def admit(state: BuyerState) -> dict[str, Any]:
        """Put every recalled memory through the gate, and keep the refusals.

        Nothing is filtered out. The refused memories travel on to the policy
        with their verdicts attached, because a decision that cannot show what it
        rejected is indistinguishable from a decision that never looked.

        The derived records -- the dossier -- go through the same gate and are
        reported with their verdicts, and they are kept out of the set the policy
        weighs. Two reasons, and both matter. A fold of memories is not a
        memory: letting it contribute credit would count its own inputs twice.
        And a dossier inherits the *strongest* evidence among its inputs while
        carrying none of their amounts, so a settlement-shaped verdict on it
        describes an arithmetic artefact rather than anybody's claim -- which,
        left in the weighed set, would read as a laundering attempt and refuse a
        counterparty for the crime of having been consolidated.
        """
        judged: list[tuple[Envelope, Any]] = [
            (envelope, deps.gate.admit(envelope))
            for _, _, envelope in state.get("recalled", [])
        ]
        judged_derived = [
            {
                "category": category,
                "name": name,
                "digest": envelope.digest,
                "tier": envelope.tier.value,
                "verdict": deps.gate.admit(envelope).to_dict(),
                "weighed": False,
            }
            for category, name, envelope in state.get("derived", [])
        ]
        admitted = sum(1 for _, verdict in judged if verdict.admits)
        codes = sorted({verdict.code.value for _, verdict in judged if not verdict.admits})
        return {
            "judged": judged,
            "judged_derived": judged_derived,
            "log": [
                f"admit: {admitted} admissible, {len(judged) - admitted} refused"
                + (f" ({', '.join(codes)})" if codes else "")
                + (
                    f"; {len(judged_derived)} derived record(s) judged and not weighed"
                    if judged_derived
                    else ""
                )
            ],
        }

    # ------------------------------------------------------------------
    def decide(state: BuyerState) -> dict[str, Any]:
        """Deterministic. No model, no network, no clock beyond the gate's.

        This node reads exactly three things: the judged memories, the flag on
        the counterparty, and the stored posture. It does not read
        ``state['proposal']``. That absence is the design -- and
        ``tests/test_model_cannot_pay.py`` asserts it by varying the proposal
        across the full range and requiring the decision to be byte-identical.
        """
        posture = Posture.from_claim(state.get("posture") or {})
        policy: TrustPolicy = posture.policy()
        decision = policy.decide(
            state["counterparty"],
            float(state["requested_usd"]),
            state.get("judged", []),
            flagged=state.get("flagged"),
        )
        return {
            "decision": decision,
            "log": [
                f"decide: {decision.action.upper()} -- {decision.explain}",
            ],
        }

    # ------------------------------------------------------------------
    def act(state: BuyerState) -> dict[str, Any]:
        """Hand the decision to the rail. One object, and the rail re-checks it.

        The rail is the only thing in this file that can move value and it is
        reachable from exactly this closure. It is given ``state['decision']``
        and nothing else -- not the amount, not the counterparty, not the
        request. If the decision is wrong, the payment is wrong; there is no
        third path where something else authorises a transfer.
        """
        receipt: Receipt = deps.rail.settle(state["decision"])
        settled = "settled" if receipt.settled else "no transfer"
        return {
            "receipt": receipt,
            "log": [
                f"act: {receipt.action} via {receipt.rail} ({settled})"
                + (f" tx {receipt.tx_hash[:12]}..." if receipt.tx_hash else "")
            ],
        }

    # ------------------------------------------------------------------
    def attest(state: BuyerState) -> dict[str, Any]:
        """Write the outcome back, and act on what the refusals revealed.

        Four writes, in this order and for these reasons:

        1. **The decision, into the journal.** ``reflect`` reads it back next
           node over, and a week from now it is the record that says what was
           known at the time.
        2. **The outcome, as a memory.** A settled payment is written ATTESTED
           with the transaction that settled it, so the next run re-derives it
           from chain rather than from our word. A refusal is written WITNESSED
           with no amount: it informs, it extends no credit.
        3. **Flags, for actors who presented forged evidence.** Not for actors
           whose evidence was merely thin -- ``laundering_attempts`` draws that
           line, and it is the difference between a counterparty to be careful
           with and an actor to stop listening to.
        4. **Edges**, so the flag propagates. The forged memory is linked to the
           actor that sourced it, and ``contaminated_by`` walks backwards along
           vouches to whoever put their name behind them. Blocking one address
           is worth much less than unwinding the ring that address belongs to.
        """
        decision: Decision = state["decision"]
        receipt: Receipt = state["receipt"]
        counterparty = decision.counterparty
        laundering = laundering_attempts(decision)

        deps.store.journal_write(
            DECISION_OP,
            counterparty=counterparty,
            action=decision.action,
            requested_usd=decision.requested_usd,
            unsecured_usd=decision.unsecured_usd,
            collateral_usd=decision.collateral_usd,
            credit_usd=decision.credit_usd,
            considered=len(decision.considered),
            admitted=len(decision.admitted),
            laundering=len(laundering),
            settled=receipt.settled,
            tx_hash=receipt.tx_hash,
            citations=decision.citations(),
        )

        written = _write_outcome(deps, state, decision, receipt)

        flags_raised: list[dict[str, Any]] = []
        contaminated: list[dict[str, Any]] = []
        for consideration in laundering:
            actor = consideration.envelope.provenance.actor_address
            handle = consideration.envelope.provenance.actor_handle
            if not (actor or handle):
                continue
            if deps.flags.is_flagged(actor or handle or ""):
                continue
            flag_id = deps.flags.flag_actor(
                address=actor,
                handle=handle,
                reason=(
                    f"laundered a memory into this store: "
                    f"{consideration.verdict.code.value} on {consideration.digest[:10]}"
                ),
                evidence={
                    "verdict": consideration.verdict.to_dict(),
                    "digest": consideration.digest,
                    "claim": consideration.envelope.claim,
                    "about": counterparty,
                    "requested_usd": decision.requested_usd,
                    "source": consideration.envelope.provenance.source,
                },
            )
            flags_raised.append(
                {
                    "flag_id": flag_id,
                    "actor_address": actor,
                    "actor_handle": handle,
                    "verdict": consideration.verdict.code.value,
                    "digest": consideration.digest,
                }
            )
            contaminated.extend(_unwind_ring(deps, state, actor))

        deps.history.invalidate()

        narration = deps.narrator.narrate(
            {
                "counterparty": counterparty,
                "action": decision.action,
                "requested_usd": decision.requested_usd,
                "unsecured_usd": decision.unsecured_usd,
                "collateral_usd": decision.collateral_usd,
                "admitted": len(decision.admitted),
                "refused": len(decision.refused),
                "refusal_codes": sorted(
                    {c.verdict.code.value for c in decision.refused}
                ),
                "counterparty_flagged": bool(state.get("flagged")),
                "flagged_actors": [f["actor_address"] for f in flags_raised],
                "settled_tx": receipt.tx_hash,
            }
        )

        return {
            "narration": narration,
            "flags_raised": flags_raised,
            "contaminated": contaminated,
            "log": [
                f"attest: wrote {written['category']}/{written['name']} as "
                f"{written['tier']}"
                + (
                    f"; flagged {len(flags_raised)} actor(s), "
                    f"{len(contaminated)} contaminated node(s)"
                    if flags_raised
                    else ""
                )
            ],
        }

    # ------------------------------------------------------------------
    def reflect(state: BuyerState) -> dict[str, Any]:
        """Review past decisions against what actually happened, and re-price trust.

        Reads the journal of every decision this agent has made and the tiers of
        every interaction it holds, computes two ratios, and writes the resulting
        posture back as a memory that supersedes the previous one. The next
        ``decide`` node loads it and builds its policy from it, so the change is
        not advice -- it is the parameter.

        Arithmetic on purpose, and bounded on purpose: the stranger ceiling can
        only move down from the library default. An adaptive parameter that can
        raise its own risk appetite is a ladder, and this system exists because
        attackers climb ladders.
        """
        before = Posture.from_claim(state.get("posture") or {})
        after = compute_posture(deps.store)
        store_posture(deps.store, after)
        deps.history.invalidate()

        moved = before.diff(after)
        detail = (
            "; ".join(f"{k} {v[0]} -> {v[1]}" for k, v in moved.items())
            if moved
            else "unchanged"
        )
        return {
            "posture_after": after.to_claim(),
            "log": [f"reflect: {detail} ({after.reason})"],
        }

    # ------------------------------------------------------------------
    def consolidate(state: BuyerState) -> dict[str, Any]:
        """Fold every interaction with this counterparty into one dossier.

        Arithmetic, not summarisation. A model-written summary of memories that
        may themselves have been planted is a new claim with no provenance, and
        the whole package is an argument against those. Counts and sums inherit
        the provenance of their inputs and can be recomputed by anyone holding
        the database.
        """
        dossier = fold_dossier(deps.store, state["counterparty"])
        deps.history.invalidate()
        return {
            "dossier": {
                "claim": dossier.claim,
                "tier": dossier.tier.value,
                "digest": dossier.digest,
                "summary": summarize(dossier),
            },
            "log": [f"consolidate: {summarize(dossier)}"],
        }

    return {
        "perceive": perceive,
        "recall": recall,
        "admit": admit,
        "decide": decide,
        "act": act,
        "attest": attest,
        "reflect": reflect,
        "consolidate": consolidate,
    }


# ----------------------------------------------------------------------
# Helpers. Kept out of the node bodies so the eight steps read as eight steps.
# ----------------------------------------------------------------------
def _write_outcome(
    deps: AgentDeps, state: BuyerState, decision: Decision, receipt: Receipt
) -> dict[str, Any]:
    """Record what happened as a memory the gate will judge on the next run.

    The tier is decided by the receipt, not by the agent's opinion of how it
    went. A settled payment carries the transaction that settled it and is
    written ATTESTED, because the next run can re-derive it from chain. Anything
    else is WITNESSED with ``amount_usd`` zero -- true, first-hand, and worth no
    credit, which is exactly what a refusal is worth.

    An escrow lands in the first branch, not the second, and that is correct
    rather than generous: its unsecured leg really did transfer, so there is a
    real settlement to cite. The memory records the collateral demanded
    alongside it, because "we paid five cents and asked for twenty in security"
    is a different fact from "we paid five cents".
    """
    counterparty = decision.counterparty
    service = state.get("service", "unspecified")

    if receipt.settled and receipt.tx_hash:
        claim: dict[str, Any] = {
            "counterparty": counterparty,
            "outcome": "settled",
            "action": decision.action,
            "amount_usd": receipt.amount_usd,
            # Consolidation folds Decimals from strings and refuses floats, so
            # the same number is carried twice, in the two forms its two readers
            # can each parse exactly.
            "amount": f"{receipt.amount_usd}",
            "asset": "USDC",
            "service": service,
            "collateral_usd": receipt.collateral_usd,
        }
        provenance = Provenance(
            tier=Tier.ATTESTED,
            source="x402:settlement",
            actor_address=deps.address,
            actor_handle=deps.handle,
            evidence=Evidence(
                chain_id=receipt.chain_id,
                tx_hash=receipt.tx_hash,
                block=receipt.block,
                kind="x402:settlement",
            ),
        )
    else:
        claim = {
            "counterparty": counterparty,
            "outcome": decision.action,
            "amount_usd": 0.0,
            "service": service,
            "requested_usd": decision.requested_usd,
            "refusal_codes": sorted({c.verdict.code.value for c in decision.refused}),
        }
        provenance = Provenance(
            tier=Tier.WITNESSED,
            source="agent:self",
            actor_address=deps.address,
            actor_handle=deps.handle,
        )

    envelope = Envelope(claim=claim, provenance=provenance)
    name = f"{counterparty}-{envelope.digest[2:12]}"
    deps.store.remember(INTERACTION_CATEGORY, name, envelope)
    return {
        "category": INTERACTION_CATEGORY,
        "name": name,
        "tier": envelope.tier.value,
        "digest": envelope.digest,
    }


def _unwind_ring(deps: AgentDeps, state: BuyerState, actor: str | None) -> list[dict[str, Any]]:
    """Link the flagged actor to what it sourced, then walk who vouched for it.

    Two steps, and the second is the one that pays. Linking the actor to its own
    forged claims is bookkeeping. Walking backwards along ``vouched_for`` finds
    the accomplice that never forged anything itself -- it only put its name
    behind somebody who did, which no per-claim check will ever catch, because
    per-claim the accomplice is clean.
    """
    if not actor:
        return []
    actor_ref = _ensure_actor_node(deps, actor)

    for category, name, envelope in state.get("recalled", []):
        source_address = envelope.provenance.actor_address
        if not source_address or _norm_actor(source_address) != _norm_actor(actor):
            continue
        try:
            deps.relations.relate(actor_ref, (category, name), SOURCED)
        except LookupError:
            # The memory row was superseded or renamed between recall and now.
            # An edge to a row that no longer exists is worse than no edge.
            continue

    out: list[dict[str, Any]] = []
    try:
        reached = deps.relations.contaminated_by(actor)
    except LookupError:
        return out

    for ref in reached:
        entry = {"category": ref.category, "name": ref.name}
        if ref.category == ACTOR_CATEGORY:
            record = deps.store.recall(ref.category, ref.name)
            address = (
                record.claim.get("address") if isinstance(record, Envelope) else ref.name
            )
            entry["address"] = address
            entry["reason"] = "vouched for a flagged actor"
            if address and not deps.flags.is_flagged(str(address)):
                entry["flag_id"] = deps.flags.flag_actor(
                    address=str(address),
                    handle=(
                        record.claim.get("handle") if isinstance(record, Envelope) else None
                    ),
                    reason=f"vouched for {actor}, which laundered a forged memory",
                    evidence={"contaminated_by": actor, "via": VOUCHED_FOR},
                )
        else:
            entry["reason"] = "sourced by a contaminated actor"
        out.append(entry)
    return out


def _ensure_actor_node(deps: AgentDeps, address: str) -> tuple[str, str]:
    """Resolve, or create, the graph node for an actor.

    The name is the normalised address, the same normalisation the FLAGGED tier
    uses, so a flag and a graph node always agree on what "the same address"
    means. Created lazily because an actor first becomes interesting at the
    moment it does something worth remembering.
    """
    name = _norm_actor(address) or address
    ref = (ACTOR_CATEGORY, name)
    if deps.store.recall(*ref) is None:
        deps.store.remember(
            ACTOR_CATEGORY,
            name,
            Envelope(
                claim={"kind": "actor", "address": address},
                provenance=Provenance(
                    tier=Tier.WITNESSED,
                    source="agent:self",
                    actor_address=deps.address,
                    actor_handle=deps.handle,
                ),
            ),
        )
    return ref


def _flag_dict(record: FlagRecord | None) -> dict[str, Any] | None:
    """A flag as plain data, so the decision's ``blocked_by`` reads cleanly."""
    if record is None:
        return None
    data = asdict(record)
    data["is_active"] = record.is_active
    return data


def _short(address: str | None) -> str:
    if not address:
        return "an unnamed counterparty"
    return f"{address[:6]}...{address[-4:]}" if len(address) > 12 else address


__all__ = ["AgentDeps", "build_nodes", "digest_of", "DOSSIER_CATEGORY"]
