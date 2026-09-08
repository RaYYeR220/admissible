"""Admissible: the whole story, in one command, with no keys and no network.

    python scripts/demo.py

That runs session 1 in this process, then spawns session 2 and the deletion test
as genuinely separate processes, so a judge sees the cold-start property rather
than being told about it. Every block prints the process id and a UTC timestamp.

Beats
-----
1. NEGATIVE CONTROL   a counterparty with real settled history. The gate
                      re-derives every memory from the chain and the agent pays.
2. ATTACK             the poisoner launders a fabricated settlement about a
                      stranger, seconds before that stranger is due to be paid.
3. REFUSAL            evidence_not_found. The policy refuses outright -- not
                      escrow -- flags the poisoner by address, and walks the
                      relations graph to the accomplice that only ever vouched.
4. FRESH SESSION      a second process opens the same file. The poisoner returns
                      with a fresh set of unfalsifiable first-person claims and
                      is refused on sight, from memory alone.
5. DELETION TEST      delete the database, replay beats 1 through 4. The attack
                      that memory stopped now succeeds and money moves.

Flags
-----
``--offline``        recorded chain fixtures. Default. No network, no keys, no funds.
``--live``           inject a reader pointed at Base mainnet instead.
``--venice``         narrate with a model. Advisory either way; the decisions do
                     not move, which is the point.
``--session N``      run one session only (1, 2 or 5), for filming.
``--delete-memory``  destroy the store and replay. This is beat 5 on its own.
``--json``           emit the whole run as one JSON document.
``--db PATH``        where the store lives.

What is real and what is not
----------------------------
Stated here so nobody has to infer it. The admission gate, the trust policy, the
memory store, the FLAGGED tier, the relations walk, the bi-temporal journal and
the reflection loop are the real implementations from ``packages/admissible``.

The chain is a recorded fixture file -- ``apps/fixtures/base-mainnet.json``,
marked synthetic in its own provenance block -- and the payment rail simulates
settlement into it rather than broadcasting a transaction. ``--live`` swaps the
reader for Base mainnet and proves the gate reads the real chain through the
same protocol; it does *not* replay this scenario, because the fixtures were
never mined and this build holds no funds. The rail stays simulated either way.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from apps import REPO_ROOT  # noqa: E402  -- puts packages/admissible/src on the path
from admissible.store import AdmissibleStore  # noqa: E402  -- and so must follow it
from apps.addresses import (  # noqa: E402
    POISONER,
    POISONER_HANDLE,
    SIBYLCAP,
    SIBYLCAP_HANDLE,
    STRANGER,
    STRANGER_HANDLE,
)
from apps.agent.narrator import build_narrator  # noqa: E402
from apps.agent.posture import Posture  # noqa: E402
from apps.agent.rails import SimulatedRail  # noqa: E402
from apps.agent.runtime import BuyerAgent, RunRecord  # noqa: E402
from apps.counterparty import (  # noqa: E402
    CounterpartyAgent,
    Job,
    promote_to_attested,
    record_outcome,
)
from apps.poisoner import PoisonerAgent  # noqa: E402
from apps.recorded_chain import RecordedChain, live_chain  # noqa: E402

DEFAULT_DB = REPO_ROOT / ".demo" / "admissible-demo.db"
WIDTH = 78

#: The job the buyer actually wants done. Small, checkable, and the same every
#: run, because a demo whose input varies is a demo whose output cannot be diffed.
JOB_PAYLOAD = (
    "Summarise the measured rate of ERC-8004 feedback records that carry a "
    "payment proof on Base."
)


# ----------------------------------------------------------------------
# Output
# ----------------------------------------------------------------------
@dataclass
class Report:
    """Collects everything printed, so ``--json`` is the same run, not a second one."""

    session: int
    pid: int
    started_at: str
    mode: str
    db: str
    beats: list[dict[str, Any]] = field(default_factory=list)
    children: list[dict[str, Any]] = field(default_factory=list)
    verdict: dict[str, Any] = field(default_factory=dict)

    def add(self, beat: dict[str, Any]) -> dict[str, Any]:
        self.beats.append(beat)
        return beat

    def to_dict(self) -> dict[str, Any]:
        return {
            "session": self.session,
            "pid": self.pid,
            "started_at": self.started_at,
            "mode": self.mode,
            "db": self.db,
            "beats": self.beats,
            "children": self.children,
            "verdict": self.verdict,
        }


class Printer:
    """Blocks with labels. Silenced entirely by ``--json``."""

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled

    def block(self, label: str, subtitle: str = "") -> None:
        if not self.enabled:
            return
        print()
        print("=" * WIDTH)
        print(f"  {label}")
        if subtitle:
            print(f"  {subtitle}")
        print("=" * WIDTH)
        # Flushed on every block boundary. Python block-buffers stdout when it is
        # a pipe, so without this a `demo.py | tee` shows the child processes'
        # output before the parent's and the beats read out of order -- which is
        # a confusing thing to happen in a demo about ordering.
        sys.stdout.flush()

    def line(self, text: str = "") -> None:
        if self.enabled:
            print(text)

    def kv(self, key: str, value: Any) -> None:
        if self.enabled:
            print(f"    {key:<26} {value}")

    def bullet(self, text: str) -> None:
        if self.enabled:
            print(f"    - {text}")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def stamp(printer: Printer, session: int, mode: str, db: Path) -> dict[str, Any]:
    """Prove which process this is. Beats 1 and 4 must be visibly different ones."""
    info = {
        "session": session,
        "pid": os.getpid(),
        "utc": utc_now(),
        "mode": mode,
        "db": str(db),
        "db_exists": db.exists(),
        "db_bytes": db.stat().st_size if db.exists() else 0,
    }
    printer.block(
        f"SESSION {session}  pid {info['pid']}  {info['utc']}",
        f"chain: {mode} | store: {db} "
        f"({'exists, ' + str(info['db_bytes']) + ' bytes' if db.exists() else 'absent'})",
    )
    return info


# ----------------------------------------------------------------------
# Wiring
# ----------------------------------------------------------------------
def build_chain(mode: str, db: Path, printer: Printer | None = None) -> Any:
    """Recorded fixtures by default; a live reader only when asked for one.

    The overlay lives beside the database but is emphatically not part of it.
    Deleting the agent's memory must not delete the chain -- the evidence is
    still there in beat 5, the agent has simply lost the record that told it
    where to look, and that distinction is the point of the beat.
    """
    if mode != "live":
        return RecordedChain.load(overlay=db.parent / "chain-overlay.json")

    reader = live_chain()
    if printer is not None:
        # Said before anything runs, because in live mode the story does not
        # play out and a viewer who was not told would reasonably read that as
        # the demo being broken.
        printer.block(
            "LIVE MODE  the same gate, pointed at Base mainnet",
            "read this before the beats: the scenario will not complete, on purpose",
        )
        printer.line()
        printer.line(
            "    The seeded history cites transactions from apps/fixtures/base-mainnet.json,"
        )
        printer.line(
            "    which is marked synthetic in its own provenance block: none of them was"
        )
        printer.line(
            "    ever mined. Against the real chain the gate re-derives every one of them"
        )
        printer.line("    and correctly answers evidence_not_found.")
        printer.line()
        printer.line(
            "    So --live proves one thing and does not prove another. It proves the"
        )
        printer.line(
            "    admission gate reads Base, over the network, through the same protocol"
        )
        printer.line(
            "    the fixtures satisfy. It does not replay the scenario, because this"
        )
        printer.line(
            "    build holds no funds and has settled nothing onchain to replay."
        )
        printer.line()
        printer.line("    Run without --live for the scenario.")
    return reader


def open_agent(db: Path, chain: Any, *, offline: bool) -> BuyerAgent:
    db.parent.mkdir(parents=True, exist_ok=True)
    return BuyerAgent(
        AdmissibleStore.open(db),
        chain,
        rail=SimulatedRail(chain),
        narrator=build_narrator(offline=offline),
    )


def seed_history(agent: BuyerAgent, chain: RecordedChain, printer: Printer) -> dict[str, Any]:
    """Give the honest counterparty the settled history it really has.

    Written now, because the demo starts from an empty store, and honest about
    it: ``observed_at`` is this moment and ``valid_from`` is thirty days ago.
    Those are the two clocks doing exactly what they exist for -- when we learned
    it, versus when it was true. Backdating ``observed_at`` instead would trip
    the gate's own backdating check, which is a nice demonstration that the check
    works but a poor way to seed a demo.

    Each seeded memory cites a settlement in the recorded chain, so the gate
    re-derives all three rather than taking the seed's word for it.
    """
    seller = CounterpartyAgent()
    seeded: list[dict[str, Any]] = []
    past = "2026-08-09T00:00:00.000Z"

    for service, tx_hash in (
        ("lookup", "0x" + "66" * 32),
        ("research-brief", "0x" + "55" * 32),
        ("deep-report", "0x" + "aa" * 32),
    ):
        transfer = chain.settlement(tx_hash) if isinstance(chain, RecordedChain) else None
        amount = seller.quote(service)
        job = Job(service=service, payload=JOB_PAYLOAD, requested_usd=amount)
        result = seller.perform(job)
        category, name, _ = record_outcome(agent.store, result)
        envelope = promote_to_attested(
            agent.store,
            category,
            name,
            counterparty=seller.address,
            amount_usd=amount,
            tx_hash=tx_hash,
            block=transfer.block if transfer else None,
            service=service,
            valid_from=past,
        )
        seeded.append(
            {
                "service": service,
                "amount_usd": amount,
                "tx_hash": tx_hash,
                "digest": envelope.digest,
                "tier": envelope.tier.value,
            }
        )
    agent.history.invalidate()

    printer.line()
    printer.line(
        "  PRIOR HISTORY (seeded now; each record cites a settlement the gate re-reads)"
    )
    for row in seeded:
        printer.bullet(
            f"{row['service']:<15} ${row['amount_usd']:.2f}  {row['tier']}  "
            f"tx {row['tx_hash'][:14]}..."
        )
    printer.kv("total attested", f"${sum(r['amount_usd'] for r in seeded):.2f}")
    return {"seeded": seeded, "total_usd": sum(r["amount_usd"] for r in seeded)}


# ----------------------------------------------------------------------
# Rendering one run
# ----------------------------------------------------------------------
def show_run(printer: Printer, record: RunRecord, *, show_memories: bool = True) -> None:
    printer.line()
    printer.kv("counterparty", f"{record.counterparty} ({record.service})")
    printer.kv("requested", f"${record.requested_usd:.2f}")
    printer.kv(
        "model proposal",
        f"{record.proposal.get('action', '?').upper()}  "
        f"[advisory, {record.proposal.get('source', '?')}"
        + (", saw an injection" if record.proposal.get("saw_injection") else "")
        + "]",
    )
    if record.proposal.get("rationale"):
        printer.kv("  model says", _clip(record.proposal["rationale"], 60))

    if show_memories and record.considered:
        printer.line()
        printer.line("    memories considered (refused ones are kept, not hidden):")
        for item in record.considered:
            mark = "ADMIT " if item["verdict"]["admits"] else "REFUSE"
            printer.line(
                f"      [{mark}] {item['digest'][:10]}  {item['tier']:<9} "
                f"{item['verdict']['code']:<22} weight ${item['weight_usd']:.4f}"
            )
            printer.line(
                f"               source {item['source']} via "
                f"{_short(item['actor'])}"
            )
    for row in record.malformed:
        printer.line(
            f"      [REFUSE] {row['category']}/{row['name']}  malformed: {row['reason'][:44]}"
        )

    printer.line()
    printer.kv("POLICY DECISION", record.action.upper())
    printer.kv("  explain", _clip(record.decision.explain, 60))
    printer.kv(
        "  money",
        f"unsecured ${record.decision.unsecured_usd:.2f} | "
        f"collateral ${record.decision.collateral_usd:.2f} | "
        f"settled ${record.settled_usd:.2f}",
    )
    if record.decision.blocked_by:
        printer.kv("  blocked by", _clip(json.dumps(record.decision.blocked_by), 60))
    if record.receipt.tx_hash:
        printer.kv("  settlement tx", record.receipt.tx_hash)
    cited = ", ".join(d[:10] for d in record.decision.citations()) or "none"
    # On a refusal these are memories that carried weight and were overridden,
    # not memories the decision rested on. Saying so matters: a refusal that
    # listed "citations" would read as though something had been drawn on.
    label = "  drawn on" if record.action != "refuse" else "  weighed, then overridden"
    printer.kv(label, cited)
    printer.kv("narration", _clip(record.narration, 60))

    if record.proposal.get("action") != record.action:
        printer.line()
        printer.line(
            f"    NOTE  the model proposed {record.proposal.get('action', '?').upper()} "
            f"and the agent did {record.action.upper()}. The model's output reaches"
        )
        printer.line(
            "          the log and nothing else; the rail takes a Decision it did "
            "not author."
        )


def run_summary(record: RunRecord) -> dict[str, Any]:
    return {
        "counterparty": record.counterparty,
        "requested_usd": record.requested_usd,
        "action": record.action,
        "settled_usd": record.settled_usd,
        "proposal": record.proposal,
        "explain": record.decision.explain,
        "blocked_by": record.decision.blocked_by,
        "citations": record.decision.citations(),
        "considered": record.considered,
        "malformed": record.malformed,
        "flags_raised": record.flags_raised,
        "contaminated": record.contaminated,
        "posture_before": record.posture_before,
        "posture_after": record.posture_after,
        "narration": record.narration,
        "log": record.log,
        "receipt": record.receipt.to_dict(),
    }


# ----------------------------------------------------------------------
# Beats
# ----------------------------------------------------------------------
def beat_control(agent: BuyerAgent, printer: Printer) -> tuple[RunRecord, dict[str, Any]]:
    seller = CounterpartyAgent()
    printer.block(
        "BEAT 1  NEGATIVE CONTROL",
        "a counterparty with real settled history, re-derived from the chain",
    )
    record = agent.hire(
        seller.address,
        seller.quote("research-brief"),
        service="research-brief",
        pitch=seller.pitch("research-brief"),
        handle=SIBYLCAP_HANDLE,
        job={"payload": JOB_PAYLOAD},
    )
    show_run(printer, record)
    return record, {
        "beat": 1,
        "name": "negative_control",
        "expected": "pay",
        "got": record.action,
        "ok": record.action == "pay",
        "run": run_summary(record),
    }


def beat_attack(agent: BuyerAgent, printer: Printer) -> dict[str, Any]:
    """The poisoner writes into the buyer's memory, seconds before a payment."""
    poisoner = PoisonerAgent()
    job = Job(service="research-brief", payload=JOB_PAYLOAD, requested_usd=poisoner.price_usd)

    printer.block(
        "BEAT 2  ATTACK",
        f"{POISONER_HANDLE} launders a settlement about {STRANGER_HANDLE} into the "
        "same store",
    )
    printer.line()
    printer.line("    two agents, one memory store. the adversary writes; the buyer reads.")
    printer.line()

    result, vector_one = poisoner.poisoned_job_result(agent.store, job)
    vector_two = poisoner.peer_reference(agent.store)
    document, vector_three = poisoner.tool_output_injection(agent.store)
    agent.history.invalidate()

    laundered = [vector_one, vector_two, vector_three]
    for entry in laundered:
        printer.line(f"    VECTOR  {entry.vector}")
        printer.kv("  wrote", f"{entry.category}/{entry.name}")
        printer.kv("  as", f"{entry.envelope.tier.value} via {entry.envelope.provenance.source}")
        printer.kv("  actor", _short(entry.envelope.provenance.actor_address))
        printer.kv("  evidence", json.dumps(entry.envelope.provenance.evidence.to_dict()) or "{}")
        printer.kv("  intent", _clip(entry.intent, 58))
        printer.line()

    printer.kv("job delivered", f"{result.delivered} ({result.artifact.get('words')} words)")
    printer.kv("document fetched", document["url"])
    printer.line()
    printer.line("    the fetched document also carries this, aimed at the model:")
    printer.line(f'      "{_clip(document["body"].splitlines()[-1], 66)}"')

    return {
        "beat": 2,
        "name": "attack",
        "vectors": [entry.to_dict() for entry in laundered],
        "job_delivered": result.delivered,
        "document_url": document["url"],
    }


def beat_refusal(agent: BuyerAgent, printer: Printer) -> tuple[RunRecord, dict[str, Any]]:
    poisoner = PoisonerAgent()
    printer.block(
        "BEAT 3  REFUSAL",
        f"the buyer is about to pay {STRANGER_HANDLE}. the gate reads the chain first.",
    )
    record = agent.hire(
        STRANGER,
        0.25,
        service="research-brief",
        pitch=poisoner.pitch(),
        handle=STRANGER_HANDLE,
        job={"payload": JOB_PAYLOAD},
    )
    show_run(printer, record)

    codes = [
        item["verdict"]["code"] for item in record.considered if not item["verdict"]["admits"]
    ]
    printer.line()
    printer.line("    THE RING")
    for flag in record.flags_raised:
        printer.bullet(
            f"FLAGGED {flag['actor_address']} ({flag['actor_handle']}) "
            f"on {flag['verdict']}, evidence digest {flag['digest'][:12]}"
        )
    for node in record.contaminated:
        printer.bullet(f"contaminated {node['category']}/{node['name']}")
        printer.line(f"        {node['reason']}")
    if not record.contaminated:
        printer.bullet("no contamination reachable from the flagged address")

    before = Posture.from_claim(record.posture_before)
    after = Posture.from_claim(record.posture_after)
    printer.line()
    printer.line("    POSTURE (reflect wrote this back to memory; decide reads it next run)")
    printer.kv(
        "stranger ceiling",
        f"${before.stranger_ceiling_usd:.4f} -> ${after.stranger_ceiling_usd:.4f}",
    )
    printer.kv("witnessed weight", f"{before.witnessed_weight} -> {after.witnessed_weight}")
    printer.kv("computed from", after.reason)

    probe_before, probe_after = _posture_probe(before, after)
    printer.line()
    printer.line("    POSTURE PROBE -- the same offer from an unknown address, both ways")
    printer.kv("under the old posture", f"{probe_before['action'].upper()} "
               f"(${probe_before['unsecured_usd']:.4f} unsecured)")
    printer.kv("under the new posture", f"{probe_after['action'].upper()} "
               f"(${probe_after['unsecured_usd']:.4f} unsecured)")

    return record, {
        "beat": 3,
        "name": "refusal",
        "expected": "refuse",
        "got": record.action,
        "ok": record.action == "refuse",
        "evidence_not_found_present": "evidence_not_found" in codes,
        "refusal_codes": codes,
        "flags_raised": record.flags_raised,
        "contaminated": record.contaminated,
        "posture_probe": {"before": probe_before, "after": probe_after},
        "run": run_summary(record),
    }


def _posture_probe(before: Posture, after: Posture) -> tuple[dict[str, Any], dict[str, Any]]:
    """The same request, decided under both postures. No writes, no side effects.

    A stranger nobody has ever heard of asks for twenty cents. Under the old
    posture that is an escrow -- a small unsecured line plus collateral for the
    rest. Under the posture reflect just computed, the unsecured line is closed
    and the same request is refused. Same policy, same memories, different
    parameter, different action: that is what "the agent learned something"
    means here.
    """

    def decide(posture: Posture) -> dict[str, Any]:
        decision = posture.policy().decide(
            "0x0000000000000000000000000000000000000001", 0.20, []
        )
        return {
            "action": decision.action,
            "unsecured_usd": decision.unsecured_usd,
            "collateral_usd": decision.collateral_usd,
            "stranger_ceiling_usd": posture.stranger_ceiling_usd,
            "explain": decision.explain,
        }

    return decide(before), decide(after)


def beat_return(agent: BuyerAgent, printer: Printer) -> tuple[RunRecord, dict[str, Any]]:
    """The poisoner comes back in a new process and is refused from memory alone."""
    poisoner = PoisonerAgent()
    printer.block(
        "BEAT 4  FRESH SESSION",
        "different process, same file. the poisoner returns and sells directly.",
    )
    flags = agent.flags.list_flags()
    printer.line()
    printer.line("    what this process knew before it did anything (cold start):")
    for flag in flags:
        printer.bullet(
            f"FLAGGED {flag.actor_address} ({flag.actor_handle}) -- {_clip(flag.reason, 46)}"
        )
    printer.kv("flags loaded", len(flags))
    printer.kv("posture loaded", f"ceiling ${agent.posture().stranger_ceiling_usd:.4f}")

    planted = poisoner.return_visit(agent.store)
    agent.history.invalidate()
    printer.line()
    printer.kv(
        "poisoner plants",
        f"{len(planted)} WITNESSED notes about itself, signed with the BUYER's address "
        f"(${sum(float(m.envelope.claim['amount_usd']) for m in planted):.2f} of asserted work)",
    )
    printer.line(
        "    it holds the store, and actor_address is a string. these are written to"
    )
    printer.line(
        "    look like the buyer's own notes about jobs it ran, and the gate ADMITS"
    )
    printer.line(
        "    them -- no envelope can tell an observation you made from one somebody"
    )
    printer.line("    else typed into your store. watch what refuses the payment anyway.")

    record = agent.hire(
        POISONER,
        0.25,
        service="research-brief",
        pitch=poisoner.pitch(),
        handle=POISONER_HANDLE,
        job={"payload": JOB_PAYLOAD},
    )
    show_run(printer, record)

    return record, {
        "beat": 4,
        "name": "returning_poisoner",
        "expected": "refuse",
        "got": record.action,
        "ok": record.action == "refuse",
        "flags_at_cold_start": [
            {"address": f.actor_address, "handle": f.actor_handle, "reason": f.reason}
            for f in flags
        ],
        "planted": [m.to_dict() for m in planted],
        "run": run_summary(record),
    }


# ----------------------------------------------------------------------
# Sessions
# ----------------------------------------------------------------------
def session_one(db: Path, mode: str, printer: Printer, *, offline: bool) -> Report:
    """Beats 1 to 3, from an empty store.

    The database is removed first, every time. A demo that depends on leftover
    state from the last run is a demo that eventually contradicts itself in front
    of an audience.
    """
    _remove_db(db)
    chain = build_chain(mode, db, printer)
    report = Report(session=1, pid=os.getpid(), started_at=utc_now(), mode=mode, db=str(db))
    info = stamp(printer, 1, mode, db)
    report.beats.append({"beat": 0, "name": "process", **info})

    agent = open_agent(db, chain, offline=offline)
    try:
        report.add({"beat": 0, "name": "seed", **seed_history(agent, chain, printer)})
        _, control = beat_control(agent, printer)
        report.add(control)
        report.add(beat_attack(agent, printer))
        _, refusal = beat_refusal(agent, printer)
        report.add(refusal)
        report.verdict = {
            "paid_honest_counterparty": control["ok"],
            "refused_the_attack": refusal["ok"],
            "evidence_not_found_raised": refusal["evidence_not_found_present"],
            "actors_flagged_directly": len(refusal["flags_raised"]),
            "ring_nodes": len(refusal["contaminated"]),
            "flags_held": len(agent.flags.list_flags()),
        }
    finally:
        agent.close()

    printer.block(
        "SESSION 1 DONE",
        "this process is finished writing and is about to exit the store",
    )
    printer.kv("store closed at", utc_now())
    printer.kv("store on disk", f"{db} ({db.stat().st_size} bytes)")
    printer.line()
    printer.line("    everything the next process knows, it will read from that file.")
    return report


def session_two(db: Path, mode: str, printer: Printer, *, offline: bool) -> Report:
    """Beat 4, in a process that has never seen any of this before."""
    chain = build_chain(mode, db, printer)
    report = Report(session=2, pid=os.getpid(), started_at=utc_now(), mode=mode, db=str(db))
    info = stamp(printer, 2, mode, db)
    report.beats.append({"beat": 0, "name": "process", **info})

    if not db.exists():
        printer.line()
        printer.line("    no store at that path. run session 1 first.")
        report.verdict = {"error": "no store"}
        return report

    agent = open_agent(db, chain, offline=offline)
    try:
        _, returning = beat_return(agent, printer)
        report.add(returning)
        report.verdict = {
            "refused_on_sight": returning["ok"],
            "flags_at_cold_start": len(returning["flags_at_cold_start"]),
        }
    finally:
        agent.close()
    return report


def session_deleted(db: Path, mode: str, printer: Printer, *, offline: bool) -> Report:
    """Beat 5. Destroy the memory, replay the story, count what changed.

    The database is deleted. The chain overlay is not: the evidence still
    exists, the agent has simply lost the record that told it where to look.
    That separation is what makes the result readable -- the half of the defence
    that is arithmetic over chain state survives, and the half that is memory
    does not.
    """
    report = Report(session=5, pid=os.getpid(), started_at=utc_now(), mode=mode, db=str(db))
    printer.block(
        "BEAT 5  DELETION TEST",
        "delete the agent's memory and replay the same attack",
    )
    removed = _remove_db(db)
    printer.line()
    printer.kv("deleted", f"{db} ({removed} bytes)" if removed else f"{db} (was absent)")
    printer.kv("chain overlay", "NOT deleted -- the chain is not the agent's memory")
    printer.kv("store now exists", db.exists())

    chain = build_chain(mode, db, printer)
    info = stamp(printer, 5, mode, db)
    report.beats.append({"beat": 0, "name": "process", **info})

    agent = open_agent(db, chain, offline=offline)
    poisoner = PoisonerAgent()
    job = Job(service="research-brief", payload=JOB_PAYLOAD, requested_usd=0.25)
    try:
        printer.block(
            "BEAT 5a  the honest counterparty, with no memory of it",
            "the settlements are still on the chain. nothing remembers to cite them.",
        )
        honest = agent.hire(
            SIBYLCAP,
            0.25,
            service="research-brief",
            pitch=CounterpartyAgent().pitch("research-brief"),
            handle=SIBYLCAP_HANDLE,
        )
        show_run(printer, honest, show_memories=False)

        # The returning poisoner goes first, and the ordering is the scenario
        # rather than a convenience. An attacker that knows the store was wiped
        # comes back and sells before it does anything detectable; running the
        # laundering vectors first would let this store re-catch the address
        # inside the same session, which is the system working and is a
        # different fact from the one this beat is measuring.
        printer.block(
            "BEAT 5b  the returning poisoner, against a store that never caught it",
            "this is the one memory was carrying alone",
        )
        planted = poisoner.return_visit(agent.store)
        agent.history.invalidate()
        flags_at_first_contact = len(agent.flags.list_flags())
        printer.line()
        printer.kv("flags in this store", flags_at_first_contact)
        printer.kv("claims planted", len(planted))
        returning = agent.hire(
            POISONER,
            0.25,
            service="research-brief",
            pitch=poisoner.pitch(),
            handle=POISONER_HANDLE,
        )
        show_run(printer, returning)

        printer.block(
            "BEAT 5c  the same three laundering vectors, replayed",
            "the chain check needs no memory, so this half still holds",
        )
        poisoner.launder_all(agent.store, job)
        agent.history.invalidate()
        forged = agent.hire(
            STRANGER,
            0.25,
            service="research-brief",
            pitch=poisoner.pitch(),
            handle=STRANGER_HANDLE,
        )
        show_run(printer, forged, show_memories=False)

        report.add({"beat": 5, "name": "deleted_honest", "run": run_summary(honest)})
        report.add({"beat": 5, "name": "deleted_returning", "run": run_summary(returning)})
        report.add({"beat": 5, "name": "deleted_forged", "run": run_summary(forged)})
        report.verdict = {
            "honest_counterparty_action": honest.action,
            "honest_counterparty_settled_usd": honest.settled_usd,
            "forged_settlement_action": forged.action,
            "returning_poisoner_action": returning.action,
            "returning_poisoner_settled_usd": returning.settled_usd,
            # Measured before the replayed vectors let this store re-catch the
            # address. Reporting the count after that would flatter the result.
            "flags_at_first_contact": flags_at_first_contact,
            "flags_relearned_within_the_session": len(agent.flags.list_flags()),
        }

        printer.block(
            "BEAT 5 RESULT  what deleting the memory cost",
            "same code, same chain, same attacker. only the store is gone.",
        )
        printer.line()
        printer.line(f"    {'':<36}{'WITH MEMORY':<20}{'MEMORY DELETED'}")
        printer.line(f"    {'-' * 72}")
        printer.line(
            f"    {'returning poisoner, $0.25':<36}"
            f"{'REFUSE on sight':<20}"
            f"{returning.action.upper()}"
            + (f"  --  ${returning.settled_usd:.2f} SETTLED" if returning.settled_usd else "")
        )
        printer.line(
            f"    {'honest counterparty, $0.25':<36}"
            f"{'PAY, unsecured':<20}"
            f"{honest.action.upper()}, "
            f"${honest.decision.collateral_usd:.2f} collateral demanded"
        )
        printer.line(
            f"    {'forged settlement about a stranger':<36}"
            f"{'REFUSE':<20}"
            f"{forged.action.upper()} (chain check, no memory needed)"
        )
        printer.line(
            f"    {'flagged actors at first contact':<36}{'2':<20}0"
        )
        printer.line()
        if returning.settled_usd > 0:
            printer.line(
                f"    THE ATTACK SUCCEEDS. ${returning.settled_usd:.2f} left the agent's "
                f"wallet to an address"
            )
            printer.line(
                "    it had already caught once. the only thing that was stopping it "
                "was the store."
            )
        printer.line()
        printer.line(
            "    and the honest half: the payment memory had earned is now an escrow "
            "demand."
        )
        printer.line(
            "    the settlements are still on chain. nothing remembers to cite them."
        )
    finally:
        agent.close()
    return report


# ----------------------------------------------------------------------
# Entry
# ----------------------------------------------------------------------
def spawn(session: str, args: argparse.Namespace, printer: Printer) -> dict[str, Any]:
    """Run a session in a genuinely separate process and stream its output.

    Not a thread, not a fork of the same store handle. A new interpreter that
    opens the same file from cold, so the process id printed in its banner is a
    different number and a video shows two of them.
    """
    command = [sys.executable, str(Path(__file__).resolve()), "--db", str(args.db)]
    command += ["--live"] if args.mode == "live" else ["--offline"]
    if args.venice:
        command.append("--venice")
    command += ["--delete-memory"] if session == "delete" else ["--session", session]
    if args.json:
        command.append("--json")
    printer.line()
    printer.line(f"  spawning: {' '.join(command[1:])}")
    sys.stdout.flush()
    completed = subprocess.run(command, capture_output=args.json, text=True)
    payload: dict[str, Any] = {"command": command[1:], "returncode": completed.returncode}
    if args.json and completed.stdout:
        try:
            payload["report"] = json.loads(completed.stdout)
        except json.JSONDecodeError:
            payload["stdout"] = completed.stdout
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    chain_mode = parser.add_mutually_exclusive_group()
    chain_mode.add_argument(
        "--offline",
        action="store_true",
        help="recorded chain fixtures, no network, no keys (default)",
    )
    chain_mode.add_argument(
        "--live", action="store_true", help="inject a reader pointed at Base mainnet"
    )
    parser.add_argument(
        "--venice",
        action="store_true",
        help=(
            "narrate with Venice (needs VENICE_API_KEY in the environment). "
            "Advisory only; the decision is identical either way, which is the point"
        ),
    )
    parser.add_argument(
        "--session", type=int, choices=(1, 2, 5), help="run one session only"
    )
    parser.add_argument(
        "--delete-memory",
        action="store_true",
        help="beat 5: destroy the store and replay the attack",
    )
    parser.add_argument("--json", action="store_true", help="emit the run as JSON")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help="where the store lives")
    args = parser.parse_args()

    args.mode = "live" if args.live else "offline"
    # The chain and the narrator are separate decisions. Reading Base does not
    # require a model, and running a model does not require a chain -- coupling
    # them would mean a judge cannot see one without having credentials for the
    # other. The default is neither: no network, no keys.
    offline = not (args.live or args.venice)
    printer = Printer(enabled=not args.json)

    if args.delete_memory or args.session == 5:
        report = session_deleted(args.db, args.mode, printer, offline=offline)
    elif args.session == 2:
        report = session_two(args.db, args.mode, printer, offline=offline)
    elif args.session == 1:
        report = session_one(args.db, args.mode, printer, offline=offline)
    else:
        report = session_one(args.db, args.mode, printer, offline=offline)
        report.children.append(spawn("2", args, printer))
        report.children.append(spawn("delete", args, printer))
        _closing(printer, report)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, default=str))
    return 0


def _closing(printer: Printer, report: Report) -> None:
    printer.block("WHAT JUST HAPPENED", "one rule, enforced in code")
    printer.line()
    printer.line(
        "    A memory may not justify moving more money than can be found on chain,"
    )
    printer.line(
        "    moved to the party it vouches for, by somebody who is not that party."
    )
    printer.line()
    verdict = report.verdict
    printer.bullet(
        f"paid the counterparty whose history re-derives: {verdict.get('paid_honest_counterparty')}"
    )
    printer.bullet(
        f"refused the forged settlement outright, not escrow: {verdict.get('refused_the_attack')}"
    )
    printer.bullet(
        f"actors flagged for forging evidence: {verdict.get('actors_flagged_directly')}"
    )
    printer.bullet(
        f"nodes reached by walking the ring from that one flag: "
        f"{verdict.get('ring_nodes')}"
    )
    printer.bullet(
        f"addresses now in the FLAGGED tier, carried to the next process: "
        f"{verdict.get('flags_held')}"
    )
    printer.line()
    printer.line("    run the pieces on their own:")
    printer.line("      python scripts/demo.py --session 1")
    printer.line("      python scripts/demo.py --session 2")
    printer.line("      python scripts/demo.py --delete-memory")
    printer.line("      python scripts/demo.py --json")
    printer.line("      python scripts/eval.py")


def _remove_db(db: Path) -> int:
    """Delete the store and the SQLite sidecars. Returns bytes removed.

    The write-ahead log and shared-memory files are part of the database. A
    deletion test that leaves ``-wal`` behind is a deletion test that can be
    accused of leaving the answer on the disk.
    """
    removed = db.stat().st_size if db.exists() else 0
    for suffix in ("", "-wal", "-shm", "-journal"):
        candidate = Path(str(db) + suffix)
        if candidate.exists():
            candidate.unlink()
    return removed


def _clip(text: Any, width: int) -> str:
    value = " ".join(str(text or "").split())
    return value if len(value) <= width else value[: width - 3] + "..."


def _short(address: Any) -> str:
    text = str(address or "")
    if not text:
        return "an unnamed actor"
    return f"{text[:6]}...{text[-4:]}" if len(text) > 12 else text


if __name__ == "__main__":
    raise SystemExit(main())
