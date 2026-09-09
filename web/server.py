"""The web surface, over the real core.

    pip install fastapi uvicorn
    python web/seed.py
    uvicorn web.server:app --port 8000

Every number this serves is computed at request time by ``admissible``: the
admission gate decides each memory, the trust policy turns the admitted set into
pay / escrow / refuse, the FLAGGED tier and the relations graph come out of
Sibyl's own tables, and the replay comes out of the bi-temporal timeline. There
is no second implementation of any of it here. This module reads the store,
calls the package, and renders the answer as JSON.

Two rules it holds itself to:

**It never fakes a chain.** With no ``BASE_RPC_URL`` set the reader is
``web/fixtures/base-mainnet.json`` and every response carries
``chain: "offline fixtures"``. The pages print that where a status light would
go. A visible gap beats an uncheckable claim.

**It never hides a refusal.** Refused memories come back in the same list as
admitted ones, with their verdict, the fields that decided it, and the evidence
they cite. A memory the surface drops is an attack the surface hides.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterable, Iterator

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi import FastAPI, HTTPException, Query  # noqa: E402
from fastapi.responses import (  # noqa: E402
    FileResponse,
    JSONResponse,
    PlainTextResponse,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402

from web import DEFAULT_DB, FIXTURES, REPO_ROOT, STATIC  # noqa: E402
from web.recorded import open_chain  # noqa: E402

from admissible.anchor import build_tree, commit, leaf_of  # noqa: E402
from admissible.envelope import digest_of  # noqa: E402
from admissible.envelope import Envelope, Tier, utcnow  # noqa: E402  (digest_of above)
from admissible.flagged import FlaggedActors, _norm_actor  # noqa: E402
from admissible.gate import AdmissionGate  # noqa: E402
from admissible.policy import Decision, TrustPolicy  # noqa: E402
from admissible.relations import SOURCED, VOUCHED_FOR, EntityRef, Relations  # noqa: E402
from admissible.store import AdmissibleStore, MalformedMemory  # noqa: E402
from admissible.timeline import Timeline  # noqa: E402
from admissible.verdicts import FORGERY_CODES, Verdict, VerdictCode  # noqa: E402
from admissible.wiring import build_gate  # noqa: E402

INTERACTION = "interaction"
DOSSIER = "dossier"
ACTOR = "actor"
META = "meta"

BASESCAN = "https://basescan.org"

#: How long the trace endpoint waits between steps. The computation is real and
#: takes microseconds; this paces it so a human can watch the gate work through
#: a file. Every streamed frame says ``paced: true`` so nobody mistakes the
#: pacing for latency.
TRACE_DELAY_MS = int(os.environ.get("ADMISSIBLE_TRACE_DELAY_MS", "90"))

#: The rule, stated precisely. The tagline is a slogan; this is the sentence the
#: code enforces, and it is narrower than the slogan on purpose -- it says how
#: much, and it says who may vouch. Both clauses were added after we attacked our
#: own gate and found the earlier wording overclaiming.
RULE = (
    "A memory may not justify moving more money than can be found on chain, "
    "moved to the party it vouches for, by somebody who is not that party."
)

#: Findings from the red-team pass against our own gate, and the attack that
#: survived it. LIMITS.md in the repository root is the source of truth and
#: lists every one; these numbers are repeated here only so the landing can
#: print them beside the scorecard.
REDTEAM = {
    "found": 20,
    "fixed": 19,
    "open": 1,
    "source": "LIMITS.md",
    "residue": (
        "Reputation is still purchasable. It costs face value now instead of "
        "$0.0027: one attacker cycling send-$5,000 / review / take-it-back twenty "
        "times turns $5,000 of working capital into $100,000 of credit. We publish "
        "that rather than hide it."
    ),
}


# ---------------------------------------------------------------------------
# Bi-temporal wrappers: a replay must not be able to see the future
# ---------------------------------------------------------------------------
class AsOfHistory:
    """``StoreHistory`` with a cutoff.

    ``admissible.wiring.StoreHistory`` answers "was this superseded" out of the
    whole journal, which is right for a decision made now and wrong for a replay:
    a memory superseded last Tuesday was not superseded the Monday before. This
    reads the same journal and ignores everything written after the cutoff, so
    "what would the agent have decided then" means what it says.
    """

    def __init__(self, store: AdmissibleStore, cutoff: str) -> None:
        self._store = store
        self._cutoff = cutoff
        self._superseded: dict[str, str] | None = None
        self._recorded: dict[str, str] | None = None

    def _load(self) -> None:
        if self._superseded is not None:
            return
        superseded: dict[str, str] = {}
        recorded: dict[str, str] = {}
        for record in reversed(self._store.journal(limit=100000)):  # oldest first
            ts = record.get("ts")
            if not ts or ts > self._cutoff:
                continue
            digest = record.get("digest")
            if digest:
                recorded.setdefault(digest, ts)
            if record.get("op") == "supersede" and record.get("superseded_digest"):
                superseded[record["superseded_digest"]] = record.get("digest", "")
        self._superseded, self._recorded = superseded, recorded

    def superseding_digest(self, digest: str) -> str | None:
        self._load()
        return (self._superseded or {}).get(digest) or None

    def recorded_at(self, digest: str) -> str | None:
        self._load()
        return (self._recorded or {}).get(digest)

    def invalidate(self) -> None:
        self._superseded = self._recorded = None


class AsOfFlags:
    """The FLAGGED tier as it stood at a moment.

    A flag raised after the cutoff had not been raised yet, and a flag revoked
    after the cutoff was still in force. Both directions matter: replaying a past
    decision with today's blocklist is hindsight, and hindsight is not evidence.
    """

    def __init__(self, flags: FlaggedActors, cutoff: str) -> None:
        self._flags = flags
        self._cutoff = cutoff

    def is_flagged(self, identifier: str) -> Any | None:
        needle = _norm_actor(identifier)
        if not needle:
            return None
        for record in self._flags.list_flags(include_revoked=True):
            if needle not in record.lookup_keys:
                continue
            if record.flagged_at > self._cutoff:
                continue
            if record.revoked_at and record.revoked_at <= self._cutoff:
                continue
            return record
        return None


# ---------------------------------------------------------------------------
# The one place the store, the chain and the gate meet
# ---------------------------------------------------------------------------
class Surface:
    """Everything a request needs, assembled once at startup."""

    def __init__(self) -> None:
        self.db_path = Path(os.environ.get("ADMISSIBLE_DB") or DEFAULT_DB).expanduser()
        if not self.db_path.exists():
            raise RuntimeError(
                f"no store at {self.db_path}. Run `python web/seed.py` first, or set "
                f"ADMISSIBLE_DB to an existing Sibyl Memory database."
            )
        self.store = AdmissibleStore.open(self.db_path)
        self.chain = open_chain()
        self.flags = FlaggedActors(self.store)
        self.relations = Relations(self.store)
        self.timeline = Timeline(self.store)
        self.policy = TrustPolicy()
        self.manifest = self._manifest()
        self.self_address = (
            os.environ.get("ADMISSIBLE_SELF_ADDRESS")
            or self.manifest.get("self_address")
            or None
        )
        self._scorecard: dict[str, Any] | None = None

    def _manifest(self) -> dict[str, Any]:
        try:
            row = self.store.client.get_entity(META, "seed-manifest")
        except Exception:  # noqa: BLE001 - a store nobody seeded is still readable
            return {}
        body = row.get("body")
        return dict(body) if isinstance(body, dict) else {}

    # -- gates ---------------------------------------------------------------
    def gate(self, as_of: str | None = None) -> AdmissionGate:
        """The gate for a decision, at now or at a past moment.

        The live path goes through ``build_gate``, which is the entry point an
        agent uses. The replay path builds the gate directly because it has to
        substitute a history and a blocklist that stop at the cutoff, and
        ``build_gate`` owns both.
        """
        if as_of is None:
            gate, history = build_gate(
                self.store, self.chain, flags=self.flags, self_address=self.self_address
            )
            history.invalidate()
            return gate
        return AdmissionGate(
            chain=self.chain,
            flags=AsOfFlags(self.flags, as_of),
            history=AsOfHistory(self.store, as_of),
            now=lambda: as_of,
            self_address=self.self_address,
        )

    # -- reads ---------------------------------------------------------------
    def rows(self, category: str = INTERACTION) -> list[dict[str, Any]]:
        return list(self.store.client.list_entities(category, limit=5000))

    def memories(
        self, counterparty: str | None = None, *, as_of: str | None = None
    ) -> list[tuple[str, Any]]:
        """``(name, envelope | MalformedMemory)`` for a counterparty, oldest first.

        With ``as_of`` set, each name is resolved through ``Timeline.as_of``,
        which walks the supersession chain backwards to the version the agent
        actually held then, and returns nothing for a name it had not learned
        yet. A name whose body did not survive comes back as ``None`` and is
        reported as a gap rather than papered over.
        """
        out: list[tuple[str, Any]] = []
        for row in self.rows():
            parsed = self.store.parse_body(row["category"], row["name"], row["body"])
            if counterparty and not _about(parsed, counterparty):
                continue
            if as_of is not None:
                if isinstance(parsed, MalformedMemory):
                    continue
                replayed = self.timeline.as_of(INTERACTION, row["name"], as_of)
                if replayed is None:
                    continue
                parsed = replayed
            out.append((row["name"], parsed))
        out.sort(key=_sort_key)
        return out

    def judge(
        self, memories: Iterable[tuple[str, Any]], gate: AdmissionGate
    ) -> list[tuple[str, Any, Verdict]]:
        judged: list[tuple[str, Any, Verdict]] = []
        for name, memory in memories:
            if isinstance(memory, MalformedMemory):
                judged.append((name, memory, memory.verdict))
            else:
                judged.append((name, memory, gate.admit(memory)))
        return judged

    def decide(
        self, counterparty: str, requested_usd: float, *, as_of: str | None = None
    ) -> tuple[Decision, list[tuple[str, Any, Verdict]]]:
        gate = self.gate(as_of)
        judged = self.judge(self.memories(counterparty, as_of=as_of), gate)
        flag = (
            AsOfFlags(self.flags, as_of).is_flagged(counterparty)
            if as_of
            else self.flags.is_flagged(counterparty)
        )
        # Malformed rows never reach the policy -- they have no provenance for it
        # to weigh -- but they are carried in the trace so the surface can show
        # them. A body we cannot parse is still a write somebody made.
        pairs = [(m, v) for _, m, v in judged if isinstance(m, Envelope)]
        decision = self.policy.decide(counterparty, requested_usd, pairs, flagged=flag)
        return decision, judged

    # -- views ---------------------------------------------------------------
    def memory_view(
        self,
        name: str,
        memory: Any,
        verdict: Verdict,
        *,
        weight: float | None = None,
        counted: bool | None = None,
    ) -> dict[str, Any]:
        base: dict[str, Any] = {
            "category": INTERACTION,
            "name": name,
            "verdict": verdict.to_dict(),
            "weight_usd": round(weight or 0.0, 6),
            "counted": bool(counted) if counted is not None else bool(weight),
            "forgery": verdict.code in FORGERY_CODES,
        }
        if isinstance(memory, MalformedMemory):
            base.update(
                parseable=False,
                digest=None,
                tier=None,
                source=None,
                actor_address=None,
                actor_handle=None,
                observed_at=None,
                claim=_claim_of(memory),
                evidence={},
                evidence_links=[],
                reason=memory.reason,
                raw_body=memory.body,
            )
            return base

        prov = memory.provenance
        evidence = prov.evidence.to_dict()
        base.update(
            parseable=True,
            digest=memory.digest,
            tier=prov.tier.value,
            source=prov.source,
            actor_address=prov.actor_address,
            actor_handle=prov.actor_handle,
            observed_at=prov.observed_at,
            valid_from=prov.valid_from,
            valid_to=prov.valid_to,
            supersedes=prov.supersedes,
            claim=memory.claim,
            evidence=evidence,
            evidence_links=self.evidence_links(prov),
        )
        return base

    def evidence_links(self, prov: Any) -> list[dict[str, Any]]:
        """Somewhere a stranger can go and check, plus what they will find there.

        Every link is marked ``recorded`` when the chain reader is a file. The
        hash is real in shape and was never mined, and saying so beside the link
        is cheaper than being caught by anyone who clicks it.
        """
        links: list[dict[str, Any]] = []
        evidence = prov.evidence
        recorded = not getattr(self.chain, "live", False)
        if evidence.tx_hash:
            settlement = getattr(self.chain, "settlement", lambda _h: None)(
                evidence.tx_hash
            )
            links.append(
                {
                    "kind": "transaction",
                    "label": _short_hash(evidence.tx_hash),
                    "value": evidence.tx_hash,
                    "url": f"{BASESCAN}/tx/{evidence.tx_hash}",
                    "recorded": recorded,
                    "note": getattr(settlement, "note", "") if settlement else "",
                }
            )
        if evidence.registry:
            links.append(
                {
                    "kind": "registry",
                    "label": f"ERC-8004 #{evidence.agent_id} / {evidence.feedback_index}",
                    "value": evidence.registry,
                    "url": f"{BASESCAN}/address/{evidence.registry}",
                    "recorded": recorded,
                    "note": "",
                }
            )
        if prov.actor_address:
            links.append(
                {
                    "kind": "actor",
                    "label": _short_addr(prov.actor_address),
                    "value": prov.actor_address,
                    "url": f"{BASESCAN}/address/{prov.actor_address}",
                    "recorded": False,
                    "note": "",
                }
            )
        return links

    def counterparty_view(self, address: str) -> dict[str, Any]:
        gate = self.gate()
        judged = self.judge(self.memories(address), gate)
        flag = self.flags.is_flagged(address)
        pairs = [(m, v) for _, m, v in judged if isinstance(m, Envelope)]
        ask = float((self.manifest.get("default_ask_usd") or {}).get(address, 1.00))
        decision = self.policy.decide(address, ask, pairs, flagged=flag)
        weights = {c.digest: c.weight_usd for c in decision.considered}

        tiers: dict[str, int] = {}
        verdicts: dict[str, int] = {}
        marks: list[int] = []
        for _, memory, verdict in judged:
            tier = memory.provenance.tier.value if isinstance(memory, Envelope) else "MALFORMED"
            tiers[tier] = tiers.get(tier, 0) + 1
            verdicts[verdict.code.value] = verdicts.get(verdict.code.value, 0) + 1
            marks.append(_mark(verdict))

        dossier = self.store.recall(DOSSIER, address)
        return {
            "address": address,
            "handle": self._handle(address),
            "sessions": len(judged),
            "tiers": tiers,
            "verdicts": verdicts,
            "marks": marks,
            "standing": _standing(judged, flag),
            "credit_usd": decision.credit_usd,
            "default_ask_usd": ask,
            "action": decision.action,
            "flagged": _flag_view(flag),
            "laundering": sum(1 for _, _, v in judged if v.code in FORGERY_CODES),
            "dossier": dossier.claim if isinstance(dossier, Envelope) else None,
            "dossier_tier": dossier.tier.value if isinstance(dossier, Envelope) else None,
            "weights": weights,
        }

    def _handle(self, address: str) -> str:
        for entry in self.manifest.get("cast") or []:
            if str(entry.get("address", "")).lower() == address.lower():
                return str(entry.get("handle") or "")
        node = self.store.recall(ACTOR, _norm_actor(address) or address.lower())
        return str(node.claim.get("handle", "")) if isinstance(node, Envelope) else ""

    def counterparties(self) -> list[str]:
        listed = self.manifest.get("counterparties")
        if listed:
            return list(listed)
        seen: list[str] = []
        for _, memory in self.memories():
            who = _claim_of(memory).get("counterparty")
            if isinstance(who, str) and who not in seen:
                seen.append(who)
        return seen

    def contaminated(self) -> dict[str, list[str]]:
        """Everything downstream of each flagged actor, by ``category/name``.

        Reachability, not a verdict. A contaminated node is one the flag can
        reach along a vouch or a sourcing; it is a reason for a human to look,
        and the gate does not refuse on it.
        """
        out: dict[str, list[str]] = {}
        for record in self.flags.list_flags():
            address = record.actor_address or record.actor_handle or ""
            try:
                refs = self.relations.contaminated_by(address)
            except LookupError:
                out[address] = []
                continue
            out[address] = [f"{r.category}/{r.name}" for r in refs]
        return out

    def scorecard(self) -> dict[str, Any]:
        """The offline adversarial scorecard, by running the repository's own bench.

        Shelled out rather than imported: ``bench/run.py`` is the file a judge is
        invited to run, and running the same command they would is the only way
        the number on the page and the number in their terminal cannot drift.
        """
        if self._scorecard is not None:
            return self._scorecard
        card: dict[str, Any] = {"available": False, "command": "python bench/run.py --json"}
        try:
            proc = subprocess.run(
                [sys.executable, str(REPO_ROOT / "bench" / "run.py"), "--json"],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=str(REPO_ROOT),
            )
            payload = json.loads(proc.stdout)
            card.update(
                available=True,
                corpus=payload.get("corpus"),
                attacks_total=payload.get("attacks_total"),
                attacks_caught_exact=payload.get("attacks_caught_exact"),
                attacks_missed=payload.get("attacks_missed"),
                attacks_refused_wrong_reason=payload.get("attacks_refused_wrong_reason"),
                controls_total=payload.get("controls_total"),
                controls_admitted=payload.get("controls_admitted"),
                false_refusals=payload.get("false_refusals"),
                passed=payload.get("pass"),
                exit_code=proc.returncode,
            )
        except Exception as exc:  # noqa: BLE001 - an absent number beats a made-up one
            card["error"] = f"{type(exc).__name__}: {exc}"
        card["honest_note"] = (
            "The controls carry equal weight: a gate that refused everything would "
            "score full marks on the attacks alone. We wrote both the corpus and "
            "the gate, so this is spec conformance rather than independent "
            f"evaluation. A dedicated pass against our own gate found "
            f"{REDTEAM['found']} distinct problems; {REDTEAM['fixed']} are fixed "
            f"and {REDTEAM['open']} is not. All of them are in LIMITS.md."
        )
        card["redteam"] = REDTEAM
        card["rule"] = RULE
        self._scorecard = card
        return card

    def chain_view(self) -> dict[str, Any]:
        return self.chain.describe()


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _claim_of(memory: Any) -> dict[str, Any]:
    if isinstance(memory, Envelope):
        return memory.claim
    body = getattr(memory, "body", None)
    if isinstance(body, dict) and isinstance(body.get("claim"), dict):
        return dict(body["claim"])
    return {}


def _about(memory: Any, counterparty: str) -> bool:
    who = _claim_of(memory).get("counterparty")
    return isinstance(who, str) and who.lower() == counterparty.lower()


def _sort_key(item: tuple[str, Any]) -> tuple[str, str]:
    name, memory = item
    observed = (
        memory.provenance.observed_at if isinstance(memory, Envelope) else ""
    )
    return (observed, name)


def _mark(verdict: Verdict) -> int:
    """A memory's outcome as one of three heights, for the cartridge strip.

    2 = admitted, 1 = refused but not an accusation, 0 = forged or unreadable.
    """
    if verdict.admits:
        return 2
    if verdict.code in FORGERY_CODES or verdict.code is VerdictCode.MALFORMED:
        return 0
    return 1


def _standing(judged: list[tuple[str, Any, Verdict]], flag: Any) -> str:
    if flag:
        return "FLAGGED"
    best = None
    for _, memory, verdict in judged:
        if verdict.admits and isinstance(memory, Envelope):
            tier = memory.provenance.tier
            if best is None or tier.rank > best.rank:
                best = tier
    if best is Tier.ATTESTED:
        return "ATTESTED"
    if best is Tier.WITNESSED:
        return "WITNESSED"
    return "HEARSAY"


def _flag_view(record: Any) -> dict[str, Any] | None:
    if not record:
        return None
    return {
        "id": record.id,
        "actor_address": record.actor_address,
        "actor_handle": record.actor_handle,
        "flagged_at": record.flagged_at,
        "reason": record.reason,
        "evidence": record.evidence,
        "revoked_at": record.revoked_at,
        "revoked_reason": record.revoked_reason,
        "active": record.is_active,
    }


def _short_hash(value: str) -> str:
    return f"{value[:10]}...{value[-6:]}" if len(value) > 20 else value


def _short_addr(value: str) -> str:
    return f"{value[:6]}...{value[-4:]}" if len(value) > 12 else value


def _no_store(payload: Any) -> JSONResponse:
    return JSONResponse(payload, headers={"Cache-Control": "no-store"})


# ---------------------------------------------------------------------------
# app
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Admissible",
    description="Counterparty memory that has to prove itself before it moves money.",
    version="0.1.0",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)

surface = Surface()

app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")


@app.get("/", include_in_schema=False)
def landing() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/app", include_in_schema=False)
def record() -> FileResponse:
    return FileResponse(STATIC / "app.html")


@app.get("/LIMITS.md", include_in_schema=False)
def limits() -> PlainTextResponse:
    path = REPO_ROOT / "LIMITS.md"
    if not path.exists():
        raise HTTPException(status_code=404, detail="LIMITS.md is not in this checkout")
    return PlainTextResponse(path.read_text(encoding="utf-8"))


@app.get("/api/site")
def site() -> JSONResponse:
    """Where the off-site links point, and honest nulls where they do not yet.

    A link that has not been published is served as ``null`` rather than as a
    plausible URL. The page renders those as unavailable instead of inventing a
    destination.
    """
    return _no_store(
        {
            "rule": RULE,
            "repo_url": os.environ.get("ADMISSIBLE_REPO_URL") or None,
            "video_url": os.environ.get("ADMISSIBLE_VIDEO_URL") or None,
            "limits_url": "/LIMITS.md",
            "limits_available": (REPO_ROOT / "LIMITS.md").exists(),
            "chain": surface.chain_view(),
            "self_address": surface.self_address,
            "seed": surface.manifest,
        }
    )


@app.get("/api/counterparties")
def counterparties() -> JSONResponse:
    """Every counterparty, its dossier, its tier histogram and where it stands."""
    return _no_store(
        {
            "generated_at": utcnow(),
            "chain": surface.chain_view(),
            "self_address": surface.self_address,
            "seed": surface.manifest,
            "counterparties": [surface.counterparty_view(a) for a in surface.counterparties()],
        }
    )


@app.get("/api/counterparty/{address}")
def counterparty(address: str) -> JSONResponse:
    """Every memory about one counterparty, each with its verdict attached."""
    resolved = _resolve(address)
    gate = surface.gate()
    judged = surface.judge(surface.memories(resolved), gate)
    view = surface.counterparty_view(resolved)
    weights = view.pop("weights", {})
    memories = [
        surface.memory_view(
            name,
            memory,
            verdict,
            weight=weights.get(getattr(memory, "digest", None), 0.0),
        )
        for name, memory, verdict in judged
    ]
    return _no_store(
        {
            "generated_at": utcnow(),
            "chain": surface.chain_view(),
            "counterparty": view,
            "memories": memories,
        }
    )


class DecideRequest(BaseModel):
    counterparty: str
    requested_usd: float = Field(default=1.0, ge=0)
    as_of: str | None = None


@app.post("/api/decide")
def decide(request: DecideRequest) -> JSONResponse:
    """Run the real gate and the real policy, and return the whole decision.

    ``as_of`` replays: memories are resolved to the version the agent held at
    that transaction time, the validity windows are judged at that moment, and
    neither a later supersession nor a later flag is allowed to leak backwards.
    """
    resolved = _resolve(request.counterparty)
    decision, judged = surface.decide(
        resolved, request.requested_usd, as_of=request.as_of
    )
    return _no_store(_decision_payload(decision, judged, request.as_of))


def _decision_payload(
    decision: Decision, judged: list[tuple[str, Any, Verdict]], as_of: str | None
) -> dict[str, Any]:
    weights = {c.digest: c.weight_usd for c in decision.considered}
    counted = {c.digest for c in decision.considered if c.weight_usd > 0}
    trace = [
        surface.memory_view(
            name,
            memory,
            verdict,
            weight=weights.get(getattr(memory, "digest", None), 0.0),
            counted=getattr(memory, "digest", None) in counted,
        )
        for name, memory, verdict in judged
    ]
    gaps = [
        {"name": name, "records": surface.timeline.unreconstructible(INTERACTION, name)}
        for name in {n for n, _, _ in judged}
        if surface.timeline.unreconstructible(INTERACTION, name)
    ]
    return {
        "generated_at": utcnow(),
        "as_of": as_of,
        "chain": surface.chain_view(),
        "self_address": surface.self_address,
        "decision": decision.to_dict(),
        "trace": trace,
        "unreconstructible": gaps,
    }


@app.get("/api/flags")
def flags() -> JSONResponse:
    """The FLAGGED tier, and what each flag reaches through the graph."""
    contamination = surface.contaminated()
    return _no_store(
        {
            "generated_at": utcnow(),
            "flags": [
                {
                    **(_flag_view(record) or {}),
                    "contaminates": contamination.get(
                        record.actor_address or record.actor_handle or "", []
                    ),
                }
                for record in surface.flags.list_flags(include_revoked=True)
            ],
            "note": (
                "Flags live in Sibyl's own flagged_actors table, under the same "
                "tenant as the memories. A second process opening this database "
                "sees the blocklist with no warm-up, which is the point: a "
                "blocklist you have to rebuild is one you do not have when it "
                "matters. Revoked flags are kept, never deleted."
            ),
        }
    )


@app.get("/api/graph")
def graph() -> JSONResponse:
    """The relations graph: who vouched for whom, and who sourced what.

    Contamination is computed by ``Relations.contaminated_by`` from each flagged
    actor: backwards along a vouch, forwards along a sourcing. It marks nodes the
    flag can reach. It is reachability, not a verdict -- the gate refuses on
    evidence, and this is what a human should look at next.
    """
    gate = surface.gate()
    verdict_by_name = {
        name: verdict.code.value
        for name, _, verdict in surface.judge(surface.memories(), gate)
    }
    contamination = surface.contaminated()
    tainted = {ref for refs in contamination.values() for ref in refs}

    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []

    def node_id(ref: EntityRef) -> str:
        return f"{ref.category}/{ref.name}"

    for row in surface.rows(ACTOR):
        parsed = surface.store.parse_body(ACTOR, row["name"], row["body"])
        claim = _claim_of(parsed)
        address = str(claim.get("address") or row["name"])
        flag = surface.flags.is_flagged(address)
        ident = f"{ACTOR}/{row['name']}"
        nodes[ident] = {
            "id": ident,
            "kind": "actor",
            "label": str(claim.get("handle") or _short_addr(address)),
            "address": address,
            "role": claim.get("role"),
            "flagged": bool(flag),
            "contaminated": ident in tainted,
        }

    for ident in list(nodes):
        ref = EntityRef(*ident.split("/", 1))
        for edge in surface.relations.edges(ref, direction="out"):
            target = node_id(edge.to_ref)
            if target not in nodes and edge.to_ref.category == INTERACTION:
                memory = surface.store.recall(INTERACTION, edge.to_ref.name)
                nodes[target] = {
                    "id": target,
                    "kind": "memory",
                    "label": edge.to_ref.name,
                    "tier": memory.provenance.tier.value
                    if isinstance(memory, Envelope)
                    else "MALFORMED",
                    "verdict": verdict_by_name.get(edge.to_ref.name),
                    "flagged": False,
                    "contaminated": target in tainted,
                }
            edges.append(
                {
                    "id": edge.id,
                    "source": ident,
                    "target": target,
                    "type": edge.relation_type,
                    "metadata": edge.metadata,
                    "contaminated": target in tainted or ident in tainted,
                }
            )

    return _no_store(
        {
            "generated_at": utcnow(),
            "nodes": list(nodes.values()),
            "edges": edges,
            "contamination": contamination,
            "relation_types": {"vouched_for": VOUCHED_FOR, "sourced": SOURCED},
        }
    )


@app.get("/api/timeline/{category}/{name}")
def timeline(
    category: str, name: str, as_of: str | None = Query(default=None)
) -> JSONResponse:
    """Bi-temporal replay of one memory: every version, and the one held at ``as_of``."""
    versions = surface.timeline.versions(category, name)
    if not versions:
        raise HTTPException(status_code=404, detail=f"no versions of {category}/{name}")
    gate = surface.gate(as_of)
    at = surface.timeline.as_of(category, name, as_of) if as_of else None
    return _no_store(
        {
            "generated_at": utcnow(),
            "category": category,
            "name": name,
            "as_of": as_of,
            "versions": [
                {
                    "origin": version.origin,
                    "recorded_at": version.recorded_at,
                    "digest": version.envelope.digest,
                    "tier": version.envelope.provenance.tier.value,
                    "observed_at": version.envelope.provenance.observed_at,
                    "valid_from": version.envelope.provenance.valid_from,
                    "valid_to": version.envelope.provenance.valid_to,
                    "supersedes": version.envelope.provenance.supersedes,
                    "claim": version.envelope.claim,
                    "verdict": gate.admit(version.envelope).to_dict(),
                }
                for version in versions
            ],
            "held_at_as_of": surface.memory_view(
                name, at, gate.admit(at)
            )
            if at is not None
            else None,
            "unreconstructible": surface.timeline.unreconstructible(category, name),
            "malformed": [
                {"reason": m.reason, "body": m.body}
                for m in surface.timeline.malformed(category, name)
            ],
        }
    )


@app.get("/api/anchor")
def anchor() -> JSONResponse:
    """The Merkle root over everything the agent currently holds admissible.

    Only admissible memories are committed. Anchoring the whole store would
    commit to hearsay and forgeries alongside evidence and make the root mean
    nothing: an anchor is a claim about what the agent is willing to act on, not
    an inventory.
    """
    gate = surface.gate()
    pairs = [
        (memory.digest, memory.provenance.observed_at)
        for _, memory, verdict in surface.judge(surface.memories(), gate)
        if isinstance(memory, Envelope) and verdict.admits
    ]
    commitment = commit(pairs)
    published = _published_anchor()
    return _no_store(
        {
            "generated_at": utcnow(),
            "chain": surface.chain_view(),
            "root": commitment.root_hex,
            "leaf_count": commitment.leaf_count,
            "as_of": commitment.as_of,
            "as_of_unix": commitment.as_of_unix if commitment.leaf_count else None,
            "digests": list(commitment.digests),
            "contract": "contracts/src/AdmissibilityAnchor.sol",
            "published": published,
            "note": (
                "The root is recomputed on every request from the memories the "
                "gate admits right now. Publishing it is a separate, signed act; "
                "this endpoint reports the published one only when a deployment "
                "artefact says so."
            ),
        }
    )


def _published_anchor() -> dict[str, Any] | None:
    """The last anchor actually published, when a deployment artefact records one."""
    candidates = [
        os.environ.get("ADMISSIBLE_ANCHOR_FILE"),
        str(REPO_ROOT / ".demo" / "anchor.json"),
        str(REPO_ROOT / "contracts" / "deployments" / "base-mainnet.json"),
    ]
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate)
        if path.exists():
            try:
                return {"source": str(path), **json.loads(path.read_text(encoding="utf-8"))}
            except (OSError, ValueError):
                continue
    return None


#: Where the ACP bridge listens. `workers/acp/` serves the live public Virtuals
#: registry search on this port; the panel falls back to recorded values, and
#: says which it used, rather than spinning.
ACP_WORKER = os.environ.get("ACP_WORKER_URL", "http://127.0.0.1:8787")
#: Generous, because the bridge re-authenticates on its first call after idling
#: and that takes about five seconds. A bridge that is simply not running fails
#: instantly with a refused connection, so the fallback stays immediate.
ACP_TIMEOUT = float(os.environ.get("ACP_WORKER_TIMEOUT", "12"))


@app.get("/api/proof")
def proof() -> JSONResponse:
    """The Base mainnet run, re-derived rather than transcribed.

    Every other endpoint here reads the seeded store against recorded fixtures.
    This one is about the executed run on chain, and it is labelled as such: the
    demo store stays ``offline fixtures`` and does not borrow this.

    What makes it worth serving at all is that the digest is not copied out of
    ``PROOF.md``. The claim is, and the server hashes it -- ``keccak256`` over the
    canonical claim, the same function the gate uses -- then hashes that into a
    Merkle leaf and builds the one-leaf tree. Three numbers come out, and the
    page shows whether each equals what was published on Base. If this file ever
    drifts from what was executed, the panel disagrees with itself in public
    instead of quietly agreeing.
    """
    path = FIXTURES / "mainnet-proof.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="no mainnet proof fixture in this checkout")
    record = json.loads(path.read_text(encoding="utf-8"))

    computed = digest_of(record["claim"])
    tree = build_tree([computed])
    control = digest_of(record["control_claim"])
    published = record["published_digest"]
    anchor = record["anchor"]

    steps = [
        {
            "key": "settlement",
            "label": "Settled on Base",
            "value": record["settlement"]["tx"],
            "kind": "tx",
            "detail": f"{record['settlement']['value']} USDC base units to "
            f"{record['settlement']['to']}",
        },
        {
            "key": "digest",
            "label": "Memory digest, recomputed here",
            "value": computed,
            "kind": "hash",
            "detail": "keccak256 over the canonical claim, by the same function the gate uses",
        },
        {
            "key": "feedback",
            "label": "Committed as feedbackHash",
            "value": record["feedback"]["feedback_hash"],
            "kind": "tx",
            "link": record["feedback"]["tx"],
            "detail": f"ERC-8004 record in {record['feedback']['registry']}",
        },
        {
            "key": "anchor",
            "label": "Anchored as the Merkle root",
            "value": tree.root_hex,
            "kind": "tx",
            "link": anchor["tx"],
            "detail": f"{anchor['leaves']} leaf, as of {anchor['as_of']}",
        },
    ]

    return _no_store(
        {
            "generated_at": utcnow(),
            "chain": {"chain": record["chain"], "chain_id": record["chain_id"], "live": True},
            "explorer": record["explorer"],
            "contract": record["contract"],
            "agent": record["agent"],
            "settlement": record["settlement"],
            "claim": record["claim"],
            "verdict": record["verdict"],
            "feedback": record["feedback"],
            "anchor": anchor,
            "steps": steps,
            "recomputed": {
                "digest": computed,
                "leaf": "0x" + leaf_of(computed).hex(),
                "root": tree.root_hex,
                "proof": tree.proof_hex(computed),
                "digest_matches_published": computed.lower() == published.lower(),
                "digest_matches_feedback_hash": computed.lower()
                == record["feedback"]["feedback_hash"].lower(),
                "root_matches_anchor": tree.root_hex.lower() == anchor["root"].lower(),
                "verifies": tree.verify(computed, tree.proof(computed)),
            },
            "control": {
                "claim": record["control_claim"],
                "digest": control,
                "leaf": "0x" + leaf_of(control).hex(),
                "verifies": tree.verify(control, []),
                "note": record["control_note"],
            },
            "reproduce": record["reproduce"],
            "source": record["source"],
            "note": record["note"],
        }
    )


@app.get("/api/sourcing")
def sourcing() -> JSONResponse:
    """Where the counterparty came from: the live Virtuals registry, and the hire.

    Prefers the ACP bridge in ``workers/acp/`` and falls back to recorded values
    with the fallback named in the response. It reports which registry answered,
    because the bridge can be pointed at either the mainnet registry or the dev
    one, and a dev-registry read presented as a mainnet read would be a lie the
    rest of this product exists to argue against.

    The job is reported at the status it is actually in. It is ``open``: the
    provider sets the budget and delivers, and at the time of writing it has not.
    """
    path = FIXTURES / "virtuals-acp.json"
    recorded = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    worker: dict[str, Any] = {"url": ACP_WORKER, "reachable": False, "error": None}
    live_agent: dict[str, Any] | None = None
    live_offerings: list[dict[str, Any]] = []
    registry: dict[str, Any] | None = None

    health = _acp_get("/health")
    if isinstance(health, dict) and health.get("ok"):
        data = health.get("data") or {}
        chain = data.get("chain") or {}
        auth = data.get("auth") or {}
        worker.update(reachable=True, chain=chain, auth_ready=bool(auth.get("ready")))
        agent = auth.get("agent") or {}
        if agent:
            offering = (agent.get("offerings") or [{}])[0]
            live_agent = {
                "name": agent.get("name"),
                "id": agent.get("id"),
                "wallet": agent.get("walletAddress"),
                "builder_code": agent.get("builderCode"),
                "offering": {
                    "name": offering.get("name"),
                    "id": offering.get("id"),
                    "price_usdc": offering.get("priceValue"),
                    "description": offering.get("description"),
                },
            }
        browsed = _acp_post("/browse", {"query": "memory", "top_k": 8})
        if isinstance(browsed, dict) and browsed.get("ok"):
            registry = {
                "endpoint": (chain.get("api") or "") + "/agents/search",
                "chain_id": chain.get("chainId"),
                "network": chain.get("network"),
                "live": True,
            }
            for entry in (browsed.get("data") or [])[:8]:
                for offering in entry.get("offerings") or [{}]:
                    live_offerings.append(
                        {
                            "name": entry.get("name"),
                            "wallet": entry.get("walletAddress"),
                            "offering": offering.get("name"),
                            "price_usdc": offering.get("priceValue"),
                        }
                    )
    else:
        worker["error"] = "the ACP bridge did not answer"

    sample = recorded.get("registry_sample") or {}
    return _no_store(
        {
            "generated_at": utcnow(),
            "worker": worker,
            "agent": live_agent or recorded.get("agent"),
            "agent_source": "live worker" if live_agent else "recorded",
            "registry": registry
            or {
                "endpoint": sample.get("endpoint"),
                "chain_id": sample.get("chain_id"),
                "network": "base mainnet",
                "live": False,
                "recorded_at": sample.get("recorded_at"),
            },
            "offerings": live_offerings or sample.get("results") or [],
            "offerings_source": "live worker" if live_offerings else "recorded",
            # The bridge can be configured for either registry. When the live read
            # is not the mainnet one, the recorded mainnet read is carried beside
            # it rather than in place of it, so neither is mistaken for the other.
            "mainnet_sample": sample if (registry or {}).get("chain_id") != 8453 else None,
            "hire": recorded.get("hire"),
            "lifecycle": recorded.get("lifecycle"),
            "into_memory": recorded.get("into_memory"),
            "source": recorded.get("source"),
            "note": recorded.get("note"),
        }
    )


def _acp_get(path: str) -> Any:
    return _acp_call("GET", path, None)


def _acp_post(path: str, body: dict[str, Any]) -> Any:
    return _acp_call("POST", path, body)


def _acp_call(method: str, path: str, body: dict[str, Any] | None) -> Any:
    """One short call to the ACP bridge. A failure is a label, never an exception."""
    import urllib.error
    import urllib.request

    request = urllib.request.Request(
        ACP_WORKER + path,
        method=method,
        data=json.dumps(body).encode("utf-8") if body is not None else None,
        headers={"content-type": "application/json", "accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=ACP_TIMEOUT) as response:
            return json.loads(response.read().decode("utf-8"))
    except Exception:  # noqa: BLE001 - an unreachable worker is a fallback, not a 500
        return None


@app.get("/api/scorecard")
def scorecard() -> JSONResponse:
    """The offline adversarial corpus, scored by running the repository's bench."""
    return _no_store(surface.scorecard())


@app.get("/api/stream")
def stream(
    counterparty: str,
    requested_usd: float = Query(default=1.0, ge=0),
    as_of: str | None = Query(default=None),
) -> StreamingResponse:
    """The same decision, streamed one step at a time as Server-Sent Events.

    The gate runs in microseconds. This paces the frames so the sequence is
    legible -- recall, then one verdict per memory in the order the gate reached
    them, then the weighing, then the decision. Every frame carries
    ``paced: true``; the pacing is the only thing here that is not the machine's
    own timing.
    """
    resolved = _resolve(counterparty)

    def events() -> Iterator[str]:
        seq = 0

        def frame(kind: str, payload: dict[str, Any]) -> str:
            nonlocal seq
            seq += 1
            body = json.dumps({"seq": seq, "paced": TRACE_DELAY_MS > 0, **payload})
            return f"event: {kind}\ndata: {body}\n\n"

        gate = surface.gate(as_of)
        # Named "armed" rather than "open": EventSource fires a native "open"
        # event on connect, and a server event of the same name would arrive at
        # the same listener with no payload.
        yield frame(
            "armed",
            {
                "counterparty": resolved,
                "requested_usd": requested_usd,
                "as_of": as_of,
                "chain": surface.chain_view(),
                "self_address": surface.self_address,
                "label": "gate armed",
            },
        )
        memories = surface.memories(resolved, as_of=as_of)
        yield frame(
            "recall",
            {
                "count": len(memories),
                "label": f"recalled {len(memories)} memories about {_short_addr(resolved)}",
            },
        )

        judged: list[tuple[str, Any, Verdict]] = []
        for name, memory in memories:
            if TRACE_DELAY_MS:
                time.sleep(TRACE_DELAY_MS / 1000)
            verdict = (
                memory.verdict
                if isinstance(memory, MalformedMemory)
                else gate.admit(memory)
            )
            judged.append((name, memory, verdict))
            yield frame("memory", {"memory": surface.memory_view(name, memory, verdict)})

        if TRACE_DELAY_MS:
            time.sleep(TRACE_DELAY_MS / 1000)
        flag = (
            AsOfFlags(surface.flags, as_of).is_flagged(resolved)
            if as_of
            else surface.flags.is_flagged(resolved)
        )
        pairs = [(m, v) for _, m, v in judged if isinstance(m, Envelope)]
        decision = surface.policy.decide(resolved, requested_usd, pairs, flagged=flag)
        yield frame(
            "weigh",
            {
                "credit_usd": decision.credit_usd,
                "admitted": len(decision.admitted),
                "refused": len(decision.refused),
                "label": f"${decision.credit_usd:.2f} of re-derivable history",
            },
        )
        if TRACE_DELAY_MS:
            time.sleep(TRACE_DELAY_MS / 1000)
        yield frame("decision", _decision_payload(decision, judged, as_of))
        yield frame("done", {"label": "decision written"})

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


def _resolve(address: str) -> str:
    """Accept any casing of an address and answer with the one the store uses."""
    needle = address.strip().lower()
    for known in surface.counterparties():
        if known.lower() == needle:
            return known
    for entry in surface.manifest.get("cast") or []:
        if str(entry.get("address", "")).lower() == needle:
            return str(entry["address"])
    return address
