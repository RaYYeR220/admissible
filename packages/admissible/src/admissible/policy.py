"""From admissibility to action.

The gate answers a narrow question -- may this memory be used? -- and stops
there. This module answers the one that costs money: given everything the agent
can legitimately remember about a counterparty, does it pay, does it demand
collateral, or does it walk away?

Three properties are load-bearing, and each is a deliberate constraint rather
than an implementation detail:

**Deterministic.** No model runs here. The same admitted set always produces the
same decision, which is what makes the decision auditable a week later and
replayable from an ``as_of`` snapshot. The language model proposes an action and
narrates the outcome; it does not get a vote.

**Cited.** Every decision names the exact memories that moved it, by digest. A
number nobody can trace back to evidence is indistinguishable from a number
somebody made up, and the whole product is an argument against that.

**Inadmissible memories are shown, not hidden.** They are listed with their
refusal reason and zero weight. Silently dropping them would make the agent look
confident; showing them is what makes it possible to see the attack happening.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Iterable, Literal, Sequence

from .envelope import Envelope, Tier
from .verdicts import FORGERY_CODES, Verdict, VerdictCode

Action = Literal["pay", "escrow", "refuse"]

#: What the agent will risk on a counterparty it has no admissible evidence
#: about. Small on purpose: a stranger is not an enemy, but a stranger is not a
#: track record either, and this is the number an attacker is trying to inflate.
STRANGER_CEILING_USD = 0.05

#: How much of a first-party observation counts toward extending credit. Our own
#: eyes are worth something, but an agent that fully trusts its own unattested
#: notes can be walked up a ladder one small lie at a time.
WITNESSED_WEIGHT = 0.25

#: The total credit every WITNESSED memory in a decision may contribute between
#: them. The gate's docstring has always said the cap on how far a witnessed
#: memory may move money lives here; until this constant existed, it did not.
#: ``WITNESSED_WEIGHT`` is a discount, and a discount on an attacker-chosen
#: number is still an attacker-chosen number: one note reading
#: ``amount_usd: 1000000`` bought a $250,000 credit line, and one reading
#: ``Infinity`` bought an unbounded one. A first-hand note nobody else can check
#: is worth a few dollars of trust, and no more, however many of them there are.
WITNESSED_CEILING_USD = 5.00


@dataclass(frozen=True)
class Consideration:
    """One memory and what the gate said about it."""

    envelope: Envelope
    verdict: Verdict
    #: Dollars of credit this memory contributes. Zero for anything refused.
    weight_usd: float = 0.0

    @property
    def digest(self) -> str:
        """This memory's digest, or ``""`` when it does not have one.

        A memory refused as MALFORMED can be one whose claim cannot be
        canonicalised at all -- a non-finite number, a key that is not a string
        -- and that is frequently *why* it was refused. It still has to appear
        in the decision record, because a refused memory nobody can see is an
        attack nobody can see, so the digest degrades to empty rather than
        raising out of the audit path.
        """
        try:
            return self.envelope.digest
        except ValueError:
            return ""

    def to_dict(self) -> dict[str, Any]:
        prov = self.envelope.provenance
        return {
            "digest": self.digest,
            "tier": prov.tier.value,
            "source": prov.source,
            "actor": prov.actor_address,
            "observed_at": prov.observed_at,
            "claim": self.envelope.claim,
            "verdict": self.verdict.to_dict(),
            "weight_usd": round(self.weight_usd, 6),
            "evidence": prov.evidence.to_dict(),
        }


@dataclass(frozen=True)
class Decision:
    """What the agent will do, and exactly why."""

    action: Action
    counterparty: str
    requested_usd: float
    #: What the agent is willing to release without security.
    unsecured_usd: float
    #: What it wants held back or posted as collateral before it proceeds.
    collateral_usd: float
    considered: tuple[Consideration, ...]
    explain: str
    #: Present when the counterparty itself, rather than a single memory, is the
    #: problem. A refusal on these grounds does not soften with more evidence.
    blocked_by: dict[str, Any] | None = None
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def admitted(self) -> tuple[Consideration, ...]:
        return tuple(c for c in self.considered if c.verdict.admits)

    @property
    def refused(self) -> tuple[Consideration, ...]:
        return tuple(c for c in self.considered if not c.verdict.admits)

    @property
    def credit_usd(self) -> float:
        return round(sum(c.weight_usd for c in self.considered), 6)

    def citations(self) -> list[str]:
        """Digests of the memories that actually moved the decision."""
        return [c.digest for c in self.considered if c.weight_usd > 0]

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "counterparty": self.counterparty,
            "requested_usd": self.requested_usd,
            "unsecured_usd": round(self.unsecured_usd, 6),
            "collateral_usd": round(self.collateral_usd, 6),
            "credit_usd": self.credit_usd,
            "explain": self.explain,
            "blocked_by": self.blocked_by,
            "warnings": list(self.warnings),
            "citations": self.citations(),
            "considered": [c.to_dict() for c in self.considered],
        }


class TrustPolicy:
    """Turns admitted memories into a credit line, and a credit line into an act."""

    def __init__(
        self,
        *,
        stranger_ceiling_usd: float = STRANGER_CEILING_USD,
        witnessed_weight: float = WITNESSED_WEIGHT,
        witnessed_ceiling_usd: float = WITNESSED_CEILING_USD,
    ) -> None:
        self._stranger_ceiling = stranger_ceiling_usd
        self._witnessed_weight = witnessed_weight
        self._witnessed_ceiling = witnessed_ceiling_usd

    def decide(
        self,
        counterparty: str,
        requested_usd: float,
        judged: Sequence[tuple[Envelope, Verdict]],
        *,
        flagged: Any | None = None,
    ) -> Decision:
        """Decide what to do about one request from one counterparty.

        ``judged`` is whatever the gate returned for every memory recalled about
        this counterparty -- admitted and refused alike. Both are kept: the
        refused ones carry no weight but they are the visible evidence that
        something tried to move this decision and failed.
        """
        # A request that is not a finite positive number is not a request. The
        # arithmetic below happily released $0.05 against a NaN and paid a
        # negative amount against a negative one.
        requested_usd = max(0.0, _as_float(requested_usd))
        considered = self._weigh_all(judged)

        if flagged:
            return Decision(
                action="refuse",
                counterparty=counterparty,
                requested_usd=requested_usd,
                unsecured_usd=0.0,
                collateral_usd=0.0,
                considered=considered,
                blocked_by=_describe(flagged),
                explain=(
                    f"{_short(counterparty)} is in the FLAGGED tier. No amount of "
                    f"further evidence from this counterparty is considered until "
                    f"the flag is lifted, because the flag is about who is speaking, "
                    f"not about what was said."
                ),
            )

        credit = sum(c.weight_usd for c in considered)
        laundering = tuple(
            c for c in considered if c.verdict.code in _LAUNDERING_CODES
        )
        warnings = tuple(
            f"{c.verdict.code.value} on {c.digest[:10]} from "
            f"{_short(c.envelope.provenance.actor_address)}"
            for c in laundering
        )

        if laundering:
            # Thin evidence and forged evidence are different things, and the
            # difference decides the action. A counterparty we simply do not know
            # gets a small unsecured line; a counterparty who just presented a
            # receipt that does not exist gets nothing, regardless of how much
            # genuine history sits beside it. Collateral is protection against
            # failure, not against fraud -- someone willing to forge a receipt is
            # willing to forge the thing the collateral is meant to secure.
            lead = laundering[0]
            return Decision(
                action="refuse",
                counterparty=counterparty,
                requested_usd=requested_usd,
                unsecured_usd=0.0,
                collateral_usd=0.0,
                considered=considered,
                warnings=warnings,
                blocked_by={
                    "kind": "laundering_attempt",
                    "verdict": lead.verdict.code.value,
                    "digest": lead.digest,
                    "actor": lead.envelope.provenance.actor_address,
                    "detail": lead.verdict.detail,
                },
                explain=(
                    f"A memory offered in support of {_short(counterparty)} cites "
                    f"evidence that does not hold up: {lead.verdict.code.value} on "
                    f"{lead.digest[:10]}. {lead.verdict.explain} Refusing "
                    f"${requested_usd:.2f} and flagging the source."
                ),
            )

        if credit >= requested_usd:
            return Decision(
                action="pay",
                counterparty=counterparty,
                requested_usd=requested_usd,
                unsecured_usd=requested_usd,
                collateral_usd=0.0,
                considered=considered,
                warnings=warnings,
                explain=(
                    f"${credit:.2f} of re-derivable history covers the ${requested_usd:.2f} "
                    f"requested, across {len(self._admitted(considered))} admissible "
                    f"memories. Paying."
                ),
            )

        headroom = min(self._stranger_ceiling, requested_usd) if credit == 0 else credit
        shortfall = max(0.0, requested_usd - headroom)

        if headroom <= 0 or shortfall >= requested_usd:
            return Decision(
                action="refuse",
                counterparty=counterparty,
                requested_usd=requested_usd,
                unsecured_usd=0.0,
                collateral_usd=0.0,
                considered=considered,
                warnings=warnings,
                explain=self._explain_refusal(counterparty, requested_usd, considered),
            )

        return Decision(
            action="escrow",
            counterparty=counterparty,
            requested_usd=requested_usd,
            unsecured_usd=headroom,
            collateral_usd=shortfall,
            considered=considered,
            warnings=warnings,
            explain=(
                f"${credit:.2f} of re-derivable history against ${requested_usd:.2f} "
                f"requested. Releasing ${headroom:.2f} unsecured and holding "
                f"${shortfall:.2f} until the work lands."
            ),
        )

    # -- internals ---------------------------------------------------------------

    def _weigh_all(
        self, judged: Sequence[tuple[Envelope, Verdict]]
    ) -> tuple[Consideration, ...]:
        """Weigh a whole recall, counting each piece of evidence once.

        Weighing memory-by-memory was the single cheapest way to inflate a
        credit line in this package, and it needed no forgery at all. One
        genuine $0.25 settlement, stored under four hundred entity names, was
        four hundred admissible memories and $100 of credit -- and because
        supersession and de-duplication both key on the digest, re-wording the
        claim by a single space produced four hundred *distinct* memories citing
        the same transaction, with the same result.

        So credit is attributed to the evidence, not to the memory that cites
        it: a settlement is worth what it settled, once, no matter how many
        rows in the store point at it. Duplicates stay in ``considered`` at zero
        weight, because hiding them would hide the attack.
        """
        out: list[Consideration] = []
        counted: set[tuple[Any, ...]] = set()
        witnessed_budget = self._witnessed_ceiling
        for env, verdict in judged:
            weight = self._weight_of(env, verdict)
            if weight > 0:
                key = _evidence_key(env)
                if key in counted:
                    weight = 0.0
                else:
                    counted.add(key)
            if weight > 0 and env.tier is Tier.WITNESSED:
                # Unattested first-party notes share one budget between them, so
                # a ladder of small lies tops out instead of compounding.
                weight = min(weight, max(0.0, witnessed_budget))
                witnessed_budget -= weight
            out.append(Consideration(envelope=env, verdict=verdict, weight_usd=weight))
        return tuple(out)

    def _weight_of(self, env: Envelope, verdict: Verdict) -> float:
        """Credit contributed by one memory. Refused memories contribute nothing.

        Note there is no partial credit for a near-miss. A settlement that went
        to the wrong address is not weak evidence of reliability; it is evidence
        of nothing at all, and treating it as a fraction would be exactly the
        ladder an attacker wants.

        For an ATTESTED memory the number comes from the gate's verdict rather
        than from the claim. They are supposed to be the same number -- the gate
        refuses when they are not -- but "supposed to" is doing security work
        there, and the claim is the half an attacker writes.
        """
        if not verdict.admits:
            return 0.0

        if env.tier is Tier.ATTESTED:
            # No verified amount means the gate admitted this memory for a
            # reason other than a settlement it priced. It informs; it does not
            # underwrite.
            return max(0.0, _as_float(verdict.detail.get("verified_amount_usd")))
        if env.tier is Tier.WITNESSED:
            # A real observation that moved no money -- latency, a delivered
            # artefact. It is admissible and it is worth reading, but it does
            # not extend a credit line.
            return max(0.0, _as_float(env.claim.get("amount_usd"))) * self._witnessed_weight
        return 0.0

    @staticmethod
    def _admitted(considered: Iterable[Consideration]) -> list[Consideration]:
        return [c for c in considered if c.verdict.admits]

    def _explain_refusal(
        self, counterparty: str, requested: float, considered: tuple[Consideration, ...]
    ) -> str:
        refused = [c for c in considered if not c.verdict.admits]
        if not considered:
            return (
                f"Nothing is remembered about {_short(counterparty)} and "
                f"${requested:.2f} is above the ${self._stranger_ceiling:.2f} a "
                f"stranger gets. Refusing."
            )
        if not refused:
            return (
                f"Everything remembered about {_short(counterparty)} is admissible "
                f"but none of it settled money, so there is no credit to draw on. "
                f"Refusing ${requested:.2f}."
            )
        lead = refused[0]
        return (
            f"{len(refused)} of {len(considered)} memories about "
            f"{_short(counterparty)} failed verification, including "
            f"{lead.verdict.code.value} on {lead.digest[:10]}. "
            f"{lead.verdict.explain} Nothing admissible remains to justify "
            f"${requested:.2f}. Refusing."
        )


#: Refusals that indicate somebody actively tried to move the decision, as
#: opposed to a memory that is merely thin. These are what get an actor flagged.
#: Defined in ``verdicts`` beside the admitting allowlist so the two sets that
#: decide what happens to money can be audited side by side -- and so the gate
#: can consult the same set when it refuses to let a softer verdict stand in
#: for one of these.
_LAUNDERING_CODES = FORGERY_CODES


def laundering_attempts(decision: Decision) -> list[Consideration]:
    """Memories in this decision that look like deliberate forgery.

    Thin evidence is ordinary. A fabricated receipt is not, and the difference is
    what separates a counterparty we should be careful with from an actor we
    should stop listening to.
    """
    return [c for c in decision.considered if c.verdict.code in _LAUNDERING_CODES]


def _evidence_key(env: Envelope) -> tuple[Any, ...]:
    """What piece of evidence this memory's credit is actually drawn from.

    A settlement is identified by its transaction, a feedback record by its slot
    in a registry. Anything with neither can only be identified by itself, so it
    falls back to the digest -- which still stops the same memory being counted
    twice, just not two memories citing the same nothing.
    """
    ev = env.provenance.evidence
    if ev.tx_hash:
        return ("tx", ev.chain_id, str(ev.tx_hash).lower())
    if ev.feedback_index is not None:
        return ("feedback", ev.chain_id, str(ev.registry).lower(), ev.agent_id, ev.feedback_index)
    return ("digest", env.digest)


def _as_float(value: Any) -> float:
    """A finite float, or zero.

    ``float("inf")`` used to survive this, and an infinite credit line pays any
    request. Anything that is not a number the arithmetic below can survive is
    worth nothing, which is the only safe reading of a number we cannot read.
    """
    if isinstance(value, bool):
        return 0.0
    try:
        out = float(value)
    except (TypeError, ValueError):
        return 0.0
    return out if math.isfinite(out) else 0.0


def _short(address: str | None) -> str:
    if not address:
        return "an unnamed actor"
    return f"{address[:6]}...{address[-4:]}" if len(address) > 12 else address


def _describe(record: Any) -> dict[str, Any]:
    for attr in ("to_dict", "_asdict"):
        method = getattr(record, attr, None)
        if callable(method):
            return dict(method())
    if isinstance(record, dict):
        return record
    return {"flag": str(record)}
