"""Trust posture: the part of the agent's policy that it computes about itself.

``TrustPolicy`` ships two numbers as constants -- what a stranger may be trusted
with, and how much a first-party observation is worth. Constants are the right
default and the wrong permanent answer. An agent that has watched an actor in
its market forge a settlement should not go on extending strangers the same
unsecured line it extended before it knew that, and an agent whose own
observations have repeatedly been confirmed by settled payments has earned the
right to weigh them slightly higher.

So the numbers are computed, in the ``reflect`` node, from records the agent
already holds, and then stored as a memory like anything else. Three properties
make this safe rather than merely adaptive:

**It is arithmetic.** No model runs. The formulas are here, in one screen, and
the inputs are counts the store can reproduce.

**It shows its work.** The posture claim carries every input it was computed
from, so "why is the ceiling zero" is answered by reading the record rather than
by re-running the agent.

**It can only tighten what matters.** ``stranger_ceiling_usd`` moves down with
observed forgery and never above the library default. An adaptive parameter that
can raise its own risk appetite is a ladder an attacker climbs; this one is
bounded above by the constant it replaces.

``witnessed_weight`` may rise, but only to a hard cap and only on the strength
of promotions -- witnessed memories that a settled payment later turned into
attested ones. That is the agent being right about something checkable, not the
agent feeling more confident.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from admissible.envelope import Envelope, Provenance, Tier, digest_of, utcnow
from admissible.policy import STRANGER_CEILING_USD, WITNESSED_WEIGHT, TrustPolicy
from admissible.store import AdmissibleStore

#: Where the posture lives. One row, superseded in place, so the timeline holds
#: every posture the agent has ever held and ``as_of`` can replay which one was
#: in force when a payment was authorised.
POSTURE_CATEGORY = "posture"
POSTURE_NAME = "trust"

#: Ceiling on how far a promotion record may raise the weight of the agent's own
#: eyes. Half of an attested dollar, and no further: a first-party note is never
#: worth as much as a settlement anyone can re-derive.
MAX_WITNESSED_WEIGHT = 0.5
MIN_WITNESSED_WEIGHT = 0.05

#: How hard observed forgery bites. At a forgery rate of 0.5 -- half the
#: decisions this agent has made involved somebody presenting evidence that did
#: not hold up -- the unsecured stranger line closes entirely.
FORGERY_SENSITIVITY = 2.0

#: Pseudo-observations added to the denominator of the promotion rate before it
#: is allowed to raise a parameter. Without it, one witnessed record that got
#: promoted reads as a promotion rate of 1.0 and takes the witnessed weight
#: straight to its cap, which is an agent drawing a confident conclusion from a
#: single data point. Four is arbitrary and deliberately visible: it means the
#: first promotion is worth a fifth of what an established record is worth.
PROMOTION_PRIOR = 4.0

#: Journal op under which decisions are recorded. Read back by reflect.
DECISION_OP = "decide"

CONSOLIDATION_SOURCE = "admissible:reflect"


@dataclass(frozen=True)
class Posture:
    """The policy parameters the agent is currently operating under."""

    stranger_ceiling_usd: float
    witnessed_weight: float
    #: The counts this was derived from. Present so the number is checkable.
    decisions: int = 0
    laundering_decisions: int = 0
    forgery_rate: float = 0.0
    interactions: int = 0
    attested_interactions: int = 0
    promotion_rate: float = 0.0
    reason: str = "library defaults; nothing observed yet"
    computed_at: str = ""

    @classmethod
    def default(cls) -> "Posture":
        return cls(
            stranger_ceiling_usd=STRANGER_CEILING_USD,
            witnessed_weight=WITNESSED_WEIGHT,
        )

    def to_claim(self) -> dict[str, Any]:
        """The claim written into memory. Every field is an input or an output."""
        return {
            "kind": "trust_posture",
            "stranger_ceiling_usd": self.stranger_ceiling_usd,
            "witnessed_weight": self.witnessed_weight,
            "decisions": self.decisions,
            "laundering_decisions": self.laundering_decisions,
            "forgery_rate": self.forgery_rate,
            "interactions": self.interactions,
            "attested_interactions": self.attested_interactions,
            "promotion_rate": self.promotion_rate,
            "reason": self.reason,
            "computed_at": self.computed_at,
        }

    @classmethod
    def from_claim(cls, claim: dict[str, Any]) -> "Posture":
        base = cls.default()
        return cls(
            stranger_ceiling_usd=_as_float(
                claim.get("stranger_ceiling_usd"), base.stranger_ceiling_usd
            ),
            witnessed_weight=_as_float(claim.get("witnessed_weight"), base.witnessed_weight),
            decisions=int(claim.get("decisions") or 0),
            laundering_decisions=int(claim.get("laundering_decisions") or 0),
            forgery_rate=_as_float(claim.get("forgery_rate"), 0.0),
            interactions=int(claim.get("interactions") or 0),
            attested_interactions=int(claim.get("attested_interactions") or 0),
            promotion_rate=_as_float(claim.get("promotion_rate"), 0.0),
            reason=str(claim.get("reason") or ""),
            computed_at=str(claim.get("computed_at") or ""),
        )

    def policy(self) -> TrustPolicy:
        """The policy this posture configures. The only place it is consumed."""
        return TrustPolicy(
            stranger_ceiling_usd=self.stranger_ceiling_usd,
            witnessed_weight=self.witnessed_weight,
        )

    def diff(self, other: "Posture") -> dict[str, tuple[float, float]]:
        """Parameters that moved between two postures, for the operator's log."""
        moved: dict[str, tuple[float, float]] = {}
        for field_name in ("stranger_ceiling_usd", "witnessed_weight"):
            before, after = getattr(self, field_name), getattr(other, field_name)
            if abs(before - after) > 1e-9:
                moved[field_name] = (before, after)
        return moved

    @property
    def digest(self) -> str:
        return digest_of(self.to_claim())


def load_posture(store: AdmissibleStore) -> Posture:
    """The posture in force, or the library defaults if none was ever computed.

    A missing posture is the honest default, not an error: an agent on its first
    run has observed nothing and should behave exactly like the constants say.
    """
    record = store.recall(POSTURE_CATEGORY, POSTURE_NAME)
    if isinstance(record, Envelope) and record.claim.get("kind") == "trust_posture":
        return Posture.from_claim(record.claim)
    return Posture.default()


def compute_posture(
    store: AdmissibleStore,
    *,
    interaction_category: str = "interaction",
    now: str | None = None,
) -> Posture:
    """Derive the posture from what the store already holds.

    Two ratios, both counted out of the append-only journal and the interaction
    rows rather than out of anything self-reported:

    ``forgery_rate``    decisions in which at least one memory turned out to
                        cite evidence that did not hold up, over all decisions.
                        This is the market the agent is operating in, measured.

    ``promotion_rate``  interactions the agent witnessed first-hand that a
                        settled payment later promoted to attested, over all
                        interactions. This is the agent being checkably right.

    Both are ratios rather than counts so an agent with a long history is not
    permanently governed by one bad week, and a new agent is not immediately
    governed by one bad day either -- with two decisions and one forgery, the
    rate is 0.5 and the stranger line closes, which is the correct reaction to
    a market where half of what you have been shown was fabricated.
    """
    decisions = store.journal(op=DECISION_OP)
    total = len(decisions)
    laundering = sum(1 for record in decisions if int(record.get("laundering") or 0) > 0)
    forgery_rate = round(laundering / total, 6) if total else 0.0

    interactions = [
        env
        for env in store.recall_many(interaction_category, limit=10_000)
        if isinstance(env, Envelope)
    ]
    attested = [env for env in interactions if env.tier is Tier.ATTESTED]
    promotion_rate = round(len(attested) / len(interactions), 6) if interactions else 0.0
    # Smoothed before it is allowed to move a parameter. The raw rate is what
    # gets reported, because that is the fact; the smoothed one is what gets
    # acted on, because one confirmed observation is not a track record.
    smoothed = round(len(attested) / (len(interactions) + PROMOTION_PRIOR), 6)

    ceiling = round(
        max(0.0, STRANGER_CEILING_USD * (1.0 - FORGERY_SENSITIVITY * forgery_rate)), 6
    )
    weight = round(
        min(
            MAX_WITNESSED_WEIGHT,
            max(
                MIN_WITNESSED_WEIGHT,
                WITNESSED_WEIGHT * (1.0 + smoothed) * (1.0 - forgery_rate),
            ),
        ),
        6,
    )

    return Posture(
        stranger_ceiling_usd=ceiling,
        witnessed_weight=weight,
        decisions=total,
        laundering_decisions=laundering,
        forgery_rate=forgery_rate,
        interactions=len(interactions),
        attested_interactions=len(attested),
        promotion_rate=promotion_rate,
        reason=_reason(total, laundering, forgery_rate, ceiling, promotion_rate),
        computed_at=now or utcnow(),
    )


def store_posture(store: AdmissibleStore, posture: Posture) -> dict[str, Any]:
    """Persist the posture, superseding the previous one rather than erasing it.

    Superseding keeps the chain intact, so ``Timeline.as_of`` can answer which
    posture was in force when a given payment was authorised. A trust parameter
    that changed with no record of when would make every past decision
    unreviewable.
    """
    envelope = Envelope(
        claim=posture.to_claim(),
        provenance=Provenance(
            # The posture is the agent's own first-hand summary of its own
            # records. It is not attested -- nothing onchain says what an agent's
            # risk appetite ought to be -- and labelling it otherwise would be
            # exactly the tier laundering the gate exists to catch.
            tier=Tier.WITNESSED,
            source=CONSOLIDATION_SOURCE,
            observed_at=posture.computed_at or utcnow(),
        ),
    )
    existing = store.recall(POSTURE_CATEGORY, POSTURE_NAME)
    if existing is None:
        return store.remember(POSTURE_CATEGORY, POSTURE_NAME, envelope)
    return store.supersede(POSTURE_CATEGORY, POSTURE_NAME, envelope)


def _reason(
    decisions: int,
    laundering: int,
    forgery_rate: float,
    ceiling: float,
    promotion_rate: float,
) -> str:
    if not decisions:
        return "no decisions on record; library defaults stand"
    parts = [
        f"{laundering} of {decisions} decisions met evidence that did not hold up "
        f"(forgery rate {forgery_rate:.2f})"
    ]
    if ceiling <= 0:
        parts.append("the unsecured stranger line is closed")
    else:
        parts.append(f"strangers may draw up to ${ceiling:.4f} unsecured")
    parts.append(f"promotion rate {promotion_rate:.2f} on first-hand observations")
    return "; ".join(parts)


def _as_float(value: Any, fallback: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return fallback
