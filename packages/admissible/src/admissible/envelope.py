"""The provenance envelope.

A memory is not a fact. It is a *claim*, plus the story of how we came to hold
it. That story is what decides whether the claim may move money, so it travels
with the claim rather than in a side table.

The envelope rides inside Sibyl Memory's own ``entities.body`` column, which is
free-form JSON under a ``json_valid`` CHECK. Every write still goes through
``set_entity``; it is still indexed by FTS5; it still lives under
``UNIQUE (tenant_id, category, name)``. We extend the primitive, we do not fork it.

Two clocks
----------
``observed_at`` is *transaction time* -- when we learned the claim.
``valid_from`` / ``valid_to`` is *valid time* -- when the claim was true of the world.

Keeping both is what makes ``as_of`` replay honest: you can ask what the agent
knew at the moment it decided, rather than what we know now. It is also the
cheapest poisoning tell there is, because a memory injected today that claims to
have been true last month has to say so in a field a verifier can read.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping

from eth_utils import keccak


class Tier(str, Enum):
    """How much weight a memory is allowed to carry.

    The ordering matters: ``HEARSAY < WITNESSED < ATTESTED``.
    """

    #: Someone asserted it. Nothing backs it. Never moves money on its own.
    HEARSAY = "HEARSAY"
    #: Our own agent observed it first-hand -- it ran the job and saw the result.
    WITNESSED = "WITNESSED"
    #: Bound to onchain state anyone can re-derive: a settled payment, a
    #: reputation record whose committed hash matches this envelope.
    ATTESTED = "ATTESTED"

    @property
    def rank(self) -> int:
        return _TIER_RANK[self]


_TIER_RANK: dict["Tier", int] = {}


def utcnow() -> str:
    """ISO-8601 UTC with a trailing Z, matching Sibyl's own timestamp format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@dataclass(frozen=True)
class Evidence:
    """Where onchain to look to re-derive the claim.

    Empty for HEARSAY. Present-but-wrong is the interesting case: that is what a
    forged memory looks like, and it is why the gate re-reads the chain instead
    of trusting these fields.
    """

    chain_id: int | None = None
    tx_hash: str | None = None
    block: int | None = None
    #: ERC-8004 reputation record, when the claim is backed by feedback.
    registry: str | None = None
    agent_id: int | None = None
    feedback_index: int | None = None
    #: What the evidence is supposed to show, e.g. "x402:settlement".
    kind: str | None = None

    _FIELDS = (
        "chain_id",
        "tx_hash",
        "block",
        "registry",
        "agent_id",
        "feedback_index",
        "kind",
    )

    def to_dict(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in self._FIELDS if getattr(self, k) is not None}

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any] | None) -> "Evidence":
        if not raw:
            return cls()
        return cls(**{k: v for k, v in raw.items() if k in cls._FIELDS})

    @property
    def is_empty(self) -> bool:
        return self.tx_hash is None and self.feedback_index is None


@dataclass(frozen=True)
class Provenance:
    """The story of a claim."""

    tier: Tier
    #: How it reached us: "x402:settlement", "agent:self", "peer:reference",
    #: "tool:fetch", "user". Kept as a string so new sources do not need a
    #: schema change -- the gate keys off `tier` and `evidence`, not off this.
    source: str
    #: Who asserted it. An address when we have one; that is the join key into
    #: the FLAGGED tier, which is why it is not merely a handle.
    actor_address: str | None = None
    actor_handle: str | None = None
    #: Transaction time -- when we learned it.
    observed_at: str = field(default_factory=utcnow)
    #: Valid time -- when it was true of the world.
    valid_from: str | None = None
    valid_to: str | None = None
    #: Digest of the envelope this one invalidates. Non-destructive: the old
    #: record is archived with a reason, never deleted.
    supersedes: str | None = None
    evidence: Evidence = field(default_factory=Evidence)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "tier": self.tier.value,
            "source": self.source,
            "observed_at": self.observed_at,
        }
        for key in ("actor_address", "actor_handle", "valid_from", "valid_to", "supersedes"):
            value = getattr(self, key)
            if value is not None:
                out[key] = value
        ev = self.evidence.to_dict()
        if ev:
            out["evidence"] = ev
        return out

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "Provenance":
        return cls(
            tier=Tier(raw["tier"]),
            source=raw["source"],
            actor_address=raw.get("actor_address"),
            actor_handle=raw.get("actor_handle"),
            observed_at=raw.get("observed_at") or utcnow(),
            valid_from=raw.get("valid_from"),
            valid_to=raw.get("valid_to"),
            supersedes=raw.get("supersedes"),
            evidence=Evidence.from_dict(raw.get("evidence")),
        )


def canonical(payload: Any) -> bytes:
    """Deterministic bytes for a claim.

    Sorted keys, no incidental whitespace, UTF-8. Two agents that agree on the
    claim must produce byte-identical output, because this is what gets hashed
    into ``feedbackHash`` onchain and compared back later.
    """
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def digest_of(claim: Any) -> str:
    """keccak256 of the canonical claim, 0x-prefixed.

    keccak256 rather than SHA-256 so the value can be committed to and compared
    inside a Solidity contract without a conversion step.
    """
    return "0x" + keccak(canonical(claim)).hex()


@dataclass(frozen=True)
class Envelope:
    """A claim plus its provenance. This is what a memory actually is here."""

    claim: dict[str, Any]
    provenance: Provenance

    @property
    def digest(self) -> str:
        return digest_of(self.claim)

    @property
    def tier(self) -> Tier:
        return self.provenance.tier

    def to_body(self) -> dict[str, Any]:
        """The JSON that goes into ``entities.body``."""
        prov = self.provenance.to_dict()
        prov["digest"] = self.digest
        return {"claim": self.claim, "provenance": prov}

    @classmethod
    def from_body(cls, body: Mapping[str, Any]) -> "Envelope":
        """Parse a stored body. Raises ValueError on anything unrecognisable.

        Callers treat that as :data:`VerdictCode.MALFORMED` rather than crashing:
        an unparseable memory is a refusal, not an exception.
        """
        if not isinstance(body, Mapping) or "claim" not in body or "provenance" not in body:
            raise ValueError("not a provenance envelope")
        claim = body["claim"]
        if not isinstance(claim, dict):
            raise ValueError("claim must be an object")
        env = cls(claim=claim, provenance=Provenance.from_dict(body["provenance"]))
        stored = body["provenance"].get("digest")
        if stored is not None and stored != env.digest:
            # The claim was edited after it was sealed. Surfacing it here means
            # the gate sees a tamper signal even before it reaches the chain.
            raise ValueError(f"digest mismatch: stored {stored}, computed {env.digest}")
        return env

    def superseded_by(self, claim: dict[str, Any], **prov: Any) -> "Envelope":
        """Build the envelope that replaces this one, keeping the chain intact."""
        base = replace(self.provenance, supersedes=self.digest, observed_at=utcnow(), **prov)
        return Envelope(claim=claim, provenance=base)

    def is_valid_at(self, when: str) -> bool:
        """Was this claim true of the world at ``when`` (valid time)?"""
        if self.provenance.valid_from and when < self.provenance.valid_from:
            return False
        if self.provenance.valid_to and when >= self.provenance.valid_to:
            return False
        return True

    def was_known_at(self, when: str) -> bool:
        """Had we learned this claim by ``when`` (transaction time)?"""
        return self.provenance.observed_at <= when


_TIER_RANK.update({Tier.HEARSAY: 0, Tier.WITNESSED: 1, Tier.ATTESTED: 2})
