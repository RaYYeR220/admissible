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
import unicodedata
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping

from eth_utils import keccak

#: How deep a claim may nest before we stop walking it. A claim is a receipt,
#: not a document tree; the only thing that needs sixty levels is a payload
#: built to blow the interpreter's stack inside a hash function.
MAX_CLAIM_DEPTH = 64


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


def parse_instant(value: Any) -> datetime | None:
    """One ISO-8601 timestamp as an aware UTC instant, or ``None``.

    The clocks used to be compared as strings, which is only correct while every
    writer happens to use the same spelling. It is the attacker who chooses the
    spelling: ``20260201T000000Z`` is a valid ISO-8601 rendering of 1 February
    that sorts *above* ``2026-09-08T...`` because ``'0' > '-'``, so a window
    that closed seven months ago reads as still open. Comparing instants removes
    the choice.

    A naive timestamp is read as UTC rather than as local time -- every writer
    in this system stamps UTC, and guessing a local zone here would silently
    move a validity boundary by hours.
    """
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            # ISO-8601 basic format ("20260201T000000"), which fromisoformat
            # only learned in 3.11. Accepting it explicitly is safer than
            # letting it fall through to a string comparison.
            for fmt in ("%Y%m%dT%H%M%S%z", "%Y%m%dT%H%M%S", "%Y%m%d"):
                try:
                    parsed = datetime.strptime(text, fmt)
                    break
                except ValueError:
                    continue
            else:
                return None
    else:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _canonical_payload(value: Any, depth: int = 0) -> Any:
    """Validate and normalise one claim before it is hashed.

    Three things a plain ``json.dumps`` lets through, each of which breaks the
    promise that somebody else can re-derive this digest:

    * **Non-string keys.** ``json.dumps`` coerces them, so ``{1: "a"}`` and
      ``{"1": "a"}`` -- and ``{True: "a"}`` and ``{"true": "a"}`` -- hash
      identically. Two different claims, one digest, is a collision.
    * **Unicode that is equal on screen and different in bytes.** NFC and NFD
      spellings of the same name render the same to a reviewer and hash
      differently, so they are normalised to NFC before hashing.
    * **Values no other JSON reader will accept.** ``NaN`` and ``Infinity`` are
      Python extensions, not JSON; a digest over them cannot be recomputed by a
      conforming parser, let alone by a contract.

    Raises :class:`ValueError` for all of them, which every caller already
    treats as :data:`~admissible.verdicts.VerdictCode.MALFORMED`.
    """
    if depth > MAX_CLAIM_DEPTH:
        raise ValueError(f"claim nests deeper than {MAX_CLAIM_DEPTH} levels")
    if isinstance(value, str):
        normalised = unicodedata.normalize("NFC", value)
        try:
            normalised.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError(f"claim carries text that is not encodable: {exc}") from exc
        return normalised
    if isinstance(value, bool) or value is None or isinstance(value, int):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("claim carries a non-finite number, which is not JSON")
        return value
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"claim key {key!r} is not a string")
            canonical_key = _canonical_payload(key, depth + 1)
            if canonical_key in out:
                raise ValueError(f"claim key {canonical_key!r} appears twice")
            out[canonical_key] = _canonical_payload(item, depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [_canonical_payload(item, depth + 1) for item in value]
    raise ValueError(f"claim carries a {type(value).__name__}, which is not JSON")


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
        """Parse an evidence block, refusing anything that is not one.

        Raises :class:`ValueError` rather than letting a hostile shape through:
        this block is read straight out of a row an attacker may have written,
        and ``cls(**raw)`` on a list is an ``AttributeError`` on the payment
        path. Every malformed shape has to arrive at the gate as a refusal.
        """
        if raw is None:
            return cls()
        if not isinstance(raw, Mapping):
            raise ValueError(f"evidence must be an object, got {type(raw).__name__}")
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
        """Parse a provenance block. Every malformed shape is a ``ValueError``.

        A missing ``tier`` used to raise ``KeyError`` and a provenance that was
        a list used to raise ``TypeError``, neither of which the gate catches --
        so a body an attacker controls could crash the decision instead of
        being refused by it. There is exactly one failure mode here now, and
        the gate maps it to MALFORMED.
        """
        if not isinstance(raw, Mapping):
            raise ValueError(f"provenance must be an object, got {type(raw).__name__}")
        for required in ("tier", "source"):
            if required not in raw:
                raise ValueError(f"provenance is missing {required!r}")
        try:
            tier = Tier(raw["tier"])
        except ValueError as exc:
            raise ValueError(f"unknown tier {raw['tier']!r}") from exc
        for key in ("source", "actor_address", "actor_handle", "observed_at",
                    "valid_from", "valid_to", "supersedes"):
            value = raw.get(key)
            if value is not None and not isinstance(value, str):
                raise ValueError(f"provenance.{key} must be a string, got {type(value).__name__}")
        return cls(
            tier=tier,
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

    Everything that would make that promise false is rejected first -- see
    :func:`_canonical_payload`. ``allow_nan=False`` is the belt to that braces:
    a digest a conforming JSON reader cannot reproduce is not a commitment,
    it is a number.
    """
    return json.dumps(
        _canonical_payload(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
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
        stored = body["provenance"].get("digest") if isinstance(body["provenance"], Mapping) else None
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
        """Was this claim true of the world at ``when`` (valid time)?

        Compared as instants, not as strings. A bound we cannot parse closes the
        window rather than opening it: an unreadable expiry is not an absent one.
        """
        moment = parse_instant(when)
        if moment is None:
            return False
        for bound, closes_before in ((self.provenance.valid_from, True),
                                     (self.provenance.valid_to, False)):
            if not bound:
                continue
            edge = parse_instant(bound)
            if edge is None:
                return False
            if (moment < edge) if closes_before else (moment >= edge):
                return False
        return True

    def was_known_at(self, when: str) -> bool:
        """Had we learned this claim by ``when`` (transaction time)?

        Same instant comparison as :meth:`is_valid_at`, and the same fail-closed
        rule: a timestamp we cannot read means we cannot claim to have known it.
        """
        observed = parse_instant(self.provenance.observed_at)
        moment = parse_instant(when)
        if observed is None or moment is None:
            return False
        return observed <= moment


_TIER_RANK.update({Tier.HEARSAY: 0, Tier.WITNESSED: 1, Tier.ATTESTED: 2})
