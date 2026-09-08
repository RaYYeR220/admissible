"""An honest seller.

It quotes a price, it does the work, it returns the result, and it never writes
anything about itself into the buyer's memory. That last part is the whole
difference between this file and ``apps/poisoner``: both are agents the buyer
transacts with, both produce claims that end up in the buyer's store, and only
one of them puts them there itself.

What the buyer remembers about this agent comes from two places, in this order:

* **WITNESSED**, when the buyer runs a job and sees the result. First-hand, and
  worth a fraction of a dollar of credit per dollar of work, because our own
  eyes are worth something and an agent that fully trusts its own unattested
  notes can be walked up a ladder one small lie at a time.
* **ATTESTED**, once a payment settles. The witnessed record is *superseded* --
  not deleted, not edited -- by one carrying the transaction that settled it, so
  the promotion is a link in a chain a stranger can walk rather than a field
  somebody changed.

The work is trivial on purpose. The point being demonstrated is what happens to
the memory of the work, not the work.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from admissible.envelope import Envelope, Evidence, Provenance, Tier, utcnow
from admissible.store import AdmissibleStore

from ..addresses import (
    BASE_CHAIN_ID,
    OUR_AGENT,
    OUR_HANDLE,
    SIBYLCAP,
    SIBYLCAP_HANDLE,
)
from ..agent.state import INTERACTION_CATEGORY

#: The three real published x402 tiers of the agent this one stands in for.
PRICES_USD = {"lookup": 0.02, "research-brief": 0.25, "deep-report": 0.5}


@dataclass(frozen=True)
class Job:
    """What the buyer is asking for."""

    service: str
    payload: str
    requested_usd: float

    @property
    def id(self) -> str:
        """Stable identity for a job, so a repeat of the same job is the same row."""
        seed = f"{self.service}|{self.payload}|{self.requested_usd}"
        return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class JobResult:
    """What came back."""

    job: Job
    seller: str
    seller_handle: str
    delivered: bool
    artifact: dict[str, Any]
    latency_ms: int
    #: Anything the seller attached to the result. Empty here. The poisoner's
    #: first vector is this field, which is why it exists on the honest agent
    #: too -- the buyer cannot tell the two apart by shape.
    attachments: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "job": {
                "id": self.job.id,
                "service": self.job.service,
                "requested_usd": self.job.requested_usd,
            },
            "seller": self.seller,
            "delivered": self.delivered,
            "artifact": self.artifact,
            "latency_ms": self.latency_ms,
            "attachments": self.attachments,
        }


class CounterpartyAgent:
    """A seller that does small, checkable work for a fixed price."""

    def __init__(
        self,
        address: str = SIBYLCAP,
        handle: str = SIBYLCAP_HANDLE,
        *,
        prices: dict[str, float] | None = None,
    ) -> None:
        self.address = address
        self.handle = handle
        self.prices = dict(prices or PRICES_USD)

    # ------------------------------------------------------------------
    def quote(self, service: str) -> float:
        """Price for a service. Raises on an unknown one rather than guessing."""
        if service not in self.prices:
            raise KeyError(f"{self.handle} does not sell {service!r}")
        return self.prices[service]

    def pitch(self, service: str) -> str:
        """What this agent says about itself when offering work.

        Plain, checkable, and carrying no instruction to whoever reads it. Worth
        comparing against ``PoisonerAgent.pitch``, which is the same field with
        an injection in it -- the buyer's model reads both the same way, and the
        gate reads neither.
        """
        return (
            f"{self.handle} offers {service} for ${self.quote(service):.2f} in USDC on "
            f"Base. Settlement is x402; every completed job leaves a transfer you can "
            f"verify yourself. Address {self.address}."
        )

    def perform(self, job: Job) -> JobResult:
        """Do the work. Deterministic, offline, and small enough to check by hand."""
        text = job.payload
        artifact = {
            "service": job.service,
            "input_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "words": len(text.split()),
            "characters": len(text),
            "summary": _first_sentence(text),
        }
        return JobResult(
            job=job,
            seller=self.address,
            seller_handle=self.handle,
            delivered=True,
            artifact=artifact,
            # Fixed rather than measured: a timing that varies run to run would
            # make the demo's output non-reproducible for no gain.
            latency_ms=1200,
        )


# ----------------------------------------------------------------------
# Memory, written by the buyer about what it saw
# ----------------------------------------------------------------------
def record_outcome(
    store: AdmissibleStore,
    result: JobResult,
    *,
    observer: str = OUR_AGENT,
    observer_handle: str = OUR_HANDLE,
    amount_usd: float | None = None,
) -> tuple[str, str, Envelope]:
    """Write what the buyer observed as a WITNESSED memory.

    Written by the buyer, about the seller, from first-hand observation -- which
    is what WITNESSED means and why the actor on the provenance is the buyer
    rather than the seller. A record whose actor is the party it flatters is a
    record with a motive.

    Returns ``(category, name, envelope)`` so the caller can supersede it later
    without re-deriving the name.
    """
    amount = result.job.requested_usd if amount_usd is None else amount_usd
    claim = {
        "counterparty": result.seller,
        "outcome": "delivered" if result.delivered else "failed",
        "amount_usd": 0.0,
        "service": result.job.service,
        "job_id": result.job.id,
        "latency_ms": result.latency_ms,
        "artifact_sha256": result.artifact.get("input_sha256"),
        "quoted_usd": amount,
    }
    envelope = Envelope(
        claim=claim,
        provenance=Provenance(
            tier=Tier.WITNESSED,
            source="agent:self",
            actor_address=observer,
            actor_handle=observer_handle,
        ),
    )
    name = f"{result.seller}-{result.job.id}"
    store.remember(INTERACTION_CATEGORY, name, envelope)
    return INTERACTION_CATEGORY, name, envelope


def promote_to_attested(
    store: AdmissibleStore,
    category: str,
    name: str,
    *,
    counterparty: str,
    amount_usd: float,
    tx_hash: str,
    block: int | None = None,
    chain_id: int = BASE_CHAIN_ID,
    observer: str = OUR_AGENT,
    observer_handle: str = OUR_HANDLE,
    service: str = "unspecified",
    valid_from: str | None = None,
) -> Envelope:
    """Promote a witnessed record to attested, once a payment has settled.

    ``supersede`` rather than a second ``remember``: the old record is archived
    with a reason and the new one names it by digest, so "this used to be a note
    and became a proof" is a link in a chain and not a field somebody edited.
    The old digest stays refusable -- re-offering the pre-promotion version
    afterwards is a replay, and the gate answers SUPERSEDED.

    The claim must match the settlement exactly. ``amount_usd`` is compared
    against the transfer in base units with zero tolerance, so a promotion built
    from anything other than the receipt will fail its own re-derivation on the
    next run -- which is the correct outcome, and better than a promotion that
    quietly rounds.
    """
    claim = {
        "counterparty": counterparty,
        "outcome": "settled",
        "amount_usd": amount_usd,
        "amount": f"{amount_usd}",
        "asset": "USDC",
        "service": service,
    }
    envelope = Envelope(
        claim=claim,
        provenance=Provenance(
            tier=Tier.ATTESTED,
            source="x402:settlement",
            actor_address=observer,
            actor_handle=observer_handle,
            observed_at=utcnow(),
            valid_from=valid_from,
            evidence=Evidence(
                chain_id=chain_id,
                tx_hash=tx_hash,
                block=block,
                kind="x402:settlement",
            ),
        ),
    )
    store.supersede(category, name, envelope)
    return envelope


def _first_sentence(text: str) -> str:
    stripped = text.strip()
    if not stripped:
        return ""
    for stop in (". ", "? ", "! "):
        head, sep, _ = stripped.partition(stop)
        if sep:
            return head + sep.strip()
    return stripped[:160]
