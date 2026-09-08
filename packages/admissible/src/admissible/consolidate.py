"""Consolidation: many interactions, one dossier, no model in the loop.

An agent that has worked with a counterparty forty times should not have to
re-read forty rows to answer "can I trust them". It should read one. That is
what this module builds -- and it builds it by *folding*, not by summarising:
counts, sums, extremes, histograms. Every number in the dossier is
re-derivable from the same inputs by anyone holding the database.

The reason it is arithmetic rather than an LLM call is not cost. A dossier
decides whether money moves. A summary produced by a model is a new claim with
no provenance of its own, generated from text that may itself have been planted
-- exactly the class of thing the rest of this package refuses to admit. A fold
inherits its inputs' provenance and can be recomputed to check it.

Which is why the dossier's tier is the **weakest** tier among its inputs. The
aggregate mixes an attested settlement with a stranger's assertion, and the sum
of those is not attested. ``attested_totals`` is carried alongside for the
subtotal that *is*, so failing closed at the top level costs nothing at the
bottom.
"""

from __future__ import annotations

from collections import Counter
from decimal import Decimal, InvalidOperation
from typing import Any, Iterable

from .envelope import Envelope, Evidence, Provenance, Tier, utcnow
from .store import AdmissibleStore

#: Where per-interaction records live by default. A deployment with a different
#: vocabulary passes its own; nothing here hardcodes a schema.
INTERACTION_CATEGORY = "interaction"
#: Where the folded dossier is written.
DOSSIER_CATEGORY = "dossier"
#: Claim keys the fold reads. Named so a caller can see the contract at a glance.
_OUTCOME_KEY = "outcome"
_AMOUNT_KEY = "amount"
_ASSET_KEYS = ("asset", "currency", "token")
_UNKNOWN_ASSET = "UNKNOWN"

#: How this dossier came to exist. Not "agent:self": nobody observed the
#: dossier, it was computed, and the source string should say so.
CONSOLIDATION_SOURCE = "admissible:consolidate"


def consolidate(
    store: AdmissibleStore,
    counterparty: str,
    *,
    interaction_category: str = INTERACTION_CATEGORY,
    dossier_category: str = DOSSIER_CATEGORY,
    write: bool = True,
    now: str | None = None,
    limit: int = 10_000,
) -> Envelope:
    """Fold every record about ``counterparty`` into one dossier envelope.

    Reads two sources and neither alone is sufficient. Entities in
    ``interaction_category`` carry the claims -- amounts, outcomes, evidence.
    Journal records carry the *writes*, including writes whose entity has since
    been superseded or renamed, which is how ``journal_events`` stays the count
    of record. The dossier reports both, and reports them separately, because a
    gap between them is itself a signal.

    ``now`` is injectable so the result is reproducible: the fold is
    deterministic, but ``observed_at`` would not be. The digest covers only the
    claim, so two folds of the same data always agree on it regardless.

    Writes the dossier at ``(dossier_category, counterparty)`` unless
    ``write=False``. Dossier records are excluded from their own inputs, so
    consolidating twice does not compound.
    """
    envelopes = _interactions(store, counterparty, interaction_category, limit)
    records = [
        rec
        for rec in store.journal(counterparty=counterparty, limit=limit)
        if rec.get("category") != dossier_category
    ]

    outcomes: Counter[str] = Counter()
    tiers: Counter[str] = Counter()
    sources: Counter[str] = Counter()
    totals: dict[str, Decimal] = {}
    attested: dict[str, Decimal] = {}
    observed: list[str] = []
    strongest_key: tuple[int, str, str] | None = None
    evidence: Evidence | None = None

    for env in envelopes:
        prov = env.provenance
        tiers[prov.tier.value] += 1
        sources[prov.source] += 1
        observed.append(prov.observed_at)

        outcome = env.claim.get(_OUTCOME_KEY)
        if isinstance(outcome, str) and outcome:
            outcomes[outcome] += 1

        amount = _decimal(env.claim.get(_AMOUNT_KEY))
        if amount is not None:
            asset = _asset(env.claim)
            totals[asset] = totals.get(asset, Decimal(0)) + amount
            if prov.tier is Tier.ATTESTED:
                attested[asset] = attested.get(asset, Decimal(0)) + amount

        if not prov.evidence.is_empty:
            # Rank by tier, then by recency, then by digest so a tie never
            # depends on row order.
            key = (prov.tier.rank, prov.observed_at, env.digest)
            if strongest_key is None or key > strongest_key:
                strongest_key, evidence = key, prov.evidence

    observed.extend(
        rec["observed_at"] for rec in records if isinstance(rec.get("observed_at"), str)
    )

    claim: dict[str, Any] = {
        "counterparty": counterparty,
        "interactions": len(envelopes),
        "journal_events": len(records),
        "outcomes": dict(sorted(outcomes.items())),
        "tiers": dict(sorted(tiers.items())),
        "sources": dict(sorted(sources.items())),
        "totals": {k: str(v) for k, v in sorted(totals.items())},
        "attested_totals": {k: str(v) for k, v in sorted(attested.items())},
        "first_seen": min(observed) if observed else None,
        "last_seen": max(observed) if observed else None,
        "strongest_evidence": evidence.to_dict() if evidence else None,
    }

    dossier = Envelope(
        claim=claim,
        provenance=Provenance(
            tier=_floor_tier(envelopes),
            source=CONSOLIDATION_SOURCE,
            observed_at=now or utcnow(),
            valid_from=claim["first_seen"],
            evidence=evidence or Evidence(),
        ),
    )
    if write:
        store.remember(dossier_category, counterparty, dossier)
    return dossier


def summarize(dossier: Envelope) -> str:
    """One line about a counterparty, built from the dossier's own numbers.

    Deterministic: same dossier, same string, every time. Written to be read by
    a human in a terminal and by an agent in a prompt, so it leads with the
    thing that decides -- how many, how much, and how well-backed.
    """
    claim = dossier.claim
    who = claim.get("counterparty", "unknown counterparty")
    n = claim.get("interactions", 0)
    if not n:
        return f"{who}: no recorded interactions."

    outcomes = claim.get("outcomes") or {}
    outcome_part = ", ".join(f"{k} {v}" for k, v in sorted(outcomes.items()))
    totals = claim.get("totals") or {}
    total_part = ", ".join(f"{v} {k}" for k, v in sorted(totals.items()))
    tiers = claim.get("tiers") or {}
    tier_part = "/".join(
        f"{k} {tiers[k]}" for k in sorted(tiers, key=lambda t: -Tier(t).rank)
    )

    headline = f"{who}: {n} interaction{'s' if n != 1 else ''}"
    parts = [f"{headline} ({outcome_part})" if outcome_part else headline]
    if total_part:
        parts.append(f"totalling {total_part}")
    parts.append(f"tiers {tier_part}")
    if claim.get("strongest_evidence"):
        kind = claim["strongest_evidence"].get("kind") or "onchain"
        parts.append(f"best evidence {kind}")
    window = _window(claim)
    if window:
        parts.append(window)
    return "; ".join(parts) + f". Dossier admitted as {dossier.tier.value}."


# ----------------------------------------------------------------------
# Internals
# ----------------------------------------------------------------------
def _interactions(
    store: AdmissibleStore, counterparty: str, category: str, limit: int
) -> list[Envelope]:
    """Interaction envelopes about this counterparty, oldest observation first.

    Malformed rows are skipped, not counted: a body we cannot parse tells us
    nothing about the counterparty, and quietly folding it in as a bare
    "interaction" would inflate the count with a record nobody can read.
    """
    out = [
        env
        for env in store.recall_many(category, limit=limit)
        if isinstance(env, Envelope) and env.claim.get("counterparty") == counterparty
    ]
    out.sort(key=lambda e: (e.provenance.observed_at, e.digest))
    return out


def _decimal(value: Any) -> Decimal | None:
    """Amounts are money. Parse them exactly or not at all.

    Floats are refused on purpose: a total assembled out of binary floats is not
    a total anyone should be asked to sign off on.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, float):
        return None
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        return None


def _asset(claim: dict[str, Any]) -> str:
    for key in _ASSET_KEYS:
        value = claim.get(key)
        if isinstance(value, str) and value:
            return value
    return _UNKNOWN_ASSET


def _floor_tier(envelopes: Iterable[Envelope]) -> Tier:
    """The weakest tier present. HEARSAY when there is nothing to fold.

    An empty dossier is not attested-by-default; it is an absence of evidence,
    which is the bottom of the range.
    """
    tiers = [env.provenance.tier for env in envelopes]
    if not tiers:
        return Tier.HEARSAY
    return min(tiers, key=lambda t: t.rank)


def _window(claim: dict[str, Any]) -> str:
    first, last = claim.get("first_seen"), claim.get("last_seen")
    if not first:
        return ""
    if first == last:
        return f"seen {first[:10]}"
    return f"first seen {first[:10]}, last seen {last[:10]}"
