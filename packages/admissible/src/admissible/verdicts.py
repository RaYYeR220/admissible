"""Admissibility verdicts.

Deliberately shaped like Sibyl Memory's own verdict contract: a search or a
recall never silently returns nothing useful. It returns a code, the tokens or
fields that caused it, and a sentence a human can read. We keep that discipline
for money decisions -- an agent that refuses to pay must be able to say exactly
which clause of the evidence failed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class VerdictCode(str, Enum):
    """Outcome of putting one memory through the admission gate."""

    ADMISSIBLE = "admissible"
    INADMISSIBLE_HEARSAY = "inadmissible_hearsay"
    EVIDENCE_NOT_FOUND = "evidence_not_found"
    DIGEST_MISMATCH = "digest_mismatch"
    COUNTERPARTY_MISMATCH = "counterparty_mismatch"
    AMOUNT_MISMATCH = "amount_mismatch"
    SUPERSEDED = "superseded"
    FLAGGED_SOURCE = "flagged_source"
    EXPIRED = "expired"
    BACKDATED = "backdated"
    MALFORMED = "malformed"
    CHAIN_UNREACHABLE = "chain_unreachable"


#: Codes that permit a memory to justify moving money. Everything else fails
#: closed. This tuple is the whole security boundary -- keep it short and keep
#: it here, so a reviewer can audit the allowlist in one glance.
ADMITTING_CODES: tuple[VerdictCode, ...] = (VerdictCode.ADMISSIBLE,)

#: Refusals that mean somebody actively tried to move the decision, as opposed
#: to a memory that is merely thin or merely stale. The decision policy refuses
#: outright on these rather than escrowing, and the gate will not let a softer
#: verdict be returned in their place.
#:
#: It sits beside :data:`ADMITTING_CODES` on purpose: these two sets are the
#: only places in the package where a verdict changes what happens to money, and
#: a reviewer should be able to read both without opening a second file.
FORGERY_CODES: frozenset[VerdictCode] = frozenset(
    {
        VerdictCode.EVIDENCE_NOT_FOUND,
        VerdictCode.COUNTERPARTY_MISMATCH,
        VerdictCode.AMOUNT_MISMATCH,
        VerdictCode.DIGEST_MISMATCH,
        VerdictCode.BACKDATED,
    }
)

_EXPLANATIONS: dict[VerdictCode, str] = {
    VerdictCode.ADMISSIBLE: (
        "The claim was re-derived from onchain evidence and the evidence digest "
        "matches what was recorded when the memory was written."
    ),
    VerdictCode.INADMISSIBLE_HEARSAY: (
        "The claim rests only on someone's assertion. Nothing corroborates it, so "
        "it may inform a conversation but it may not move money."
    ),
    VerdictCode.EVIDENCE_NOT_FOUND: (
        "The memory cites onchain evidence that does not exist at the given "
        "location. Either it was fabricated or it was written against a different chain."
    ),
    VerdictCode.DIGEST_MISMATCH: (
        "The evidence exists but its committed hash does not match this claim. The "
        "memory was altered after it was attested."
    ),
    VerdictCode.COUNTERPARTY_MISMATCH: (
        "The cited transaction is real but it does not involve the counterparty the "
        "claim is about."
    ),
    VerdictCode.AMOUNT_MISMATCH: (
        "The cited transaction is real and involves the right counterparty, but it "
        "does not settle the amount the claim asserts."
    ),
    VerdictCode.SUPERSEDED: (
        "A later memory invalidated this one. The superseding record is cited so the "
        "history stays auditable rather than being deleted."
    ),
    VerdictCode.FLAGGED_SOURCE: (
        "The actor who asserted this claim is in the FLAGGED tier. Everything they "
        "sourced is demoted until it is independently re-derived."
    ),
    VerdictCode.EXPIRED: (
        "The claim carried a validity window and that window has closed. It is true "
        "history, but it is not current fact."
    ),
    VerdictCode.BACKDATED: (
        "The memory says it was observed long before this store wrote it down. "
        "Its own two clocks disagree, which is the shape of a record injected now "
        "and dressed up as old."
    ),
    VerdictCode.MALFORMED: (
        "The memory is not a well-formed provenance envelope, so there is nothing to "
        "verify against."
    ),
    VerdictCode.CHAIN_UNREACHABLE: (
        "The chain could not be read, so admissibility is unknown. Unknown is not "
        "yes: the gate refuses rather than assuming."
    ),
}


@dataclass(frozen=True, slots=True)
class Verdict:
    """Why one memory may or may not move money."""

    code: VerdictCode
    #: Envelope fields that decided it, e.g. ``("provenance.evidence.tx_hash",)``.
    fields: tuple[str, ...] = ()
    #: Free-form detail: the digest we expected, the address we found, and so on.
    detail: dict[str, Any] = field(default_factory=dict)

    @property
    def admits(self) -> bool:
        """True when this memory is allowed to justify a money decision."""
        return self.code in ADMITTING_CODES

    @property
    def explain(self) -> str:
        """A sentence a human -- or a judge -- can read without the source."""
        return _EXPLANATIONS[self.code]

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code.value,
            "admits": self.admits,
            "fields": list(self.fields),
            "detail": self.detail,
            "explain": self.explain,
        }

    def __str__(self) -> str:  # pragma: no cover - display only
        return f"{self.code.value}({','.join(self.fields)})"


def admissible(**detail: Any) -> Verdict:
    return Verdict(VerdictCode.ADMISSIBLE, detail=detail)


def refuse(code: VerdictCode, *fields: str, **detail: Any) -> Verdict:
    if code in ADMITTING_CODES:
        raise ValueError(f"{code} admits; use admissible() instead")
    return Verdict(code, fields=tuple(fields), detail=detail)
