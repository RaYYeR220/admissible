"""An honest seller agent, and the memories a buyer forms about it.

It quotes, it works, it delivers. It writes nothing about itself into the
buyer's store -- which is the only structural difference between it and the
adversary next door, and the reason provenance rather than category is what the
gate keys off.
"""

from __future__ import annotations

from .agent import (
    PRICES_USD,
    CounterpartyAgent,
    Job,
    JobResult,
    promote_to_attested,
    record_outcome,
)

__all__ = [
    "PRICES_USD",
    "CounterpartyAgent",
    "Job",
    "JobResult",
    "promote_to_attested",
    "record_outcome",
]
