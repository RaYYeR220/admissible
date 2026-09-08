"""The adversary: an agent that writes into the memory another agent reads.

Three laundering vectors and a return visit. It holds a handle on the same
Sibyl Memory database the buyer reads, which is the deployment and the attack
surface at once -- two agents coordinating through one store, one of them
hostile.
"""

from __future__ import annotations

from .agent import (
    BORROWED_TX,
    FABRICATED_TX,
    INJECTED_INSTRUCTION,
    LaunderedMemory,
    PoisonerAgent,
)

__all__ = [
    "BORROWED_TX",
    "FABRICATED_TX",
    "INJECTED_INSTRUCTION",
    "LaunderedMemory",
    "PoisonerAgent",
]
