"""The buyer: a LangGraph agent that hires other agents and pays them.

    perceive -> recall -> admit -> decide -> act -> attest -> reflect -> consolidate

Its memory is a Sibyl Memory database reached through ``SibylStore``, the
first-party LangGraph ``BaseStore`` adapter. Its decisions come from
``admissible``: the gate re-derives every memory from evidence, and a
deterministic policy turns what survives into pay, escrow or refuse.

The model proposes and narrates. It cannot reach the signer -- see
``rails.py``, which imports a ``Decision`` and the standard library and nothing
that a model has touched.
"""

from __future__ import annotations

from .narrator import Narrator, Offer, Proposal, StubNarrator, VeniceNarrator, build_narrator
from .nodes import AgentDeps, build_nodes
from .posture import Posture, compute_posture, load_posture, store_posture
from .rails import PaymentRail, Receipt, RefusingRail, SimulatedRail, audit_decision
from .runtime import BuyerAgent, RunRecord
from .state import BuyerState

__all__ = [
    "AgentDeps",
    "BuyerAgent",
    "BuyerState",
    "Narrator",
    "Offer",
    "PaymentRail",
    "Posture",
    "Proposal",
    "Receipt",
    "RefusingRail",
    "RunRecord",
    "SimulatedRail",
    "StubNarrator",
    "VeniceNarrator",
    "audit_decision",
    "build_narrator",
    "build_nodes",
    "compute_posture",
    "load_posture",
    "store_posture",
]
