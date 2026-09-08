"""The buyer, assembled.

One class, one method that matters: :meth:`BuyerAgent.hire`. Everything the
demo, the eval and the tests do goes through it, so there is exactly one path
from "an agent offered to sell us something" to "money did or did not move".

The two stores are the same database. ``AdmissibleStore`` owns the
``MemoryClient``; ``SibylStore`` is handed that same client, so the LangGraph
adapter and the provenance layer share one connection, one tenant and one file.
A second process opening the same path sees everything the first one wrote,
which is the cold-start property the whole demo rests on and the reason nothing
here caches memories in the object.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from admissible.envelope import Envelope
from admissible.flagged import FlaggedActors
from admissible.policy import Decision
from admissible.relations import Relations
from admissible.store import AdmissibleStore
from admissible.wiring import build_gate
from sibyl_memory_langgraph import SibylStore

from ..addresses import OUR_AGENT, OUR_HANDLE
from .graph import NODE_ORDER, build_graph
from .narrator import Narrator, StubNarrator, build_narrator
from .nodes import AgentDeps
from .posture import Posture, load_posture
from .rails import PaymentRail, Receipt


@dataclass
class RunRecord:
    """Everything one pass of the graph produced, for printing and for scoring."""

    counterparty: str
    requested_usd: float
    service: str
    proposal: dict[str, Any]
    decision: Decision
    receipt: Receipt
    narration: str
    considered: list[dict[str, Any]]
    malformed: list[dict[str, Any]]
    flagged: dict[str, Any] | None
    #: Verdicts on records the agent computed rather than learned. Reported so a
    #: reviewer can see they were judged, never weighed.
    judged_derived: list[dict[str, Any]] = field(default_factory=list)
    flags_raised: list[dict[str, Any]] = field(default_factory=list)
    contaminated: list[dict[str, Any]] = field(default_factory=list)
    posture_before: dict[str, Any] = field(default_factory=dict)
    posture_after: dict[str, Any] = field(default_factory=dict)
    dossier: dict[str, Any] = field(default_factory=dict)
    log: list[str] = field(default_factory=list)

    @property
    def action(self) -> str:
        return self.decision.action

    @property
    def settled_usd(self) -> float:
        """Money that actually moved.

        An escrow moves its unsecured leg, so this is not zero for one -- the
        policy's own account of an escrow is "releasing $X unsecured and holding
        $Y", and reporting it as a no-op would understate what the agent risks on
        a counterparty it has never met.
        """
        return self.receipt.amount_usd if self.receipt.settled else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "counterparty": self.counterparty,
            "requested_usd": self.requested_usd,
            "service": self.service,
            "proposal": self.proposal,
            "decision": self.decision.to_dict(),
            "receipt": self.receipt.to_dict(),
            "narration": self.narration,
            "malformed": self.malformed,
            "flagged": self.flagged,
            "judged_derived": self.judged_derived,
            "flags_raised": self.flags_raised,
            "contaminated": self.contaminated,
            "posture_before": self.posture_before,
            "posture_after": self.posture_after,
            "dossier": self.dossier,
            "log": self.log,
        }


class BuyerAgent:
    """An agent that hires other agents and pays them out of what it remembers."""

    def __init__(
        self,
        store: AdmissibleStore,
        chain: Any,
        *,
        rail: PaymentRail,
        narrator: Narrator | None = None,
        address: str = OUR_AGENT,
        handle: str = OUR_HANDLE,
        flags: FlaggedActors | None = None,
    ) -> None:
        self.store = store
        self.flags = flags or FlaggedActors(store)
        self.relations = Relations(store)
        # The gate is built from the store and whatever chain reader it was
        # handed. It never learns which one -- the recorded fixtures and Base
        # mainnet reach it through the same protocol.
        #
        # ``self_address`` is passed rather than defaulted because omitting it is
        # a security decision: without it the gate can confirm a settlement
        # involved the counterparty but not that it involved us, and moving USDC
        # between two addresses you own satisfies the weaker test.
        self.gate, self.history = build_gate(
            store, chain, flags=self.flags, self_address=address
        )
        self.narrator = narrator or StubNarrator()
        self.rail = rail
        self.lg_store = SibylStore(client=store.client)
        self.deps = AgentDeps(
            store=store,
            gate=self.gate,
            history=self.history,
            flags=self.flags,
            relations=self.relations,
            narrator=self.narrator,
            rail=self.rail,
            address=address,
            handle=handle,
        )
        self.graph = build_graph(self.deps, self.lg_store)

    # ------------------------------------------------------------------
    @classmethod
    def open(
        cls,
        db_path: str | Path,
        chain: Any,
        *,
        rail: PaymentRail,
        offline: bool = True,
        narrator: Narrator | None = None,
        **kwargs: Any,
    ) -> "BuyerAgent":
        """Open the store at ``db_path`` and wire an agent to it.

        ``offline`` defaults to True: the caller has to opt in to reaching a
        third party, rather than opt out of it. A demo that silently degrades
        when a key happens to be present in the environment is a demo that
        behaves differently on the judge's machine than on ours.
        """
        store = AdmissibleStore.open(db_path)
        return cls(
            store,
            chain,
            rail=rail,
            narrator=narrator or build_narrator(offline=offline),
            **kwargs,
        )

    def close(self) -> None:
        """Close the shared connection. Both stores go with it -- there is one."""
        self.store.close()

    # ------------------------------------------------------------------
    def hire(
        self,
        counterparty: str,
        requested_usd: float,
        *,
        service: str = "unspecified",
        pitch: str = "",
        handle: str | None = None,
        job: dict[str, Any] | None = None,
    ) -> RunRecord:
        """Run the graph once over one offer, and return everything it produced."""
        posture_before = load_posture(self.store).to_claim()
        final = self.graph.invoke(
            {
                "counterparty": counterparty,
                "counterparty_handle": handle,
                "requested_usd": float(requested_usd),
                "service": service,
                "pitch": pitch,
                "job": job or {},
                "log": [],
            }
        )
        decision: Decision = final["decision"]
        return RunRecord(
            counterparty=counterparty,
            requested_usd=float(requested_usd),
            service=service,
            proposal=final.get("proposal", {}),
            decision=decision,
            receipt=final["receipt"],
            narration=final.get("narration", ""),
            considered=[c.to_dict() for c in decision.considered],
            malformed=final.get("malformed", []),
            flagged=final.get("flagged"),
            judged_derived=final.get("judged_derived", []),
            flags_raised=final.get("flags_raised", []),
            contaminated=final.get("contaminated", []),
            posture_before=posture_before,
            posture_after=final.get("posture_after", {}),
            dossier=final.get("dossier", {}),
            log=final.get("log", []),
        )

    # ------------------------------------------------------------------
    def posture(self) -> Posture:
        """The trust posture currently in force. Read straight from memory."""
        return load_posture(self.store)

    def remember(self, category: str, name: str, envelope: Envelope) -> dict[str, Any]:
        """Write a memory through the journalled door, and drop the gate's caches.

        Exposed so the demo can seed prior history without reaching around the
        agent. Every write invalidates the history cache, because the next
        verdict has to see what was just written.
        """
        row = self.store.remember(category, name, envelope)
        self.history.invalidate()
        return row


__all__ = ["BuyerAgent", "RunRecord", "NODE_ORDER"]
