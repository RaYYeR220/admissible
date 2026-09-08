"""The money boundary.

This is the only module in the repository that moves value, and it is written
so that a reviewer can establish the security property by reading the import
block:

    it imports a Decision, a chain reader and the standard library.
    it does not import the narrator, an HTTP client, or anything a model touches.

That is not a comment, it is a test -- ``tests/test_signer_isolation.py`` parses
this file and asserts the import set, so the property fails loudly rather than
rotting quietly the first time somebody needs "just one string from the model".

The interface is one method that takes exactly one argument: a
:class:`admissible.policy.Decision`. Not a state dict, not a proposal, not an
amount. The rail cannot be told to pay -- it can only be handed a decision that
already says so, and it re-checks that decision against its own citations
before it acts. Re-checking a decision this module did not author is cheap,
and it means a bug in the policy has to get past two independent readers of the
same evidence.

The rail in this build is simulated. It writes a settlement into the recorded
chain rather than broadcasting a transaction, which is stated in the receipt
(``rail="simulated"``) so nothing downstream can mistake it for a mined
transfer. A live rail is a signer and a facilitator behind this same interface;
the shape of the boundary does not change when the money becomes real, which is
the reason to draw it here rather than later.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from admissible.envelope import digest_of, utcnow
from admissible.policy import Decision

from ..addresses import BASE_CHAIN_ID, OUR_AGENT, USDC_BASE
from ..recorded_chain import RecordedChain, Transfer, usd_to_base_units


class RailRefused(RuntimeError):
    """The rail declined to act on the decision it was handed.

    Distinct from a policy refusal. A policy refusal is the system working; this
    is the system disagreeing with itself, which is a bug or an attack and must
    never be swallowed.
    """


@dataclass(frozen=True)
class Receipt:
    """What actually happened at the money boundary."""

    action: str
    counterparty: str
    #: Released without security. Taken from the decision, never from a caller.
    amount_usd: float
    #: Held back or demanded as collateral before the work proceeds.
    collateral_usd: float
    settled: bool
    rail: str
    explain: str
    tx_hash: str | None = None
    chain_id: int | None = None
    block: int | None = None
    token: str | None = None
    at: str = field(default_factory=utcnow)
    #: Digests of the memories that justified this, copied from the decision so
    #: the receipt is self-contained evidence rather than a pointer to state.
    citations: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "counterparty": self.counterparty,
            "amount_usd": round(self.amount_usd, 6),
            "collateral_usd": round(self.collateral_usd, 6),
            "settled": self.settled,
            "rail": self.rail,
            "explain": self.explain,
            "tx_hash": self.tx_hash,
            "chain_id": self.chain_id,
            "block": self.block,
            "token": self.token,
            "at": self.at,
            "citations": list(self.citations),
        }


@runtime_checkable
class PaymentRail(Protocol):
    """One method, one argument, one thing it can be asked to do."""

    def settle(self, decision: Decision) -> Receipt:
        """Act on a decision. Never raises for a refusal -- that is a receipt too."""


def audit_decision(decision: Decision) -> None:
    """Re-derive the decision's own arithmetic before releasing anything.

    Four checks, all cheap, none of them trusting the field they are checking:

    1. It is a :class:`Decision`. A dict that quacks like one is exactly what an
       injection produces, and ``isinstance`` is the cheapest place to say no.
    2. It does not release more than was asked for.
    3. Every digest it cites is present in its own considered set *and* was
       admitted. A citation to a refused memory is a laundered decision.
    4. The unsecured release is covered by the weight of the admitted memories.
       This is the policy's own rule, recomputed here by a module that did not
       write it.

    Raises :class:`RailRefused`. Fails closed, loudly, at the boundary.
    """
    if not isinstance(decision, Decision):
        raise RailRefused(
            f"the rail takes a Decision, not {type(decision).__name__}; "
            "nothing else may authorise a payment"
        )
    if decision.unsecured_usd < 0 or decision.collateral_usd < 0:
        raise RailRefused("a decision with a negative leg is malformed")
    if decision.unsecured_usd > decision.requested_usd + 1e-9:
        raise RailRefused(
            f"decision releases ${decision.unsecured_usd} against a "
            f"${decision.requested_usd} request"
        )

    admitted = {c.digest: c for c in decision.considered if c.verdict.admits}
    for digest in decision.citations():
        if digest not in admitted:
            raise RailRefused(
                f"decision cites {digest[:10]} which is not an admitted memory of "
                "its own considered set"
            )
    if decision.action == "pay":
        credit = sum(c.weight_usd for c in admitted.values())
        if credit + 1e-9 < decision.unsecured_usd:
            raise RailRefused(
                f"decision pays ${decision.unsecured_usd} on ${credit:.6f} of "
                "admissible credit"
            )


class SimulatedRail:
    """Settles into the recorded chain instead of onto Base.

    Every settlement it produces is written through to the chain's overlay file,
    so the ATTESTED memory the agent writes afterwards re-derives in the next
    process. An agent that pays and cannot later prove it paid has not learned
    anything, and a demo that only works while one process stays alive is not
    demonstrating memory.

    The transaction hash is derived from the decision itself (counterparty,
    amount, citations, timestamp) rather than drawn at random, so a replay of
    the same demo produces the same hash and a diff of two runs shows only what
    actually differed.
    """

    name = "simulated"

    def __init__(
        self,
        chain: RecordedChain,
        *,
        payer: str = OUR_AGENT,
        token: str = USDC_BASE,
        chain_id: int = BASE_CHAIN_ID,
        start_block: int = 51_100_000,
    ) -> None:
        self._chain = chain
        self._payer = payer
        self._token = token
        self._chain_id = chain_id
        self._block = start_block

    def settle(self, decision: Decision) -> Receipt:
        """Act on the decision. The only public method, and it takes one thing."""
        audit_decision(decision)

        if decision.action == "refuse":
            return Receipt(
                action="refuse",
                counterparty=decision.counterparty,
                amount_usd=0.0,
                collateral_usd=0.0,
                settled=False,
                rail=self.name,
                explain=decision.explain,
                citations=tuple(decision.citations()),
            )

        # An escrow is not a refusal with extra words. The policy's own account
        # of it is "releasing $X unsecured and holding $Y until the work lands",
        # so the unsecured leg is transferred here and the receipt says so. It
        # would be more flattering to treat escrow as moving nothing, and every
        # number downstream -- the eval's money column especially -- would then
        # be understating what the agent actually risks on a stranger.
        transfer = self._transfer_for(decision)
        if transfer.value <= 0:
            # An escrow whose unsecured leg rounds to nothing. There is no
            # transfer to make and inventing a zero-value one would put a
            # settlement in the chain that never happened.
            return Receipt(
                action=decision.action,
                counterparty=decision.counterparty,
                amount_usd=0.0,
                collateral_usd=decision.collateral_usd,
                settled=False,
                rail=self.name,
                explain=decision.explain,
                citations=tuple(decision.citations()),
            )

        self._chain.record_settlement(transfer)
        self._block += 1
        return Receipt(
            action=decision.action,
            counterparty=decision.counterparty,
            amount_usd=decision.unsecured_usd,
            collateral_usd=decision.collateral_usd,
            settled=True,
            rail=self.name,
            explain=decision.explain,
            tx_hash=transfer.tx_hash,
            chain_id=self._chain_id,
            block=transfer.block,
            token=self._token,
            citations=tuple(decision.citations()),
        )

    def _transfer_for(self, decision: Decision) -> Transfer:
        """Build the settlement this decision authorises.

        The amount comes from ``decision.unsecured_usd`` and from nowhere else.
        Base units are computed with the same string arithmetic the gate uses,
        because the memory written after this payment has to re-derive against
        exactly this value.
        """
        seed = {
            "counterparty": decision.counterparty,
            "payer": self._payer,
            "amount_usd": decision.unsecured_usd,
            "citations": sorted(decision.citations()),
            "block": self._block,
        }
        return Transfer(
            tx_hash=digest_of(seed),
            token=self._token,
            sender=self._payer,
            recipient=decision.counterparty,
            value=usd_to_base_units(decision.unsecured_usd),
            block=self._block,
        )


class RefusingRail:
    """A rail that settles nothing, for runs that must not move value.

    Used by ``scripts/eval.py`` where the question is what the agent *would*
    have done. Scoring a policy by letting it spend is a bad habit even when the
    money is simulated.
    """

    name = "dry-run"

    def settle(self, decision: Decision) -> Receipt:
        """Report what would have moved, and move nothing.

        ``amount_usd`` carries the sum a live rail would have transferred, so a
        caller can score exposure without any transfer happening. ``settled`` is
        False on every path, which is the whole contract of this class.
        """
        audit_decision(decision)
        return Receipt(
            action=decision.action,
            counterparty=decision.counterparty,
            amount_usd=decision.unsecured_usd if decision.action != "refuse" else 0.0,
            collateral_usd=decision.collateral_usd,
            settled=False,
            rail=self.name,
            explain=decision.explain,
            citations=tuple(decision.citations()),
        )
