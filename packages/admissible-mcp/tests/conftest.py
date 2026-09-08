"""Fixtures for the server suite. Offline, no keys, one database per test.

Nothing here touches ``~/.sibyl-memory``: every test opens its own file under
``tmp_path`` and installs it as the process-wide session, so a suite run cannot
read -- or write -- a developer's real memory store.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

# Fallback for a bare `pytest tests/` from a checkout with nothing installed.
_ROOT = Path(__file__).resolve().parents[1]
for candidate in (_ROOT / "src", _ROOT.parent / "admissible" / "src"):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

from admissible.envelope import Envelope, Evidence, Provenance, Tier  # noqa: E402
from admissible.gate import SettlementFacts  # noqa: E402
from admissible_mcp import session as session_module  # noqa: E402
from admissible_mcp.session import Session, Settings  # noqa: E402

#: The agent's own wallet in these tests. Supplying it is what lets the gate
#: tell "a settlement happened" from "a settlement happened to us".
OUR_ADDRESS = "0x8cdec2c69be9e200a8591da3e86e822b03f7ce1f"
COUNTERPARTY = "0x4069ef1afc8a9b2a29117a3740fcab2912499fbe"
STRANGER = "0x000000000000000000000000000000000000dead"

TX = "0x" + "11" * 32
OTHER_TX = "0x" + "22" * 32


class FakeChain:
    """A chain reader with a fixed, tiny history.

    The gate talks to a two-method protocol precisely so the whole evidence path
    can be exercised with no network: these are canned receipts, and they are
    the only chain any test here sees.
    """

    def __init__(self) -> None:
        self.settlements: dict[str, SettlementFacts] = {
            TX: SettlementFacts(
                tx_hash=TX,
                token="0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
                sender=OUR_ADDRESS,
                recipient=COUNTERPARTY,
                value=250_000,
                block=41_700_000,
                status=1,
            )
        }
        self.feedback: dict[tuple[str, int, int], str] = {}

    def verify_settlement(self, tx_hash: str, chain_id: int) -> SettlementFacts | None:
        return self.settlements.get(tx_hash)

    def read_feedback_hash(
        self, registry: str, agent_id: int, feedback_index: int, chain_id: int
    ) -> str | None:
        return self.feedback.get((registry.lower(), agent_id, feedback_index))


@pytest.fixture()
def chain() -> FakeChain:
    return FakeChain()


@pytest.fixture()
def live(tmp_path: Path, chain: FakeChain):
    """A live session on a fresh database, installed for the tools to find."""
    settings = Settings(
        db_path=tmp_path / "memory.db",
        self_address=OUR_ADDRESS,
    )
    sess = Session.open(settings, chain=chain)
    session_module.use(sess)
    try:
        yield sess
    finally:
        session_module.reset()


def settlement_claim(
    counterparty: str = COUNTERPARTY, amount: str | float = "0.25"
) -> dict[str, Any]:
    return {"counterparty": counterparty, "amount_usd": amount, "outcome": "delivered"}


def envelope(
    claim: dict[str, Any],
    *,
    tier: Tier = Tier.WITNESSED,
    source: str = "agent:self",
    actor_address: str | None = OUR_ADDRESS,
    evidence: Evidence | None = None,
    observed_at: str | None = None,
) -> Envelope:
    prov = Provenance(
        tier=tier,
        source=source,
        actor_address=actor_address,
        evidence=evidence or Evidence(),
        **({"observed_at": observed_at} if observed_at else {}),
    )
    return Envelope(claim=claim, provenance=prov)
