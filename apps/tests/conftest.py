"""Shared fixtures for the app tests.

Every test gets its own database and its own copy of the recorded chain under
``tmp_path``. Nothing here touches ``~/.sibyl-memory`` or the demo store: the
property being proved is that a second process opening a file sees what the
first one wrote, and a shared global store would make that unfalsifiable.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from admissible.store import AdmissibleStore  # noqa: E402
from apps.agent.rails import RefusingRail, SimulatedRail  # noqa: E402
from apps.agent.runtime import BuyerAgent  # noqa: E402
from apps.recorded_chain import RecordedChain  # noqa: E402


@pytest.fixture()
def chain(tmp_path: Path) -> RecordedChain:
    """The checked-in fixture plus a private overlay this test may write to."""
    return RecordedChain.load(overlay=tmp_path / "chain-overlay.json")


@pytest.fixture()
def store(tmp_path: Path):
    s = AdmissibleStore.open(tmp_path / "memory.db")
    try:
        yield s
    finally:
        s.close()


@pytest.fixture()
def agent(store: AdmissibleStore, chain: RecordedChain):
    """A buyer with the stub narrator and a rail that really settles.

    ``offline`` is not a parameter here: the tests must never reach a third
    party, so the narrator is constructed explicitly rather than discovered from
    the environment.
    """
    return BuyerAgent(store, chain, rail=SimulatedRail(chain))


@pytest.fixture()
def dry_agent(store: AdmissibleStore, chain: RecordedChain):
    """A buyer whose rail reports what would move and moves nothing."""
    return BuyerAgent(store, chain, rail=RefusingRail())
