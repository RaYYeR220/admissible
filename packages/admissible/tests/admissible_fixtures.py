"""Shared fixtures.

Every test gets its own database under ``tmp_path``. Nothing here touches
``~/.sibyl-memory``: the cold-start story we are proving is "a second process
opens the same file and reads the same facts", not "a shared global store
happens to be warm".
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Fallback for a bare `pytest tests/` run from a directory whose rootdir
# resolution misses the pyproject: the package is not installed in the
# hackathon checkout, it is imported from source.
_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from admissible.envelope import Envelope, Evidence, Provenance, Tier  # noqa: E402
from admissible.store import AdmissibleStore  # noqa: E402


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "memory.db"


@pytest.fixture()
def store(db_path: Path):
    s = AdmissibleStore.open(db_path)
    try:
        yield s
    finally:
        s.close()


def envelope(
    claim: dict,
    *,
    tier: Tier = Tier.WITNESSED,
    source: str = "agent:self",
    observed_at: str | None = None,
    actor_address: str | None = None,
    actor_handle: str | None = None,
    valid_from: str | None = None,
    valid_to: str | None = None,
    evidence: Evidence | None = None,
) -> Envelope:
    """Terse envelope builder so tests read as assertions, not as construction."""
    prov = Provenance(
        tier=tier,
        source=source,
        actor_address=actor_address,
        actor_handle=actor_handle,
        valid_from=valid_from,
        valid_to=valid_to,
        evidence=evidence or Evidence(),
        **({"observed_at": observed_at} if observed_at else {}),
    )
    return Envelope(claim=claim, provenance=prov)
