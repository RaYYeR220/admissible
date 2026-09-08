"""A ChainReader backed by recorded receipts instead of an RPC endpoint.

The demo has to run with no network, no keys and no funds, and it has to run the
*same* gate a live deployment runs. ``AdmissionGate`` was built against the
``ChainReader`` protocol precisely so that swapping the chain for a file changes
nothing about the reasoning -- so this module supplies the file, and nothing
else in ``apps/`` knows which one it is holding.

Two sources feed it and they are kept apart on purpose:

* **The fixture** (``apps/fixtures/base-mainnet.json``) is checked in and never
  written to. It is the world as it stood before the demo started.
* **The overlay** is written at runtime by :class:`apps.agent.rails.SimulatedRail`
  when a simulated payment settles. It is what makes an ATTESTED memory
  re-derivable in the *next* process: an agent that pays and then cannot prove
  it paid has not really learned anything.

Keeping the overlay in its own file is also what makes the deletion test honest.
Deleting the agent's memory must not delete the chain -- the evidence is still
there, the agent has simply lost the record that told it where to look.

HONESTY NOTE, stated here rather than in a footnote: the fixture is
**synthetic**. The addresses are real and public, the shapes match what a Base
mainnet USDC transfer decodes to, and the amounts match the counterparty's real
published price tiers -- but no transaction in this file was ever mined. The
file says so in its own ``provenance`` block, and ``--live`` swaps this class
for a reader that talks to Base.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from admissible.envelope import digest_of
from admissible.gate import ChainUnreachable, SettlementFacts

from . import REPO_ROOT

#: USDC carries six decimals. Named here because the rail and the fixture must
#: agree with the gate on what "0.25" means down to the base unit.
USDC_DECIMALS = 6

DEFAULT_FIXTURE = REPO_ROOT / "apps" / "fixtures" / "base-mainnet.json"


def usd_to_base_units(amount: float | int | str, decimals: int = USDC_DECIMALS) -> int:
    """Convert a human amount to token base units without float drift.

    Deliberately the same string-based conversion the gate uses, rather than
    ``int(amount * 10**decimals)``: ``0.29 * 10**6`` is 289999.99999999994, and
    a rounding artefact that turns a valid payment into an AMOUNT_MISMATCH is a
    bug that only ever shows up in front of an audience. ``apps/tests`` asserts
    this function and the gate's agree across a spread of awkward values.
    """
    text = f"{amount}"
    if "e" in text or "E" in text:
        text = f"{float(amount):.{decimals}f}"
    whole, _, frac = text.partition(".")
    frac = (frac + "0" * decimals)[:decimals]
    sign = -1 if whole.startswith("-") else 1
    return sign * (abs(int(whole or 0)) * 10**decimals + int(frac or 0))


@dataclass(frozen=True)
class Transfer:
    """One recorded settlement, in the shape the gate asks for."""

    tx_hash: str
    token: str
    sender: str
    recipient: str
    value: int
    block: int
    timestamp: int | None = None

    def to_facts(self) -> SettlementFacts:
        return SettlementFacts(
            tx_hash=self.tx_hash,
            token=self.token,
            sender=self.sender,
            recipient=self.recipient,
            value=self.value,
            block=self.block,
            timestamp=self.timestamp,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "tx_hash": self.tx_hash,
            "token": self.token,
            "from": self.sender,
            "to": self.recipient,
            "value": self.value,
            "block": self.block,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, tx_hash: str, raw: dict[str, Any]) -> "Transfer":
        return cls(
            tx_hash=tx_hash,
            token=raw["token"],
            sender=raw["from"],
            recipient=raw["to"],
            value=int(raw["value"]),
            block=int(raw["block"]),
            timestamp=raw.get("timestamp"),
        )


class RecordedChain:
    """Reads settlements and feedback hashes out of JSON files.

    Implements :class:`admissible.gate.ChainReader` structurally. It is passed
    to the gate as a constructor argument and the gate never learns what it is,
    which is the whole reason the offline demo and the live demo score the same.
    """

    def __init__(
        self,
        transfers: dict[str, Transfer] | None = None,
        feedback: dict[str, Any] | None = None,
        *,
        overlay_path: Path | None = None,
        unreachable: bool = False,
        provenance: dict[str, Any] | None = None,
    ) -> None:
        self._transfers: dict[str, Transfer] = dict(transfers or {})
        self._feedback: dict[str, Any] = dict(feedback or {})
        self._overlay_path = Path(overlay_path) if overlay_path else None
        self._unreachable = unreachable
        self.provenance = dict(provenance or {})

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------
    @classmethod
    def load(
        cls,
        fixture: str | Path | None = None,
        *,
        overlay: str | Path | None = None,
    ) -> "RecordedChain":
        """Fixture plus, if it exists, the overlay of simulated settlements.

        A missing overlay is normal (nothing has settled yet) and is not an
        error; a missing fixture is, because a chain reader that silently knows
        nothing would admit nothing and look like a very cautious gate.
        """
        path = Path(fixture) if fixture else DEFAULT_FIXTURE
        raw = json.loads(path.read_text(encoding="utf-8"))
        chain = cls(
            transfers={
                h: Transfer.from_dict(h, t) for h, t in (raw.get("transfers") or {}).items()
            },
            feedback=dict(raw.get("feedback") or {}),
            overlay_path=Path(overlay) if overlay else None,
            provenance=raw.get("provenance"),
        )
        if chain._overlay_path and chain._overlay_path.exists():
            chain._merge_overlay(json.loads(chain._overlay_path.read_text(encoding="utf-8")))
        return chain

    def _merge_overlay(self, raw: dict[str, Any]) -> None:
        for tx_hash, record in (raw.get("transfers") or {}).items():
            self._transfers[tx_hash] = Transfer.from_dict(tx_hash, record)

    # ------------------------------------------------------------------
    # ChainReader
    # ------------------------------------------------------------------
    def verify_settlement(self, tx_hash: str, chain_id: int) -> SettlementFacts | None:
        """Facts about a transfer, or None when the transaction does not exist.

        Lookup is case-insensitive on the hash. An attacker who re-cases a hash
        is not citing a different transaction, and treating it as one would turn
        a COUNTERPARTY_MISMATCH into an EVIDENCE_NOT_FOUND -- a weaker, less
        informative refusal for the same forgery.
        """
        if self._unreachable:
            raise ChainUnreachable("recorded chain configured as unreachable")
        found = self._transfers.get(tx_hash) or self._transfers.get(tx_hash.lower())
        return found.to_facts() if found else None

    def read_feedback_hash(
        self, registry: str, agent_id: int, feedback_index: int, chain_id: int
    ) -> str | None:
        """The digest committed alongside an ERC-8004 feedback record.

        The fixture may record either a literal hash or the claim that was
        committed. Recording the claim is the faithful option: onchain the value
        *is* the hash of a claim, so re-deriving it here exercises the same
        equality the live reader would.
        """
        if self._unreachable:
            raise ChainUnreachable("recorded chain configured as unreachable")
        record = self._feedback.get(_feedback_key(registry, agent_id, feedback_index))
        if record is None:
            return None
        if isinstance(record, str):
            return record
        commits = record.get("commits_claim")
        return digest_of(commits) if commits is not None else record.get("hash")

    def committed_claim(
        self, registry: str, agent_id: int, feedback_index: int
    ) -> dict[str, Any] | None:
        """The claim a feedback record committed to, when the fixture records one.

        Exists so a seeded memory can be built *from* the fixture rather than
        beside it. A claim retyped in two places drifts by one key eventually,
        and the failure would look like the gate catching a forgery when it was
        really catching a typo.
        """
        record = self._feedback.get(_feedback_key(registry, agent_id, feedback_index))
        if isinstance(record, dict):
            claim = record.get("commits_claim")
            return dict(claim) if isinstance(claim, dict) else None
        return None

    def settlement(self, tx_hash: str) -> Transfer | None:
        """A recorded transfer by hash, for callers building a memory about it."""
        return self._transfers.get(tx_hash) or self._transfers.get(tx_hash.lower())

    # ------------------------------------------------------------------
    # Write-through, used only by the simulated rail
    # ------------------------------------------------------------------
    def record_settlement(self, transfer: Transfer) -> Transfer:
        """Add a settlement and persist it to the overlay.

        Persistence matters more than it looks: without it, the ATTESTED memory
        the agent writes after paying would fail to re-derive in the next
        process, and the cold-start story would quietly be a warm-start story.

        The write is atomic (temp file plus replace) so an interrupted demo
        leaves either the old overlay or the new one, never half of one.
        """
        self._transfers[transfer.tx_hash] = transfer
        if self._overlay_path is None:
            return transfer
        self._overlay_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "note": (
                "Settlements produced by the simulated payment rail during a demo "
                "run. Not mined anywhere. Deleting this file is not the deletion "
                "test -- the deletion test deletes the agent's memory, not the chain."
            ),
            "transfers": {h: t.to_dict() for h, t in self._transfers.items()},
        }
        fd, tmp = tempfile.mkstemp(
            dir=str(self._overlay_path.parent), suffix=".tmp", prefix="overlay-"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
            os.replace(tmp, self._overlay_path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        return transfer

    # ------------------------------------------------------------------
    def __len__(self) -> int:
        return len(self._transfers)

    def describe(self) -> str:
        kind = self.provenance.get("kind", "recorded")
        return f"{type(self).__name__}({kind}, {len(self._transfers)} settlements)"


def _feedback_key(registry: str, agent_id: int, feedback_index: int) -> str:
    return f"{registry.lower()}/{agent_id}/{feedback_index}"


def live_chain(rpc_url: str | None = None) -> Any:
    """A reader pointed at Base mainnet, for ``--live``.

    Imported lazily and by name. ``admissible.chain`` is owned by another part
    of the build and this package must not depend on it at import time -- the
    gate takes a ``ChainReader``, so the concrete class is a detail resolved at
    the edge of the program and nowhere else.

    Raises ``RuntimeError`` with an actionable message rather than an
    ``ImportError`` traceback, because the caller who asked for ``--live`` needs
    to know whether the problem is the module, the RPC or the network.
    """
    try:
        from admissible import chain as chain_module  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover - depends on build state
        raise RuntimeError(
            "live mode needs admissible.chain, which is not importable: "
            f"{exc}. Run without --live to use the recorded fixtures."
        ) from exc

    url = rpc_url or os.environ.get("BASE_RPC")
    for factory_name in ("BaseChain", "ChainReader", "build_chain", "chain_reader"):
        factory = getattr(chain_module, factory_name, None)
        if factory is None:
            continue
        try:
            reader = factory(url) if url else factory()
        except TypeError:
            continue
        # Read-only is not a hope, it is a check. The gate's protocol is two
        # reads and no writes; anything handed back here has to satisfy it, and
        # a class that has grown a different method set should fail now rather
        # than at the first settlement the demo tries to verify.
        missing = [
            method
            for method in ("verify_settlement", "read_feedback_hash")
            if not callable(getattr(reader, method, None))
        ]
        if missing:
            raise RuntimeError(
                f"admissible.chain.{factory_name} is not a ChainReader: "
                f"missing {', '.join(missing)}"
            )
        return reader
    raise RuntimeError(
        "admissible.chain exposes no recognised reader factory "
        "(looked for BaseChain, ChainReader, build_chain, chain_reader)."
    )
