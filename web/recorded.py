"""The chain the web surface reads, and the honest label that goes with it.

``AdmissionGate`` takes a ``ChainReader`` -- two reads, no writes, no signer --
so the reasoning is identical whether the answers come from Base or from a file.
This module supplies the file, and it supplies the sentence the UI prints above
the deck when it does.

Zero-credential by default. With no ``BASE_RPC_URL`` configured the server runs
against ``web/fixtures/base-mainnet.json`` and every surface says
``offline fixtures``. With one configured it builds ``admissible.chain.BaseChain``
and says ``base mainnet``. Nothing in between, and nothing that reads live when
it is not: a visible gap beats an uncheckable claim.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from admissible.envelope import digest_of
from admissible.gate import ChainUnreachable, SettlementFacts

try:  # the gate grew feedback attribution; a checkout without it still runs
    from admissible.gate import FeedbackAttribution
except ImportError:  # pragma: no cover - depends on the package version
    FeedbackAttribution = None  # type: ignore[assignment]

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "base-mainnet.json"

#: What the UI prints when it is reading a file rather than a chain.
OFFLINE_LABEL = "offline fixtures"
LIVE_LABEL = "base mainnet"


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
    note: str = ""

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
            note=raw.get("note", ""),
        )


class RecordedChain:
    """A ``ChainReader`` backed by recorded receipts instead of an RPC endpoint.

    Implements the protocol structurally. The gate never learns which one it is
    holding, which is the whole reason the offline surface and a live one score
    the same.
    """

    label = OFFLINE_LABEL
    live = False

    def __init__(self, raw: dict[str, Any], path: Path) -> None:
        self.path = path
        self.provenance = dict(raw.get("provenance") or {})
        self._transfers = {
            h: Transfer.from_dict(h, t) for h, t in (raw.get("transfers") or {}).items()
        }
        self._feedback = dict(raw.get("feedback") or {})

    @classmethod
    def load(cls, path: str | Path | None = None) -> "RecordedChain":
        p = Path(path) if path else FIXTURE
        return cls(json.loads(p.read_text(encoding="utf-8")), p)

    # -- ChainReader ---------------------------------------------------------
    def verify_settlement(self, tx_hash: str, chain_id: int) -> SettlementFacts | None:
        """Facts about a transfer, or ``None`` when it does not exist.

        Case-insensitive on the hash: an attacker who re-cases a hash is not
        citing a different transaction, and treating it as one would downgrade a
        counterparty_mismatch into the vaguer evidence_not_found.
        """
        found = self._transfers.get(tx_hash) or self._transfers.get(tx_hash.lower())
        return found.to_facts() if found else None

    def read_feedback_hash(
        self, registry: str, agent_id: int, feedback_index: int, chain_id: int
    ) -> str | None:
        record = self._feedback.get(feedback_key(registry, agent_id, feedback_index))
        if record is None:
            return None
        if isinstance(record, str):
            return record
        commits = record.get("commits_claim")
        return digest_of(commits) if commits is not None else record.get("hash")

    def attribute_feedback(
        self, registry: str, agent_id: int, feedback_index: int, chain_id: int
    ) -> Any | None:
        """Who wrote a reputation record, and what they had paid for the right to.

        The gate will not admit a review it cannot attribute, because a matching
        ``feedbackHash`` proves integrity and says nothing about authority:
        registries are permissionless, so a record whose hash is the keccak of
        your own flattering claim costs one transaction. The fixture therefore
        records the author, the subject's wallets and the settlement behind the
        review -- the same three facts a live reader digs out of the
        ``NewFeedback`` log and the transfers around it.
        """
        record = self._feedback.get(feedback_key(registry, agent_id, feedback_index))
        if record is None:
            return None
        if FeedbackAttribution is None:  # pragma: no cover - version skew
            raise ChainUnreachable(
                "this build of admissible has no FeedbackAttribution to answer with"
            )
        if isinstance(record, str):
            record = {"hash": record}
        commits = record.get("commits_claim")
        return FeedbackAttribution(
            agent_id=agent_id,
            feedback_index=feedback_index,
            author=record.get("author") or "",
            feedback_hash=(
                digest_of(commits) if commits is not None else record.get("hash") or ""
            ),
            subject_wallets=tuple(record.get("subject_wallets") or ()),
            settlement_tx=record.get("settlement_tx"),
            settlement_token=record.get("settlement_token"),
            settled_value=int(record.get("settled_value") or 0),
            block=record.get("block"),
        )

    # -- extras the surface uses, not the gate -------------------------------
    def settlement(self, tx_hash: str) -> Transfer | None:
        return self._transfers.get(tx_hash) or self._transfers.get(tx_hash.lower())

    def committed_claim(
        self, registry: str, agent_id: int, feedback_index: int
    ) -> dict[str, Any] | None:
        """The claim a feedback record committed to, when the fixture records one.

        Seeded memories are built *from* this rather than beside it. A claim
        retyped in two places drifts by one key eventually, and the failure looks
        exactly like the gate catching a forgery when it is really catching a typo.
        """
        record = self._feedback.get(feedback_key(registry, agent_id, feedback_index))
        if isinstance(record, dict) and isinstance(record.get("commits_claim"), dict):
            return dict(record["commits_claim"])
        return None

    def describe(self) -> dict[str, Any]:
        return {
            "chain": self.label,
            "live": False,
            "source": str(self.path),
            "settlements": len(self._transfers),
            "feedback_records": len(self._feedback),
            "note": self.provenance.get("honest_note", ""),
        }

    def __len__(self) -> int:
        return len(self._transfers)


class LiveChain:
    """``admissible.chain.BaseChain`` behind the same two methods.

    A thin adapter rather than a subclass, so a failure to reach Base surfaces as
    ``ChainUnreachable`` -- which the gate already refuses on -- instead of as
    whatever web3 happened to raise.
    """

    label = LIVE_LABEL
    live = True

    def __init__(self, inner: Any, rpc_url: str) -> None:
        self._inner = inner
        self.rpc_url = rpc_url

    @classmethod
    def connect(cls, rpc_url: str) -> "LiveChain":
        from admissible.chain import BaseChain  # imported only when asked for

        return cls(BaseChain(rpc_url=rpc_url), rpc_url)

    def verify_settlement(self, tx_hash: str, chain_id: int) -> SettlementFacts | None:
        return self._inner.verify_settlement(tx_hash, chain_id)

    def read_feedback_hash(
        self, registry: str, agent_id: int, feedback_index: int, chain_id: int
    ) -> str | None:
        return self._inner.read_feedback_hash(registry, agent_id, feedback_index, chain_id)

    def attribute_feedback(
        self, registry: str, agent_id: int, feedback_index: int, chain_id: int
    ) -> Any | None:
        attribute = getattr(self._inner, "attribute_feedback", None)
        if attribute is None:
            raise ChainUnreachable(
                "this build of admissible.chain cannot attribute a feedback record"
            )
        return attribute(registry, agent_id, feedback_index, chain_id)

    def settlement(self, tx_hash: str) -> None:
        return None

    def committed_claim(self, *_: Any) -> None:
        return None

    def describe(self) -> dict[str, Any]:
        return {
            "chain": self.label,
            "live": True,
            "source": _redact(self.rpc_url),
            "settlements": None,
            "feedback_records": None,
            "note": "Reads are made against Base mainnet over the configured RPC endpoint.",
        }


def open_chain(env: dict[str, str] | None = None) -> RecordedChain | LiveChain:
    """The reader this deployment gets, decided once, at the edge of the program.

    Falling back to the fixture when a configured RPC will not connect is
    deliberate and is announced: the surface would rather say "offline fixtures"
    loudly than serve chain answers it did not actually get.
    """
    source = os.environ if env is None else env
    rpc = (source.get("BASE_RPC_URL") or "").strip()
    if not rpc:
        return RecordedChain.load(source.get("ADMISSIBLE_CHAIN_FIXTURE") or None)
    try:
        return LiveChain.connect(rpc)
    except Exception:  # noqa: BLE001 - the fallback has to be total to be honest
        return RecordedChain.load(source.get("ADMISSIBLE_CHAIN_FIXTURE") or None)


def feedback_key(registry: str, agent_id: int, feedback_index: int) -> str:
    return f"{registry.lower()}/{agent_id}/{feedback_index}"


def _redact(url: str) -> str:
    """An RPC URL with its API key removed. Endpoints are secrets often enough."""
    head, _, _ = url.partition("?")
    parts = head.rstrip("/").split("/")
    if len(parts) > 3 and len(parts[-1]) > 12:
        parts[-1] = "..."
    return "/".join(parts)


__all__ = [
    "ChainUnreachable",
    "LiveChain",
    "RecordedChain",
    "Transfer",
    "feedback_key",
    "open_chain",
]
