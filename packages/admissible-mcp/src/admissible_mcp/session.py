"""What every tool shares: one store, one gate, one blocklist.

The server is stateless between calls in the protocol sense -- each tool call is
independent -- but it is emphatically not stateless underneath. Opening a fresh
``AdmissibleStore`` per call would re-read Sibyl's ``schema.sql``, rebuild the
FTS5 virtual tables and throw away the gate's journal caches on every tool
invocation, and the journal caches are what keep the supersession and backdating
checks affordable enough to run in front of every decision.

So the store, the flags and the gate are built once and reused, exactly as
Sibyl's own MCP server caches its ``MemoryClient``. Two rules make that safe:

* **Writes invalidate.** :class:`~admissible.wiring.StoreHistory` memoises the
  journal, so a tool that writes has to say so. Anything that does not
  invalidate would let the next verdict be computed against a journal that is
  one write out of date -- which is the difference between seeing a
  supersession and missing it.
* **Configuration is read once, from the environment, and never from a file in
  this package.** No key of any kind is read here: the gate is a reader, and a
  server that never holds a signer cannot be talked into spending anything.

Offline by default is deliberate. Without ``BASE_RPC_URL`` (or an explicit
``ADMISSIBLE_CHAIN=base``) there is no chain reader, and every ATTESTED memory
comes back ``chain_unreachable`` rather than admitted. That is the correct
answer, not a degraded one: unknown is not yes.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from admissible.flagged import FlaggedActors
from admissible.gate import AdmissionGate
from admissible.store import AdmissibleStore
from admissible.wiring import StoreHistory, build_gate

#: Where Sibyl Memory puts its database when nobody says otherwise. Sharing the
#: default is the whole point: an agent that already has a Sibyl store gets its
#: history, and its provenance verdicts, without importing anything.
DEFAULT_DB_PATH = Path.home() / ".sibyl-memory" / "memory.db"

#: Categories swept when a tool is asked about a counterparty rather than about
#: one named memory. Interactions are what we did with them, testimonials are
#: what others say about them, dossiers are folds of both -- and a deployment
#: with a different vocabulary overrides this with ``ADMISSIBLE_CATEGORIES``.
DEFAULT_CATEGORIES: tuple[str, ...] = ("interaction", "testimonial", "dossier")

#: Upper bound on a bulk read. Sibyl clamps its own limits; naming ours keeps
#: "everything the store holds" an honest description of a bounded query.
MAX_SWEEP = 10_000

_TRUTHY = {"1", "true", "yes", "on", "base"}


@dataclass(frozen=True)
class Settings:
    """Everything the server reads out of the environment, resolved once."""

    db_path: Path = DEFAULT_DB_PATH
    tenant_id: str | None = None
    #: The wallet this agent pays from. Supplying it is what lets the gate tell
    #: "this settlement happened" from "this settlement happened to us", so a
    #: counterparty cannot buy a track record by paying themselves.
    self_address: str | None = None
    rpc_url: str | None = None
    chain_enabled: bool = False
    categories: tuple[str, ...] = DEFAULT_CATEGORIES

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Settings":
        source = os.environ if env is None else env
        db = source.get("ADMISSIBLE_DB") or source.get("SIBYL_MEMORY_DB")
        rpc = source.get("BASE_RPC_URL") or None
        chain_flag = (source.get("ADMISSIBLE_CHAIN") or "").strip().lower()
        raw_categories = source.get("ADMISSIBLE_CATEGORIES") or ""
        categories = tuple(c.strip() for c in raw_categories.split(",") if c.strip())
        return cls(
            db_path=Path(db).expanduser() if db else DEFAULT_DB_PATH,
            tenant_id=source.get("SIBYL_TENANT_ID") or None,
            self_address=source.get("ADMISSIBLE_SELF_ADDRESS") or None,
            rpc_url=rpc,
            chain_enabled=bool(rpc) or chain_flag in _TRUTHY,
            categories=categories or DEFAULT_CATEGORIES,
        )

    def to_dict(self) -> dict[str, Any]:
        """Reportable configuration. Never a key, never a secret -- there are none."""
        return {
            "db_path": str(self.db_path),
            "tenant_id": self.tenant_id,
            "self_address": self.self_address,
            "chain": "base" if self.chain_enabled else "off",
            "rpc_url": self.rpc_url,
            "categories": list(self.categories),
        }


@dataclass
class Session:
    """The store, the gate, the flags -- and the chain, when one is configured."""

    settings: Settings
    store: AdmissibleStore
    flags: FlaggedActors
    gate: AdmissionGate
    history: StoreHistory
    chain: Any | None = None
    #: Why there is no chain reader, when there is none. Surfaced by the tools
    #: so a calling model reads "no chain configured" rather than inferring it
    #: from a verdict it does not understand.
    chain_status: str = "no chain configured; attested memories cannot be re-derived"
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @classmethod
    def open(cls, settings: Settings | None = None, *, chain: Any | None = None) -> "Session":
        """Open the store named by ``settings`` and wire a gate to it.

        ``chain`` is injectable so tests -- and an embedder that already holds a
        client -- can hand in a reader rather than having one built from the
        environment. Nothing else about the wiring differs.
        """
        settings = settings or Settings.from_env()
        kwargs: dict[str, Any] = {}
        if settings.tenant_id:
            kwargs["tenant_id"] = settings.tenant_id
        store = AdmissibleStore.open(settings.db_path, **kwargs)
        flags = FlaggedActors(store)

        status = "no chain configured; attested memories cannot be re-derived"
        if chain is None and settings.chain_enabled:
            chain, status = _build_chain(settings)
        elif chain is not None:
            status = "chain reader supplied by the host process"

        gate, history = build_gate(
            store,
            chain,
            flags=flags,
            self_address=settings.self_address,
        )
        return cls(
            settings=settings,
            store=store,
            flags=flags,
            gate=gate,
            history=history,
            chain=chain,
            chain_status=status,
        )

    def invalidate(self) -> None:
        """Drop the gate's journal caches. Every write path must call this."""
        self.history.invalidate()

    def close(self) -> None:
        self.store.close()


def _build_chain(settings: Settings) -> tuple[Any | None, str]:
    """A Base reader, or a sentence saying why there is not one.

    Imported lazily because it drags in web3, and a server started to answer
    ``admissible_recall`` on a local database should not pay for an Ethereum
    client it will never use. A failure here is reported, never raised: a
    missing RPC must degrade to "unknown", and the gate already refuses on
    unknown.
    """
    try:
        from admissible.chain import BASE_MAINNET, BaseChain

        chain = BaseChain(rpc_url=settings.rpc_url, config=BASE_MAINNET)
        return chain, f"reading Base mainnet at {chain.rpc_url}"
    except Exception as exc:  # noqa: BLE001 - a broken reader is not a crash
        return None, f"chain reader unavailable ({type(exc).__name__}: {exc})"


# ----------------------------------------------------------------------
# The process-wide session
# ----------------------------------------------------------------------
_lock = threading.Lock()
_current: Session | None = None


def session() -> Session:
    """The shared session, opened on first use.

    Guarded by a lock because the MCP SDK runs synchronous tools in a worker
    thread pool: two tool calls can arrive at once, and opening the database
    twice would leave one of them holding a store the other is about to close.
    """
    global _current
    with _lock:
        if _current is None:
            _current = Session.open()
        return _current


def use(new_session: Session | None) -> None:
    """Install a session built by the caller. Tests and embedders use this."""
    global _current
    with _lock:
        _current = new_session


def reset() -> None:
    """Close and forget the shared session."""
    global _current
    with _lock:
        if _current is not None:
            try:
                _current.close()
            except Exception:  # noqa: BLE001 - shutdown must not raise
                pass
        _current = None
