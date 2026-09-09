"""Base-chain reads, and the writes we are ready to make.

This module is the only place in Admissible that talks to a chain, and it is
deliberately dull: it fetches facts and hands them back. It does not decide
whether a memory is admissible -- :mod:`admissible.gate` does that, from the
facts this module returns. Keeping the reader ignorant of verdicts is what lets
the gate be tested against canned receipts with no network at all.

Three things here are load-bearing.

**Unreachable is not absent.** A refused RPC and a transaction that never
existed are different answers, and conflating them is how a verifier turns into
a rubber stamp. Every read either returns a fact, returns ``None`` because the
chain genuinely says "not there", or raises :class:`ChainUnreachable`. Nothing
returns a cheerful default. That is also why reverts are never retried: a revert
*is* the chain answering, and the answer is no.

**A feedback hash that is not a hash is not evidence.** ERC-8004's
``giveFeedback`` accepts ``bytes32(0)`` and most callers pass exactly that. Over
the 8,710 ``NewFeedback`` events emitted on Base mainnet in the 300,000 blocks
to block 51,055,657, 92.8% carried a zero ``feedbackHash``; 61 of the 132 agents
receiving feedback in that window had *never* received one with a hash. A score
with no digest behind it is an opinion. :meth:`BaseChain.give_feedback` refuses
to write one.

**The hash is in the log, not in the getter.** ``readFeedback`` returns the
score, the tags and the revocation flag -- and not the ``feedbackHash``. The
committed digest exists only in the ``NewFeedback`` event. Any verifier that
reads feedback through the getter alone therefore cannot check the commitment at
all, which goes a long way to explaining the number above. We read the log.

Addresses, ABIs and block heights in this file were read from Base mainnet, not
copied from documentation; :mod:`tests.test_chain` re-reads them.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, replace
from enum import Enum
from functools import cached_property
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Mapping, Sequence, TypeVar

from eth_typing import ChecksumAddress
from web3 import Web3
from web3.contract import Contract
from web3.exceptions import ContractLogicError, TransactionNotFound
from web3.logs import DISCARD

from .envelope import Evidence
from .gate import ChainUnreachable, FeedbackAttribution, SettlementFacts

__all__ = [
    "BASE_MAINNET",
    "BASE_SEPOLIA",
    "AgentRecord",
    "BaseChain",
    "ChainConfig",
    "ChainUnreachable",
    "FeedbackAttribution",
    "FeedbackRecord",
    "Mismatch",
    "SettlementFacts",
    "Summary",
    "VerifiedSettlement",
    "ZeroFeedbackHash",
]

_ABI_DIR = Path(__file__).with_name("abi")


def _hex0x(value: Any) -> str:
    """A 0x-prefixed hex string, whatever web3 handed us.

    web3 7 returns ``HexBytes.hex()`` *without* the prefix, and the obvious fix
    -- ``"0x" + h.hex().lstrip("0x")`` -- silently eats the leading nibbles of
    every digest that happens to start with a zero. Roughly one hash in sixteen.
    Prefixing exactly once is the whole job, so it is done in exactly one place.
    """
    if isinstance(value, (bytes, bytearray)):
        return "0x" + bytes(value).hex()
    text = str(value)
    return text if text.startswith(("0x", "0X")) else "0x" + text


#: 32 zero bytes -- the ``feedbackHash`` almost everybody writes.
ZERO_HASH = "0x" + "00" * 32

#: ``keccak256("Transfer(address,address,uint256)")``. Every ERC-20 transfer,
#: and every B20 one, since B20 keeps the ERC-20 log shape.
TRANSFER_TOPIC = _hex0x(Web3.keccak(text="Transfer(address,address,uint256)"))

#: ``keccak256`` of the ERC-8004 ``NewFeedback`` event, which is where the
#: committed digest actually lives.
NEW_FEEDBACK_TOPIC = _hex0x(
    Web3.keccak(
        text=(
            "NewFeedback(uint256,address,uint64,int128,uint8,string,string,"
            "string,string,string,bytes32)"
        )
    )
)


def _load_abi(name: str) -> list[dict[str, Any]]:
    """Read one of the ABIs pulled from the verified implementations."""
    return json.loads((_ABI_DIR / f"{name}.json").read_text(encoding="utf-8"))


@dataclass(frozen=True)
class ChainConfig:
    """Everything that differs between Base mainnet and Base Sepolia.

    The ERC-8004 registries sit behind ERC-1967 proxies at vanity ``0x8004…``
    addresses; the ABIs we ship were fetched from the *implementations* behind
    those proxies, because the proxy's own ABI is just the fallback.
    """

    name: str
    chain_id: int
    rpc_url: str
    identity_registry: str
    reputation_registry: str
    validation_registry: str
    #: The block the registries went live, so a log scan has an honest floor.
    #: Below this there is nothing to find, so "not found" is a real answer.
    registry_genesis_block: int
    usdc: str | None = None
    #: The B20 factory precompile. Identical on every network running B20, and
    #: it has no bytecode -- it is implemented in the node, so ``eth_getCode``
    #: returns empty while ``eth_call`` works.
    b20_factory: str = "0xB20f000000000000000000000000000000000000"


BASE_MAINNET = ChainConfig(
    name="base",
    chain_id=8453,
    rpc_url="https://mainnet.base.org",
    identity_registry="0x8004A169FB4a3325136EB29fA0ceB6D2e539a432",
    reputation_registry="0x8004BAa17C55a88189AE136b182e5fdA19dE9b63",
    # Bytecode is present at this address on mainnet but the contract was never
    # initialised: every call reverts. We keep it for completeness and the
    # client refuses to pretend otherwise.
    validation_registry="0x8004Cb1BF31DAf7788923b405b754f57acEB4272",
    registry_genesis_block=41_663_783,
    usdc="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
)

BASE_SEPOLIA = ChainConfig(
    name="base-sepolia",
    chain_id=84532,
    rpc_url="https://sepolia.base.org",
    identity_registry="0x8004A818BFB912233c491871b3d84c89A494BD9e",
    reputation_registry="0x8004B663056A597Dffe9eCcC1965A193B7388713",
    validation_registry="0x8004Cb1BF31DAf7788923b405b754f57acEB4272",
    registry_genesis_block=0,
    usdc="0x036CbD53842c5426634e7929541eC2318f3dCF7e",
)

_BY_CHAIN_ID: dict[int, ChainConfig] = {
    BASE_MAINNET.chain_id: BASE_MAINNET,
    BASE_SEPOLIA.chain_id: BASE_SEPOLIA,
}


class TransactionReverted(RuntimeError):
    """A write reached the chain and the chain said no.

    Distinct from :class:`ChainUnreachable`: this is an answer, and retrying it
    would just spend the fee again.
    """


class ZeroFeedbackHash(ValueError):
    """Refused: a feedback record with no digest commits to nothing.

    Raised rather than silently substituted, because the whole point of the
    ATTESTED tier is that somebody can re-derive the claim from what we wrote.
    """


class Mismatch(str, Enum):
    """Why a settlement failed to match what was claimed.

    Deliberately *not* a :class:`~admissible.verdicts.VerdictCode`. This module
    reports what the chain says; the gate decides what that means. The mapping
    the gate applies is one-to-one all the same:

    ``RECIPIENT`` -> ``COUNTERPARTY_MISMATCH``, ``AMOUNT`` -> ``AMOUNT_MISMATCH``,
    ``TOKEN``/``NO_TRANSFER``/``REVERTED`` -> ``EVIDENCE_NOT_FOUND``.
    """

    NONE = "none"
    #: The transfer settled, to somebody else.
    RECIPIENT = "recipient"
    #: Right counterparty, wrong number.
    AMOUNT = "amount"
    #: A transfer happened, but of a different token than the claim names.
    TOKEN = "token"
    #: The transaction exists and carries no ERC-20 transfer at all.
    NO_TRANSFER = "no_transfer"
    #: The transaction exists and reverted. It moved nothing.
    REVERTED = "reverted"


@dataclass(frozen=True)
class Transfer:
    """One decoded ERC-20 ``Transfer`` log."""

    token: str
    sender: str
    recipient: str
    value: int
    log_index: int


@dataclass(frozen=True)
class VerifiedSettlement(SettlementFacts):
    """A settlement read back from the chain, with the comparison already done.

    Subclasses the gate's :class:`~admissible.gate.SettlementFacts` so the gate's
    ``ChainReader`` protocol is satisfied verbatim, while callers that passed
    expectations get the richer answer they asked for. ``mismatch`` is
    :attr:`Mismatch.NONE` when nothing was expected -- absence of a complaint is
    not evidence of a match, so check what you asked for.
    """

    chain_id: int = 0
    #: ``1`` for a succeeded transaction, ``0`` for one that reverted.
    status: int = 1
    mismatch: Mismatch = Mismatch.NONE
    #: Every transfer of the token in question, in log order. A facilitator that
    #: splits a fee out of the payment produces more than one, and the gate is
    #: entitled to see all of them rather than just the one we picked.
    transfers: tuple[Transfer, ...] = ()

    @property
    def settled(self) -> bool:
        """True when the transfer happened and matched everything expected."""
        return self.status == 1 and self.mismatch is Mismatch.NONE

    def as_evidence(self, kind: str = "x402:settlement") -> Evidence:
        """The :class:`~admissible.envelope.Evidence` this settlement supports."""
        return Evidence(
            chain_id=self.chain_id,
            tx_hash=self.tx_hash,
            block=self.block,
            kind=kind,
        )


@dataclass(frozen=True)
class AgentRecord:
    """An ERC-8004 agent, as the registry describes it.

    ``owner`` and ``wallet`` are separate on purpose and are frequently
    different addresses: agent 20880 keeps its identity NFT in cold storage and
    settles x402 payments from another wallet entirely. Verifying a payment
    against the *owner* would therefore reject every genuine payment it makes,
    which is exactly the class of bug this record exists to prevent.
    """

    agent_id: int
    chain_id: int
    registry: str
    owner: str
    wallet: str
    token_uri: str
    #: The parsed registration JSON, when the URI was reachable and was JSON.
    #: ``None`` means we could not fetch it -- never that it said nothing.
    registration: dict[str, Any] | None = None

    @property
    def declares_registry(self) -> str | None:
        """The registry the agent's own JSON claims, as CAIP-10.

        Worth comparing against :attr:`registry`: an agent whose manifest points
        somewhere else is either misconfigured or impersonating.
        """
        regs = (self.registration or {}).get("registrations") or []
        for entry in regs:
            if isinstance(entry, Mapping) and entry.get("agentId") == self.agent_id:
                value = entry.get("agentRegistry")
                return str(value) if value is not None else None
        return None

    @property
    def self_declaration_matches(self) -> bool:
        """True when the agent's manifest points back at the registry we read."""
        declared = self.declares_registry
        if declared is None:
            return False
        want = f"eip155:{self.chain_id}:{self.registry}".lower()
        return declared.lower() == want

    def payment_wallets(self) -> tuple[str, ...]:
        """Addresses the manifest says payments settle to.

        Falls back to the registered agent wallet, which is what a manifest-less
        agent implies. These are *claims by the agent*, not proof; they are the
        addresses to check a settlement against, not a reason to skip checking.
        """
        wallets = (self.registration or {}).get("wallets")
        found: list[str] = []
        if isinstance(wallets, Mapping):
            for key in ("payment", "identity"):
                entry = wallets.get(key)
                if isinstance(entry, Mapping) and entry.get("address"):
                    found.append(str(entry["address"]))
        if not found and self.wallet:
            found.append(self.wallet)
        return tuple(dict.fromkeys(a.lower() for a in found))


@dataclass(frozen=True)
class FeedbackRecord:
    """One ERC-8004 feedback entry.

    ``feedback_hash`` is ``None`` when we read the record through the getter and
    did not go looking in the logs; it is :data:`ZERO_HASH` when the writer
    committed to nothing at all. Those are different states and the gate treats
    them differently, so they are not collapsed here.
    """

    agent_id: int
    client: str
    index: int
    value: int
    value_decimals: int
    tag1: str
    tag2: str
    is_revoked: bool
    feedback_hash: str | None = None
    block: int | None = None
    tx_hash: str | None = None
    registry: str | None = None
    chain_id: int | None = None

    @property
    def score(self) -> float:
        """The value with its decimals applied, e.g. 80 at 2dp -> 0.8."""
        return self.value / (10**self.value_decimals)

    @property
    def commits_to_a_claim(self) -> bool:
        """True when this record actually pins down what it is about."""
        return bool(self.feedback_hash) and self.feedback_hash != ZERO_HASH

    def as_evidence(self, kind: str = "erc8004:feedback") -> Evidence:
        return Evidence(
            chain_id=self.chain_id,
            tx_hash=self.tx_hash,
            block=self.block,
            registry=self.registry,
            agent_id=self.agent_id,
            feedback_index=self.index,
            kind=kind,
        )


@dataclass(frozen=True)
class Summary:
    """The registry's aggregate over a set of clients."""

    agent_id: int
    count: int
    value: int
    decimals: int
    clients: tuple[str, ...] = ()

    @property
    def score(self) -> float:
        return self.value / (10**self.decimals)


T = TypeVar("T")


class BaseChain:
    """A client for the Base chain, read-first.

    ``private_key`` is optional. Without it the object is in read-only mode:
    every read works and every write raises, rather than failing later at
    signing time with something obscure. Pass ``PRIVATE_KEY`` through the
    environment -- :meth:`from_env` does that -- and never through a file in
    this repository.
    """

    def __init__(
        self,
        rpc_url: str | None = None,
        chain_id: int | None = None,
        private_key: str | None = None,
        *,
        config: ChainConfig | None = None,
        timeout: float = 30.0,
        retries: int = 4,
        backoff: float = 1.0,
        max_scan_chunks: int = 64,
        http_get: Callable[[str, float], bytes] | None = None,
        web3: Web3 | None = None,
    ) -> None:
        if config is None:
            if chain_id is not None:
                config = _BY_CHAIN_ID.get(chain_id)
                if config is None:
                    raise ValueError(f"no built-in config for chain {chain_id}")
            else:
                config = BASE_MAINNET
        self.config = config
        self.chain_id = config.chain_id
        self.rpc_url = rpc_url or config.rpc_url
        self._retries = max(1, retries)
        self._backoff = backoff
        self._timeout = timeout
        #: How many 10k-block windows a log scan may walk before it gives up and
        #: says so. 64 windows is ~640k blocks, about a fortnight of Base.
        self.max_scan_chunks = max(1, max_scan_chunks)
        self._http_get = http_get or _default_http_get
        self.w3 = web3 or Web3(
            Web3.HTTPProvider(self.rpc_url, request_kwargs={"timeout": timeout})
        )
        self._account = None
        if private_key:
            from eth_account import Account

            self._account = Account.from_key(private_key)

    # -- construction -----------------------------------------------------------

    @classmethod
    def from_env(
        cls, config: ChainConfig | None = None, *, env: Mapping[str, str] | None = None, **kw: Any
    ) -> "BaseChain":
        """Build a client, taking the key from ``PRIVATE_KEY`` if it is set.

        Read-only when it is not. The key never reaches a file in this package;
        that asymmetry is deliberate and is the reason this constructor exists.
        """
        source = os.environ if env is None else env
        return cls(
            config=config or BASE_MAINNET,
            private_key=source.get("PRIVATE_KEY") or None,
            rpc_url=source.get("BASE_RPC_URL") or None,
            **kw,
        )

    @classmethod
    def sepolia(cls, **kw: Any) -> "BaseChain":
        return cls(config=BASE_SEPOLIA, **kw)

    # -- identity ---------------------------------------------------------------

    @property
    def read_only(self) -> bool:
        return self._account is None

    @property
    def address(self) -> ChecksumAddress | None:
        """The signer's address, or ``None`` in read-only mode."""
        return self._account.address if self._account else None

    def _require_signer(self, what: str) -> Any:
        if self._account is None:
            raise PermissionError(
                f"{what} needs a signer; this client is read-only. "
                "Set PRIVATE_KEY in the environment."
            )
        return self._account

    # -- contracts --------------------------------------------------------------

    @cached_property
    def identity(self) -> Contract:
        return self.w3.eth.contract(
            address=Web3.to_checksum_address(self.config.identity_registry),
            abi=_load_abi("erc8004_identity"),
        )

    @cached_property
    def reputation(self) -> Contract:
        return self.w3.eth.contract(
            address=Web3.to_checksum_address(self.config.reputation_registry),
            abi=_load_abi("erc8004_reputation"),
        )

    @cached_property
    def b20_factory(self) -> Contract:
        return self.w3.eth.contract(
            address=Web3.to_checksum_address(self.config.b20_factory),
            abi=_load_abi("b20_factory"),
        )

    def erc20(self, token: str) -> Contract:
        return self.w3.eth.contract(
            address=Web3.to_checksum_address(token), abi=_load_abi("erc20")
        )

    # -- transport --------------------------------------------------------------

    def _call(self, fn: Callable[[], T], what: str) -> T:
        """Run one RPC read, retrying transport failures but never reverts.

        The distinction is the point. A revert is the chain answering; retrying
        it wastes time and, worse, invites the caller to read a timeout as a
        "no". Transport failures -- 429s from the public endpoint especially --
        are retried with a linear backoff and then surface as
        :class:`ChainUnreachable`, which the gate turns into a refusal.
        """
        last: Exception | None = None
        for attempt in range(self._retries):
            try:
                return fn()
            except (ContractLogicError, TransactionNotFound):
                # The chain answered. "No" and "not there" are results, not
                # failures, and retrying them only delays an honest verdict.
                raise
            except Exception as exc:  # transport: sockets, timeouts, 429, DNS
                if _is_revert(exc):
                    raise
                last = exc
            if attempt + 1 < self._retries:
                time.sleep(self._backoff * (attempt + 1))
        raise ChainUnreachable(f"{what} failed after {self._retries} attempts: {last}") from last

    def block_number(self) -> int:
        return self._call(lambda: self.w3.eth.block_number, "eth_blockNumber")

    # -- ERC-8004 identity ------------------------------------------------------

    def resolve_agent(self, agent_id: int, *, fetch_uri: bool = True) -> AgentRecord:
        """Owner, wallet, tokenURI and -- if reachable -- the registration JSON.

        ``ownerOf`` reverts for an id that was never minted, which we let
        through as :class:`~web3.exceptions.ContractLogicError`: an agent that
        does not exist is a different problem from a chain we cannot read.

        A tokenURI that will not load is not fatal. The registry is the
        authority on owner and wallet; the JSON is the agent's own account of
        itself and is therefore the least trustworthy part of the record.
        """
        owner = self._call(
            lambda: self.identity.functions.ownerOf(agent_id).call(), f"ownerOf({agent_id})"
        )
        wallet = self._call(
            lambda: self.identity.functions.getAgentWallet(agent_id).call(),
            f"getAgentWallet({agent_id})",
        )
        token_uri = self._call(
            lambda: self.identity.functions.tokenURI(agent_id).call(), f"tokenURI({agent_id})"
        )
        registration: dict[str, Any] | None = None
        if fetch_uri and token_uri:
            registration = self._fetch_json(token_uri)
        return AgentRecord(
            agent_id=agent_id,
            chain_id=self.chain_id,
            registry=Web3.to_checksum_address(self.config.identity_registry),
            owner=owner,
            wallet=wallet,
            token_uri=token_uri,
            registration=registration,
        )

    def _fetch_json(self, uri: str) -> dict[str, Any] | None:
        """Best-effort fetch of a registration document. Never raises."""
        if not uri.startswith(("http://", "https://")):
            return None
        try:
            body = self._http_get(uri, self._timeout)
            parsed = json.loads(body)
        except Exception:
            return None
        return parsed if isinstance(parsed, dict) else None

    def register_agent(
        self, token_uri: str, *, wait: bool = True, gas_buffer: float = 1.25
    ) -> int | None:
        """Mint an agent identity and return its id.

        The id is read from the ``Registered`` event rather than from the
        function's return value, because a return value is not observable from a
        mined transaction -- only the log is. Returns ``None`` when ``wait`` is
        false and the receipt was therefore never read.
        """
        account = self._require_signer("register_agent")
        fn = self.identity.functions.register(token_uri)
        receipt = self._send(fn, account, wait=wait, gas_buffer=gas_buffer)
        if receipt is None:
            return None
        events = self.identity.events.Registered().process_receipt(receipt, errors=DISCARD)
        for ev in events:
            return int(ev["args"]["agentId"])
        return None

    # -- ERC-8004 reputation ----------------------------------------------------

    def give_feedback(
        self,
        agent_id: int,
        score: int,
        feedback_hash: bytes | str,
        uri: str = "",
        tag: str = "",
        *,
        score_decimals: int = 0,
        tag2: str = "",
        endpoint: str = "",
        wait: bool = True,
        gas_buffer: float = 1.25,
    ) -> dict[str, Any] | None:
        """Write a feedback record that actually commits to something.

        The onchain signature is
        ``giveFeedback(uint256 agentId, int128 value, uint8 valueDecimals,
        string tag1, string tag2, string endpoint, string feedbackURI,
        bytes32 feedbackHash)``. The shorter argument list here is the one the
        rest of Admissible wants; the remaining fields are keyword-only.

        ``feedback_hash`` must be a real 32-byte digest -- pass
        :func:`admissible.envelope.digest_of` of the claim the score is about.
        A zero hash raises :class:`ZeroFeedbackHash`. That refusal is the whole
        point: a record committing to ``bytes32(0)`` is compatible with any
        story told afterwards, so it can never make a memory ATTESTED, and
        writing one would put a claim onchain that we could not later verify
        ourselves.
        """
        account = self._require_signer("give_feedback")
        digest = _to_bytes32(feedback_hash)
        if digest == b"\x00" * 32:
            raise ZeroFeedbackHash(
                "refusing to write a feedback record with an empty feedbackHash: "
                "it would commit to nothing and could never be re-derived"
            )
        fn = self.reputation.functions.giveFeedback(
            agent_id, int(score), int(score_decimals), tag, tag2, endpoint, uri, digest
        )
        receipt = self._send(fn, account, wait=wait, gas_buffer=gas_buffer)
        if receipt is None:
            return None
        out: dict[str, Any] = {
            "tx_hash": _hex0x(receipt["transactionHash"]),
            "block": receipt["blockNumber"],
            "status": receipt["status"],
        }
        for ev in self.reputation.events.NewFeedback().process_receipt(receipt, errors=DISCARD):
            out["feedback_index"] = int(ev["args"]["feedbackIndex"])
            out["feedback_hash"] = _hex0x(ev["args"]["feedbackHash"])
            break
        return out

    def read_feedback(
        self,
        agent_id: int,
        client_address: str,
        index: int | None = None,
        *,
        with_hash: bool = False,
        from_block: int | None = None,
    ) -> FeedbackRecord | None:
        """One feedback record, or ``None`` if that index was never written.

        ``index`` defaults to the client's most recent. Indices are per
        ``(agent, client)`` and start at 1.

        ``with_hash`` costs a log scan, because ``readFeedback`` does not return
        the ``feedbackHash`` -- see the module docstring. Left off by default so
        that reading a score stays one ``eth_call``.
        """
        client = Web3.to_checksum_address(client_address)
        last = self._call(
            lambda: self.reputation.functions.getLastIndex(agent_id, client).call(),
            f"getLastIndex({agent_id})",
        )
        if last == 0:
            return None
        wanted = last if index is None else int(index)
        if wanted < 1 or wanted > last:
            return None
        value, decimals, tag1, tag2, revoked = self._call(
            lambda: self.reputation.functions.readFeedback(agent_id, client, wanted).call(),
            f"readFeedback({agent_id},{wanted})",
        )
        record = FeedbackRecord(
            agent_id=agent_id,
            client=client,
            index=wanted,
            value=int(value),
            value_decimals=int(decimals),
            tag1=tag1,
            tag2=tag2,
            is_revoked=bool(revoked),
            registry=Web3.to_checksum_address(self.config.reputation_registry),
            chain_id=self.chain_id,
        )
        if not with_hash:
            return record
        found = self._find_feedback_log(agent_id, wanted, client=client, from_block=from_block)
        if found is None:
            return record
        return replace_feedback(record, found)

    def read_feedback_hash(
        self,
        registry: str,
        agent_id: int,
        feedback_index: int,
        chain_id: int,
        *,
        client: str | None = None,
        from_block: int | None = None,
    ) -> str | None:
        """The digest committed alongside a feedback record.

        This is the gate's ``ChainReader`` hook, so the first four arguments are
        positional and fixed. ``registry`` and ``chain_id`` are checked rather
        than ignored: a memory citing another chain's registry must not be
        answered with a lookup against this one, so a mismatch is ``None``
        ("not here"), not a silently redirected read.

        Returns ``None`` when the record does not exist. Raises
        :class:`ChainUnreachable` when the scan window could not cover the whole
        registry history, because "I did not look everywhere" is not "it is not
        there" -- and the gate must refuse rather than assume.
        """
        if chain_id != self.chain_id:
            return None
        if registry and not _same_address(registry, self.config.reputation_registry):
            return None
        found = self._find_feedback_log(
            agent_id, feedback_index, client=client, from_block=from_block
        )
        return found["feedback_hash"] if found else None

    def _find_feedback_log(
        self,
        agent_id: int,
        index: int,
        *,
        client: str | None = None,
        from_block: int | None = None,
        chunk: int = 9_999,
    ) -> dict[str, Any] | None:
        """Scan ``NewFeedback`` backwards for one record.

        Newest-first because a memory we are checking is usually recent, and
        because stopping early is the difference between one RPC call and a
        thousand. Public Base endpoints cap ``eth_getLogs`` at a 10,000-block
        range, hence the chunking.

        The interesting case is the record we *do not* find. Scanning the whole
        registry history is roughly 940 requests against a rate-limited public
        endpoint, so the scan is bounded by :attr:`max_scan_chunks`. Running out
        of budget raises :class:`ChainUnreachable` rather than returning
        ``None``: we did not establish that the record is absent, only that we
        stopped looking, and reporting the second as the first would let a
        forged feedback index pass as a merely-missing one. Give ``from_block``
        when the answer's neighbourhood is known and the scan is one request.
        """
        floor = self.config.registry_genesis_block if from_block is None else int(from_block)
        head = self.block_number()
        topics: list[Any] = [NEW_FEEDBACK_TOPIC, _topic_uint(agent_id)]
        if client is not None:
            topics.append(_topic_address(client))
        address = Web3.to_checksum_address(self.config.reputation_registry)
        end = head
        scanned = 0
        while end >= floor:
            if scanned >= self.max_scan_chunks:
                raise ChainUnreachable(
                    f"searched {scanned * chunk} blocks back from {head} without finding "
                    f"feedback #{index} for agent {agent_id}; the record may exist further "
                    "back, so this is unknown rather than absent"
                )
            start = max(floor, end - chunk)
            logs = self._call(
                lambda s=start, e=end: self.w3.eth.get_logs(
                    {"address": address, "fromBlock": s, "toBlock": e, "topics": topics}
                ),
                f"eth_getLogs({start}-{end})",
            )
            scanned += 1
            for log in reversed(logs):
                decoded = self.reputation.events.NewFeedback().process_log(log)
                if int(decoded["args"]["feedbackIndex"]) != int(index):
                    continue
                return {
                    "feedback_hash": _hex0x(decoded["args"]["feedbackHash"]),
                    "block": decoded["blockNumber"],
                    "tx_hash": _hex0x(decoded["transactionHash"]),
                    "client": decoded["args"]["clientAddress"],
                    "index": int(decoded["args"]["feedbackIndex"]),
                }
            if start == floor:
                # We reached the block the registry was deployed in. Nothing
                # exists below it, so this really is "not there".
                return None
            end = start - 1
        return None

    def get_summary(
        self,
        agent_id: int,
        clients: Sequence[str] | None = None,
        tag1: str = "",
        tag2: str = "",
    ) -> Summary:
        """The registry's aggregate score over a set of clients.

        ``clientAddresses`` may not be empty: the registry reverts with
        ``clientAddresses required`` rather than summarising everybody, which is
        a sensible refusal to let one caller pay for an unbounded loop. When no
        clients are given we therefore fetch the full list with ``getClients``
        first, so "summarise this agent" means what a caller expects.
        """
        chosen = (
            [Web3.to_checksum_address(c) for c in clients]
            if clients
            else self.get_clients(agent_id)
        )
        if not chosen:
            return Summary(agent_id=agent_id, count=0, value=0, decimals=0, clients=())
        count, value, decimals = self._call(
            lambda: self.reputation.functions.getSummary(
                agent_id, list(chosen), tag1, tag2
            ).call(),
            f"getSummary({agent_id})",
        )
        return Summary(
            agent_id=agent_id,
            count=int(count),
            value=int(value),
            decimals=int(decimals),
            clients=tuple(chosen),
        )

    def get_clients(self, agent_id: int) -> list[ChecksumAddress]:
        """Every address that has ever left this agent feedback."""
        return self._call(
            lambda: self.reputation.functions.getClients(agent_id).call(),
            f"getClients({agent_id})",
        )

    def agent_addresses(self, agent_id: int) -> tuple[str, ...]:
        """Every address that *is* this agent, lowercased.

        Owner, registered wallet and the payment wallets the registration
        declares, in that order and de-duplicated. They are routinely different:
        agent 20880 keeps its identity NFT at ``0x4069ef1a…`` and settles x402
        payments from ``0xe3e14118…``. Anything comparing a payment against one
        of them alone gets the wrong answer about half the time, which is why
        this returns a set rather than an address.

        The manifest half is the agent's own account of itself and is therefore
        the least trustworthy part -- but it is only ever used here to *widen*
        the set of addresses that count as the agent, which can only ever make
        a self-dealing check stricter.
        """
        agent = self.resolve_agent(agent_id)
        found = [_norm(agent.owner), _norm(agent.wallet), *agent.payment_wallets()]
        return tuple(dict.fromkeys(a for a in found if a))

    def attribute_feedback(
        self,
        registry: str,
        agent_id: int,
        feedback_index: int,
        chain_id: int,
        *,
        from_block: int | None = None,
    ) -> FeedbackAttribution | None:
        """Who wrote a feedback record, and what they had settled to its subject.

        This is the gate's second ``ChainReader`` hook, and it exists because
        the first one cannot answer the question that matters. A committed
        ``feedbackHash`` proves a record was not edited. It says nothing about
        whether its author was entitled to vouch for anybody, and on a
        permissionless registry the author is frequently the subject.

        So this resolves three things the digest cannot: the ``clientAddress``
        indexed on the ``NewFeedback`` log, every address that is the agent
        under review, and -- if the author is not one of them -- the most recent
        USDC transfer from author to agent at or before the block the review was
        written. Payment first, then the review it justifies; a transfer
        afterwards does not retroactively buy the right to have said something.

        ``None`` only when the record genuinely does not exist. A search that
        ran out of budget raises :class:`ChainUnreachable`, in keeping with the
        rest of this module: not finding a payment in the window we could afford
        to search is not the same as there being none.
        """
        if chain_id != self.chain_id:
            return None
        if registry and not _same_address(registry, self.config.reputation_registry):
            return None
        found = self._find_feedback_log(agent_id, feedback_index, from_block=from_block)
        if found is None:
            return None

        author = _norm(found.get("client"))
        wallets = self.agent_addresses(agent_id)
        paid: VerifiedSettlement | None = None
        if author and author not in wallets:
            # Skipped when the author is the agent: the gate refuses that
            # outright, and a log scan to confirm a self-review is money wasted.
            paid = self.find_settlement(author, wallets, before_block=found.get("block"))
        return FeedbackAttribution(
            agent_id=agent_id,
            feedback_index=feedback_index,
            author=author,
            feedback_hash=found["feedback_hash"],
            subject_wallets=wallets,
            settlement_tx=paid.tx_hash if paid else None,
            settlement_token=paid.token if paid else None,
            settled_value=paid.value if paid else 0,
            block=found.get("block"),
        )

    def find_settlement(
        self,
        payer: str,
        recipients: Sequence[str],
        *,
        token: str | None = None,
        before_block: int | None = None,
        chunk: int = 9_999,
    ) -> VerifiedSettlement | None:
        """The most recent transfer from ``payer`` to any of ``recipients``.

        Both parties are indexed topics on the ``Transfer`` event, so this is
        one filtered ``eth_getLogs`` per window rather than a scan of anything.
        Recipients go in as a single OR-ed topic position, which is what lets an
        agent's owner, wallet and declared payment wallets all be checked in the
        same request.

        Bounded the same way :meth:`_find_feedback_log` is, and for the same
        reason: running out of :attr:`max_scan_chunks` raises
        :class:`ChainUnreachable` rather than returning ``None``. "I searched a
        fortnight of blocks and found no payment" is not "this author never
        paid", and reporting the first as the second would let an unpaid review
        pass as merely old. Pass ``from_block`` upstream, or raise
        ``max_scan_chunks``, when deeper history has to be reachable.
        """
        token = token or self.config.usdc
        wanted = [r for r in (_norm(x) for x in recipients) if r]
        if not token or not _norm(payer) or not wanted:
            return None
        head = int(before_block) if before_block is not None else self.block_number()
        floor = self.config.registry_genesis_block
        address = Web3.to_checksum_address(token)
        topics: list[Any] = [
            TRANSFER_TOPIC,
            _topic_address(_norm(payer)),
            [_topic_address(r) for r in wanted],
        ]
        end = head
        scanned = 0
        while end >= floor:
            if scanned >= self.max_scan_chunks:
                raise ChainUnreachable(
                    f"searched {scanned * chunk} blocks back from {head} without finding a "
                    f"payment from {payer} to the agent; one may exist further back, so "
                    "this is unknown rather than absent"
                )
            start = max(floor, end - chunk)
            logs = self._call(
                lambda s=start, e=end: self.w3.eth.get_logs(
                    {"address": address, "fromBlock": s, "toBlock": e, "topics": topics}
                ),
                f"eth_getLogs({start}-{end})",
            )
            scanned += 1
            for log in reversed(logs):
                for transfer in decode_transfers([log], token=token):
                    if transfer.value <= 0:
                        continue
                    # A Transfer log only exists in a transaction that succeeded;
                    # reverted transactions emit none. Status is 1 by definition.
                    return VerifiedSettlement(
                        tx_hash=_hex0x(log["transactionHash"]),
                        token=transfer.token,
                        sender=transfer.sender,
                        recipient=transfer.recipient,
                        value=transfer.value,
                        block=int(log["blockNumber"]),
                        chain_id=self.chain_id,
                        status=1,
                    )
            if start == floor:
                return None
            end = start - 1
        return None

    # -- settlement -------------------------------------------------------------

    #: ``anchor(bytes32 root, uint64 asOf, uint32 leafCount)`` -- the only two
    #: functions we call on our own contract, inlined rather than shipping a
    #: build artefact the reader would have to trust.
    ANCHOR_ABI = [
        {
            "type": "function",
            "name": "anchor",
            "stateMutability": "nonpayable",
            "inputs": [
                {"name": "root", "type": "bytes32"},
                {"name": "asOf", "type": "uint64"},
                {"name": "leafCount", "type": "uint32"},
            ],
            "outputs": [{"name": "index", "type": "uint256"}],
        },
        {
            "type": "function",
            "name": "anchorCount",
            "stateMutability": "view",
            "inputs": [{"name": "agent", "type": "address"}],
            "outputs": [{"name": "", "type": "uint256"}],
        },
    ]

    def transfer_erc20(
        self, token: str, to: str, amount: int, *, wait: bool = True, gas_buffer: float = 1.25
    ) -> str:
        """Move tokens, and return the hash so the caller can cite it.

        Used for the direct-settlement half of x402: pay first, then present the
        hash. It costs one extra transaction over signing an authorization, and
        it buys the thing this project is about -- the evidence is final on chain
        before the request is made, so it exists whether or not the service ever
        answers.
        """
        account = self._require_signer("transfer_erc20")
        if amount <= 0:
            raise ValueError("refusing to broadcast a zero-value transfer")
        # The shipped erc20 ABI covers only what the reader needs -- balanceOf
        # and the Transfer event. The one write we make is spelled out here so
        # the file stays a reader's ABI and the calldata for a transfer is
        # visible next to the code that sends it.
        transfer_abi = [{
            "type": "function",
            "name": "transfer",
            "stateMutability": "nonpayable",
            "inputs": [
                {"name": "to", "type": "address"},
                {"name": "amount", "type": "uint256"},
            ],
            "outputs": [{"name": "", "type": "bool"}],
        }]
        contract = self.w3.eth.contract(
            address=self.w3.to_checksum_address(token), abi=transfer_abi
        )
        fn = contract.functions.transfer(self.w3.to_checksum_address(to), int(amount))
        receipt = self._send(fn, account, wait=wait, gas_buffer=gas_buffer)
        if receipt is None:
            raise ChainUnreachable("transfer was broadcast without waiting for a receipt")
        if receipt.get("status") != 1:
            raise TransactionReverted(f"transfer reverted: {_hex0x(receipt['transactionHash'])}")
        return _hex0x(receipt["transactionHash"])

    def anchor(
        self,
        contract_address: str,
        root: str,
        as_of_unix: int,
        leaf_count: int,
        *,
        wait: bool = True,
        gas_buffer: float = 1.25,
    ) -> str:
        """Publish the Merkle commitment over everything currently admissible.

        The contract refuses an ``asOf`` older than the agent's last one, so a
        failure here usually means the caller is trying to re-publish an older
        view of its own memory. That is the guarantee, not a bug.
        """
        account = self._require_signer("anchor")
        contract = self.w3.eth.contract(
            address=self.w3.to_checksum_address(contract_address), abi=self.ANCHOR_ABI
        )
        fn = contract.functions.anchor(_to_bytes32(root), int(as_of_unix), int(leaf_count))
        receipt = self._send(fn, account, wait=wait, gas_buffer=gas_buffer)
        if receipt is None:
            raise ChainUnreachable("anchor was broadcast without waiting for a receipt")
        if receipt.get("status") != 1:
            raise TransactionReverted(f"anchor reverted: {_hex0x(receipt['transactionHash'])}")
        return _hex0x(receipt["transactionHash"])


    def verify_settlement(
        self,
        tx_hash: str,
        chain_id: int | None = None,
        expected_to: str | None = None,
        expected_amount: int | None = None,
        expected_token: str | None = None,
    ) -> VerifiedSettlement | None:
        """What a claimed payment actually did.

        This is the load-bearing read of the whole product: everything else
        decides how much to trust a memory, and this decides whether the money
        the memory talks about ever moved.

        Returns ``None`` -- and only -- when the transaction does not exist.
        Every other outcome comes back as a populated
        :class:`VerifiedSettlement` whose ``mismatch`` says what was wrong,
        because "no such transaction", "paid somebody else" and "paid the wrong
        amount" are three different accusations and the gate maps them to three
        different refusals. Collapsing them into a bare ``False`` is how a
        verifier stops being able to explain itself.

        ``expected_amount`` is in base units (USDC on Base has six decimals, so
        $0.25 is ``250_000``). Comparison is exact: the x402 ``exact`` scheme
        means exact, and "close enough" is not a property money has.

        Raises :class:`ChainUnreachable` if the chain could not be consulted.
        """
        if chain_id is not None and chain_id != self.chain_id:
            # A receipt from another chain is not absent here, but this client
            # genuinely cannot speak to it. Refusing beats guessing.
            return None
        try:
            receipt = self._call(
                lambda: self.w3.eth.get_transaction_receipt(tx_hash), f"receipt({tx_hash})"
            )
        except TransactionNotFound:
            # The one case that is genuinely "this payment never happened".
            return None
        if receipt is None:
            return None

        block = int(receipt["blockNumber"])
        try:
            timestamp = int(
                self._call(lambda: self.w3.eth.get_block(block), f"block({block})")["timestamp"]
            )
        except ChainUnreachable:
            # A missing timestamp weakens the record but does not falsify the
            # transfer we already read, so it is left absent rather than faked.
            timestamp = None

        token = expected_token or self.config.usdc
        transfers = tuple(decode_transfers(receipt["logs"], token=token))
        status = int(receipt.get("status", 1))
        tx = _hex0x(receipt["transactionHash"])

        if status != 1:
            return VerifiedSettlement(
                tx_hash=tx, token=_norm(token), sender="", recipient="", value=0,
                block=block, timestamp=timestamp, chain_id=self.chain_id,
                status=status, mismatch=Mismatch.REVERTED, transfers=transfers,
            )
        if not transfers:
            # Either it moved no tokens at all, or it moved a different one. We
            # can tell those apart, and the difference matters to a reader.
            any_transfer = tuple(decode_transfers(receipt["logs"], token=None))
            return VerifiedSettlement(
                tx_hash=tx, token=_norm(token), sender="", recipient="", value=0,
                block=block, timestamp=timestamp, chain_id=self.chain_id, status=status,
                mismatch=Mismatch.TOKEN if any_transfer else Mismatch.NO_TRANSFER,
                transfers=any_transfer,
            )

        chosen = transfers[0]
        mismatch = Mismatch.NONE
        if expected_to is not None:
            match = next(
                (t for t in transfers if _same_address(t.recipient, expected_to)), None
            )
            if match is None:
                mismatch = Mismatch.RECIPIENT
            else:
                chosen = match
        if mismatch is Mismatch.NONE and expected_amount is not None:
            if chosen.value != int(expected_amount):
                exact = next(
                    (
                        t
                        for t in transfers
                        if t.value == int(expected_amount)
                        and (expected_to is None or _same_address(t.recipient, expected_to))
                    ),
                    None,
                )
                if exact is None:
                    mismatch = Mismatch.AMOUNT
                else:
                    chosen = exact
        return VerifiedSettlement(
            tx_hash=tx,
            token=chosen.token,
            sender=chosen.sender,
            recipient=chosen.recipient,
            value=chosen.value,
            block=block,
            timestamp=timestamp,
            chain_id=self.chain_id,
            status=status,
            mismatch=mismatch,
            transfers=transfers,
        )

    # -- B20 --------------------------------------------------------------------

    def b20_balance(self, token_address: str, holder: str) -> int:
        """``balanceOf`` against a B20 token.

        B20 is Base's native token standard: tokens live at addresses minted by
        the factory precompile at ``0xB20f…0000`` and carry a one-byte stub
        instead of real bytecode, because the implementation is in the node
        rather than in the EVM. The practical consequence is that a B20 token is
        read exactly like an ERC-20 -- ``balanceOf`` is still ``0x70a08231`` --
        so no special client is needed. Verified live against
        ``0xb2000000000000000000004f480c6f51BeD64155`` on Base mainnet.
        """
        return self._call(
            lambda: self.erc20(token_address).functions.balanceOf(
                Web3.to_checksum_address(holder)
            ).call(),
            f"b20 balanceOf({token_address})",
        )

    def is_b20(self, token_address: str) -> bool:
        """Whether the factory precompile vouches for this token.

        The address prefix (``0xB200…`` for assets, ``0xB201…`` for stablecoins)
        is a derivation artefact, not a guarantee -- Base mainnet is full of
        ordinary ERC-20s deployed to vanity ``0xb200…`` addresses with names
        like "0xb20" precisely to be mistaken for the real thing. Asking the
        factory is the only answer that cannot be spoofed.
        """
        return self._call(
            lambda: self.b20_factory.functions.isB20(
                Web3.to_checksum_address(token_address)
            ).call(),
            f"isB20({token_address})",
        )

    # -- writing ----------------------------------------------------------------

    def _send(
        self, fn: Any, account: Any, *, wait: bool, gas_buffer: float
    ) -> Mapping[str, Any] | None:
        """Build, sign and broadcast one transaction.

        Estimates gas first, which doubles as a dry run: a call that would
        revert fails here, before anything is signed or broadcast, and before
        any fee is spent.
        """
        nonce = self._call(
            lambda: self.w3.eth.get_transaction_count(account.address), "eth_getTransactionCount"
        )
        tx = fn.build_transaction(
            {"from": account.address, "nonce": nonce, "chainId": self.chain_id}
        )
        gas = self._call(lambda: self.w3.eth.estimate_gas(tx), "eth_estimateGas")
        tx["gas"] = int(gas * gas_buffer)
        signed = account.sign_transaction(tx)
        tx_hash = self._call(
            lambda: self.w3.eth.send_raw_transaction(signed.raw_transaction),
            "eth_sendRawTransaction",
        )
        if not wait:
            return None
        return self._call(
            lambda: self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180),
            "wait_for_transaction_receipt",
        )

    def dry_run(self, fn: Any) -> dict[str, Any]:
        """Everything a write does except signing and broadcasting.

        Exists so the write paths can be exercised -- and proven to encode the
        right calldata against the right address -- from an unfunded wallet,
        without spending anything.
        """
        account = self._require_signer("dry_run")
        nonce = self._call(
            lambda: self.w3.eth.get_transaction_count(account.address), "eth_getTransactionCount"
        )
        tx = fn.build_transaction(
            {"from": account.address, "nonce": nonce, "chainId": self.chain_id}
        )
        return {"to": tx["to"], "data": tx["data"], "chainId": tx["chainId"], "from": account.address}


# -- pure helpers, kept module level so the gate's tests can use them without a node


def decode_transfers(
    logs: Iterable[Mapping[str, Any]], token: str | None = None
) -> Iterator[Transfer]:
    """Decode ERC-20 ``Transfer`` logs out of a receipt.

    Filters on the token address and on ``topic0`` rather than trusting log
    order or position. Real settlements go through routers that emit their own
    events around the transfer -- the sibylcap payment we verified has three
    logs and only the middle one is the USDC transfer -- so picking "the first
    log" or "the last log" would be wrong on live data.

    Anonymous or malformed logs are skipped rather than raising: a receipt is
    attacker-influenced input, and one unparseable log must not stop us reading
    the transfer that is actually there.
    """
    want = _norm(token) if token else None
    for log in logs:
        address = _norm(log.get("address"))
        if want and address != want:
            continue
        topics = log.get("topics") or []
        if len(topics) < 3:
            continue
        if _hex_topic(topics[0]) != TRANSFER_TOPIC:
            continue
        try:
            value = int(_hex_data(log.get("data")) or "0x0", 16)
        except (TypeError, ValueError):
            continue
        yield Transfer(
            token=Web3.to_checksum_address(address),
            sender=_topic_to_address(topics[1]),
            recipient=_topic_to_address(topics[2]),
            value=value,
            log_index=int(log.get("logIndex", 0)),
        )


def replace_feedback(record: FeedbackRecord, found: Mapping[str, Any]) -> FeedbackRecord:
    """Attach log-sourced fields to a getter-sourced record."""
    return replace(
        record,
        feedback_hash=found.get("feedback_hash"),
        block=found.get("block"),
        tx_hash=found.get("tx_hash"),
    )


def _default_http_get(url: str, timeout: float) -> bytes:
    from urllib.request import Request, urlopen

    req = Request(url, headers={"User-Agent": "admissible/0.1", "Accept": "application/json"})
    with urlopen(req, timeout=timeout) as resp:  # noqa: S310 - scheme checked by caller
        return resp.read()


def _to_bytes32(value: bytes | str) -> bytes:
    """Coerce a digest to exactly 32 bytes, refusing anything ambiguous."""
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str):
        text = value[2:] if value.startswith(("0x", "0X")) else value
        try:
            raw = bytes.fromhex(text)
        except ValueError as exc:
            raise ValueError(f"feedback hash is not hex: {value!r}") from exc
    else:
        raise TypeError(f"feedback hash must be bytes or hex str, got {type(value).__name__}")
    if len(raw) != 32:
        raise ValueError(f"feedback hash must be 32 bytes, got {len(raw)}")
    return raw


def _norm(address: Any) -> str:
    return str(address).lower() if address else ""


def _same_address(a: str | None, b: str | None) -> bool:
    return bool(a) and bool(b) and str(a).lower() == str(b).lower()


def _hex_topic(topic: Any) -> str:
    if isinstance(topic, (bytes, bytearray)):
        return "0x" + bytes(topic).hex()
    return str(topic).lower()


def _hex_data(data: Any) -> str | None:
    if data is None:
        return None
    if isinstance(data, (bytes, bytearray)):
        return "0x" + bytes(data).hex()
    return str(data)


def _topic_to_address(topic: Any) -> str:
    return Web3.to_checksum_address("0x" + _hex_topic(topic)[-40:])


def _topic_uint(value: int) -> str:
    return "0x" + f"{int(value):064x}"


def _topic_address(value: str) -> str:
    return "0x" + "0" * 24 + str(value)[2:].lower()


def _is_revert(exc: Exception) -> bool:
    """Whether an RPC error carries a revert, however the provider phrased it.

    Providers disagree about which exception type a revert arrives as, so this
    reads the message. Getting it wrong is only ever a performance bug -- a
    revert misread as transport is retried and then reported as unreachable,
    which still refuses rather than admits.
    """
    return "execution reverted" in str(exc).lower()
