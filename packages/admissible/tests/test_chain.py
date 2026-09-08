"""Tests for the Base-chain client.

Split in two, on purpose.

The offline tests are the ones that matter for correctness. They feed canned
receipts through the decoder and assert that a real transfer, a transfer to
somebody else, and a transfer of the wrong size come back as three *different*
answers -- because the gate turns each into a different refusal, and a verifier
that cannot tell them apart cannot explain itself.

The live tests are the ones that matter for honesty. Every address, ABI and
block height in :mod:`admissible.chain` was read off Base mainnet rather than
copied out of a document, and these re-read them so that a claim like "agent
20880 is owned by 0x4069ef1a" is checked rather than asserted. They are marked
``live`` and deselect with ``-m "not live"``.

The canned receipt is not invented. It is the real structure of
``0xe70d3765…985ead8b``, a $0.25 USDC payment to agent 20880's payment wallet
for its project-evaluation endpoint, and it is deliberately awkward: three logs,
of which only the middle one is the transfer. The third is a router event
carrying *the same recipient in a topic and the same value in its data*. Any
decoder that trusts log position, or that matches on shape instead of on
``topic0`` and token address, passes the happy path and fails this.
"""

from __future__ import annotations

import pytest
from web3 import Web3

from admissible.chain import (
    BASE_MAINNET,
    BASE_SEPOLIA,
    ZERO_HASH,
    AgentRecord,
    BaseChain,
    ChainUnreachable,
    Mismatch,
    ZeroFeedbackHash,
    _hex0x,
    _to_bytes32,
    decode_transfers,
)
from admissible.envelope import digest_of
from admissible.gate import SettlementFacts

USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
SIBYL_PAYMENT_WALLET = "0xe3e14118238b5693c854674f7c276136a2dd311f"
SIBYL_IDENTITY_WALLET = "0x4069ef1afC8A9b2a29117A3740fCAB2912499fBe"
PAYER = "0xfC10f0A357c74318451A583C30A1fb5C8c7a2407"
SETTLEMENT_TX = "0xe70d3765e7955850cd22c22345a5e877f358d5776eaff0880ec65bac985ead8b"
SETTLEMENT_BLOCK = 51_053_955
SETTLEMENT_VALUE = 250_000

TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
ROUTER_TOPIC = "0x47db2abce6d5fbcd80ffd9b4ba74dcde804a746ef732bc7f8a70fabfc912c590"

AGENT_ID = 20880
IDENTITY_REGISTRY = "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432"
REPUTATION_REGISTRY = "0x8004BAa17C55a88189AE136b182e5fdA19dE9b63"
KNOWN_CLIENT = "0x31E8e9468EEFd1279E669578d54FF34F46978130"

#: A B20 token, confirmed by the factory precompile rather than by its address.
B20_TOKEN = "0xb2000000000000000000004f480c6f51BeD64155"
B20_HOLDER = "0x498581fF718922c3f8e6A244956aF099B2652b2b"

#: A feedback record that actually commits to a claim -- rare enough that it is
#: worth pinning one as a fixture.
HASHED_FEEDBACK = {
    "agent_id": 22178,
    "client": "0x103040545ac5031a11e8c03dd11324c7333a13c7",
    "index": 268,
    "block": 51_045_562,
    "hash": "0xca6c054ab7a01f3542a511173d9d15f9cb3b32548ddda9be4d4cde6dc843d5e3",
}


def _topic_addr(address: str) -> str:
    return "0x" + "0" * 24 + address[2:].lower()


def _word(value: int) -> str:
    return "0x" + f"{value:064x}"


def receipt(
    *,
    to: str = SIBYL_PAYMENT_WALLET,
    value: int = SETTLEMENT_VALUE,
    token: str = USDC,
    status: int = 1,
    include_transfer: bool = True,
) -> dict:
    """The real shape of the sibylcap settlement, with knobs for the bad cases.

    Logs 0 and 2 are the payment router's own events. Log 2 is the trap: it
    names the same recipient and the same value as the transfer, and is not one.
    """
    logs = [
        {
            "address": PAYER,
            "topics": ["0x2c51b4266e228b7f9c2401e482ed194b99ddaeefb4f7fc40677e6ee59838e359", _word(0)],
            "data": "0x",
            "logIndex": 478,
        }
    ]
    if include_transfer:
        logs.append(
            {
                "address": token,
                "topics": [TRANSFER_TOPIC, _topic_addr(PAYER), _topic_addr(to)],
                "data": _word(value),
                "logIndex": 479,
            }
        )
    logs.append(
        {
            "address": PAYER,
            "topics": [ROUTER_TOPIC, _topic_addr(to)],
            "data": _word(value),
            "logIndex": 480,
        }
    )
    return {
        "transactionHash": bytes.fromhex(SETTLEMENT_TX[2:]),
        "blockNumber": SETTLEMENT_BLOCK,
        "status": status,
        "logs": logs,
    }


class FakeEth:
    def __init__(self, receipts: dict, timestamp: int | None = 1_788_897_257) -> None:
        self._receipts = receipts
        self._timestamp = timestamp
        self.chain_id = 8453

    def get_transaction_receipt(self, tx_hash: str):
        from web3.exceptions import TransactionNotFound

        key = tx_hash.lower()
        if key not in self._receipts:
            raise TransactionNotFound(f"{tx_hash} not found")
        return self._receipts[key]

    def get_block(self, _block):
        return {"timestamp": self._timestamp}


class FakeWeb3:
    def __init__(self, receipts: dict, **kw) -> None:
        self.eth = FakeEth(receipts, **kw)


def chain_with(*receipts_: dict, tx: str = SETTLEMENT_TX, **kw) -> BaseChain:
    mapping = {tx.lower(): r for r in receipts_}
    return BaseChain(config=BASE_MAINNET, web3=FakeWeb3(mapping, **kw), retries=1)


# ---------------------------------------------------------------------------
# decoding
# ---------------------------------------------------------------------------


def test_decoder_ignores_router_events_that_look_like_transfers():
    """The decoy log has the right recipient and value and is not a transfer."""
    found = list(decode_transfers(receipt()["logs"], token=USDC))
    assert len(found) == 1
    assert found[0].value == SETTLEMENT_VALUE
    assert found[0].recipient.lower() == SIBYL_PAYMENT_WALLET
    assert found[0].sender.lower() == PAYER.lower()
    assert found[0].log_index == 479


def test_decoder_filters_by_token():
    """A transfer of a different token is not the transfer we asked about."""
    weth = "0x4200000000000000000000000000000000000006"
    assert list(decode_transfers(receipt(token=weth)["logs"], token=USDC)) == []
    assert len(list(decode_transfers(receipt(token=weth)["logs"], token=weth))) == 1


def test_decoder_survives_malformed_logs():
    """A receipt is attacker-influenced input; one bad log must not blind us."""
    logs = receipt()["logs"] + [
        {"address": USDC, "topics": [], "data": "0x"},
        {"address": USDC, "topics": [TRANSFER_TOPIC], "data": "0x"},
        {"address": USDC, "topics": [TRANSFER_TOPIC, _word(1), _word(2)], "data": "zzz"},
    ]
    assert len(list(decode_transfers(logs, token=USDC))) == 1


def test_hex0x_preserves_leading_zero_digests():
    """``"0x" + h.hex().lstrip("0x")`` eats these. One hash in sixteen."""
    raw = bytes.fromhex("00" + "ab" * 31)
    assert _hex0x(raw) == "0x00" + "ab" * 31
    assert len(_hex0x(raw)) == 66


def test_to_bytes32_rejects_anything_ambiguous():
    assert len(_to_bytes32("0x" + "11" * 32)) == 32
    assert _to_bytes32(b"\x02" * 32) == b"\x02" * 32
    for bad in ("0x1234", "nothex", "0x" + "11" * 33):
        with pytest.raises(ValueError):
            _to_bytes32(bad)
    with pytest.raises(TypeError):
        _to_bytes32(12345)


# ---------------------------------------------------------------------------
# verify_settlement -- the three refusals must stay three
# ---------------------------------------------------------------------------


def test_settlement_matches_when_everything_agrees():
    facts = chain_with(receipt()).verify_settlement(
        SETTLEMENT_TX, 8453, expected_to=SIBYL_PAYMENT_WALLET,
        expected_amount=SETTLEMENT_VALUE, expected_token=USDC,
    )
    assert facts.mismatch is Mismatch.NONE
    assert facts.settled
    assert facts.value == SETTLEMENT_VALUE
    assert facts.block == SETTLEMENT_BLOCK
    assert facts.timestamp == 1_788_897_257
    assert facts.recipient.lower() == SIBYL_PAYMENT_WALLET


def test_missing_transaction_is_none_not_a_mismatch():
    """"Never happened" is the one answer that is not a populated record."""
    assert chain_with(receipt()).verify_settlement("0x" + "de" * 32, 8453) is None


def test_wrong_recipient_is_distinguishable():
    facts = chain_with(receipt()).verify_settlement(
        SETTLEMENT_TX, 8453, expected_to=SIBYL_IDENTITY_WALLET, expected_amount=SETTLEMENT_VALUE
    )
    assert facts is not None
    assert facts.mismatch is Mismatch.RECIPIENT
    assert not facts.settled
    # Paying the agent's *identity* wallet instead of its payment wallet is the
    # realistic version of this mistake, so the facts still name who was paid.
    assert facts.recipient.lower() == SIBYL_PAYMENT_WALLET


def test_wrong_amount_is_distinguishable_from_wrong_recipient():
    facts = chain_with(receipt()).verify_settlement(
        SETTLEMENT_TX, 8453, expected_to=SIBYL_PAYMENT_WALLET, expected_amount=500_000
    )
    assert facts.mismatch is Mismatch.AMOUNT
    assert facts.value == SETTLEMENT_VALUE


def test_amount_is_compared_exactly():
    """One base unit short of $0.25 is not $0.25."""
    facts = chain_with(receipt()).verify_settlement(
        SETTLEMENT_TX, 8453, expected_to=SIBYL_PAYMENT_WALLET,
        expected_amount=SETTLEMENT_VALUE - 1,
    )
    assert facts.mismatch is Mismatch.AMOUNT


def test_reverted_transaction_moved_nothing():
    facts = chain_with(receipt(status=0)).verify_settlement(
        SETTLEMENT_TX, 8453, expected_to=SIBYL_PAYMENT_WALLET, expected_amount=SETTLEMENT_VALUE
    )
    assert facts.mismatch is Mismatch.REVERTED
    assert facts.value == 0
    assert not facts.settled


def test_no_transfer_at_all_differs_from_wrong_token():
    bare = chain_with(receipt(include_transfer=False)).verify_settlement(SETTLEMENT_TX, 8453)
    assert bare.mismatch is Mismatch.NO_TRANSFER

    weth = "0x4200000000000000000000000000000000000006"
    other = chain_with(receipt(token=weth)).verify_settlement(
        SETTLEMENT_TX, 8453, expected_token=USDC
    )
    assert other.mismatch is Mismatch.TOKEN
    assert other.transfers, "the transfer that did happen is still reported"


def test_fee_split_picks_the_transfer_we_asked_about():
    """A facilitator taking a fee emits two transfers; we must match the right one."""
    doubled = receipt()
    doubled["logs"].append(
        {
            "address": USDC,
            "topics": [TRANSFER_TOPIC, _topic_addr(PAYER), _topic_addr("0x" + "11" * 20)],
            "data": _word(5_000),
            "logIndex": 481,
        }
    )
    facts = chain_with(doubled).verify_settlement(
        SETTLEMENT_TX, 8453, expected_to=SIBYL_PAYMENT_WALLET, expected_amount=SETTLEMENT_VALUE
    )
    assert facts.mismatch is Mismatch.NONE
    assert facts.value == SETTLEMENT_VALUE
    assert len(facts.transfers) == 2, "both transfers stay visible to the gate"


def test_another_chains_receipt_is_not_answered_from_this_one():
    assert chain_with(receipt()).verify_settlement(SETTLEMENT_TX, 1) is None


def test_result_satisfies_the_gates_protocol():
    """The gate calls ``verify_settlement(tx, chain_id)`` and reads five fields."""
    facts = chain_with(receipt()).verify_settlement(SETTLEMENT_TX, 8453)
    assert isinstance(facts, SettlementFacts)
    assert (facts.tx_hash, facts.sender, facts.recipient, facts.value, facts.block) == (
        SETTLEMENT_TX,
        Web3.to_checksum_address(PAYER),
        Web3.to_checksum_address(SIBYL_PAYMENT_WALLET),
        SETTLEMENT_VALUE,
        SETTLEMENT_BLOCK,
    )


def test_evidence_lines_up_with_the_envelope():
    facts = chain_with(receipt()).verify_settlement(SETTLEMENT_TX, 8453)
    ev = facts.as_evidence().to_dict()
    assert ev == {
        "chain_id": 8453,
        "tx_hash": SETTLEMENT_TX,
        "block": SETTLEMENT_BLOCK,
        "kind": "x402:settlement",
    }


def test_unreachable_chain_is_raised_not_swallowed():
    """The gate turns this into a refusal. It must never look like absence."""

    class Broken:
        chain_id = 8453

        def get_transaction_receipt(self, _tx):
            raise ConnectionError("connection reset")

    broken = BaseChain(config=BASE_MAINNET, retries=2, backoff=0.0)
    broken.w3 = type("W", (), {"eth": Broken()})()
    with pytest.raises(ChainUnreachable):
        broken.verify_settlement(SETTLEMENT_TX, 8453)


# ---------------------------------------------------------------------------
# writes
# ---------------------------------------------------------------------------


def test_read_only_client_cannot_write():
    chain = BaseChain(config=BASE_MAINNET)
    assert chain.read_only and chain.address is None
    with pytest.raises(PermissionError):
        chain.give_feedback(AGENT_ID, 80, "0x" + "11" * 32)
    with pytest.raises(PermissionError):
        chain.register_agent("https://example.invalid/8004.json")


def test_zero_feedback_hash_is_impossible():
    """The differentiator, enforced rather than documented.

    92.8% of ``NewFeedback`` events on Base mainnet carry exactly this value.
    A record committing to ``bytes32(0)`` is consistent with any story told
    afterwards, so writing one would put a claim onchain we could not later
    re-derive ourselves.
    """
    chain = BaseChain(config=BASE_MAINNET, private_key="0x" + "11" * 32)
    for empty in (ZERO_HASH, b"\x00" * 32, "0x" + "00" * 32):
        with pytest.raises(ZeroFeedbackHash):
            chain.give_feedback(AGENT_ID, 80, empty)


def test_a_real_digest_is_accepted_by_the_hash_check():
    """The refusal must reject emptiness, not every hash."""
    digest = digest_of({"counterparty": SIBYL_PAYMENT_WALLET, "amount_usd": "0.25"})
    assert _to_bytes32(digest) != b"\x00" * 32
    assert len(_to_bytes32(digest)) == 32


# ---------------------------------------------------------------------------
# agent records
# ---------------------------------------------------------------------------


def _record(**kw) -> AgentRecord:
    base = dict(
        agent_id=AGENT_ID,
        chain_id=8453,
        registry=IDENTITY_REGISTRY,
        owner=SIBYL_IDENTITY_WALLET,
        wallet=SIBYL_IDENTITY_WALLET,
        token_uri="https://sibylcap.com/8004.json",
        registration={
            "name": "SIBYL",
            "registrations": [
                {"agentId": AGENT_ID, "agentRegistry": f"eip155:8453:{IDENTITY_REGISTRY}"}
            ],
            "wallets": {
                "identity": {"address": SIBYL_IDENTITY_WALLET},
                "payment": {"address": SIBYL_PAYMENT_WALLET},
            },
        },
    )
    base.update(kw)
    return AgentRecord(**base)


def test_payment_wallet_is_not_the_owner():
    """Checking a settlement against the owner would reject every real payment."""
    record = _record()
    assert record.self_declaration_matches
    assert SIBYL_PAYMENT_WALLET in record.payment_wallets()
    assert record.payment_wallets()[0] == SIBYL_PAYMENT_WALLET
    assert record.owner.lower() != SIBYL_PAYMENT_WALLET


def test_manifest_pointing_at_another_registry_does_not_match():
    """An agent whose JSON points elsewhere is misconfigured or impersonating."""
    record = _record(
        registration={
            "registrations": [{"agentId": AGENT_ID, "agentRegistry": "eip155:1:0xdeadbeef"}]
        }
    )
    assert not record.self_declaration_matches


def test_missing_manifest_falls_back_to_the_registered_wallet():
    record = _record(registration=None)
    assert not record.self_declaration_matches
    assert record.payment_wallets() == (SIBYL_IDENTITY_WALLET.lower(),)


# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------


def test_presets_are_the_addresses_we_verified():
    assert BASE_MAINNET.chain_id == 8453
    assert BASE_SEPOLIA.chain_id == 84532
    assert BASE_MAINNET.usdc == USDC
    assert BASE_MAINNET.b20_factory == "0xB20f000000000000000000000000000000000000"
    assert BASE_MAINNET.identity_registry == IDENTITY_REGISTRY
    assert BASE_MAINNET.reputation_registry == REPUTATION_REGISTRY


def test_unknown_chain_id_is_refused_rather_than_guessed():
    with pytest.raises(ValueError):
        BaseChain(chain_id=999999)


def test_from_env_is_read_only_without_a_key():
    assert BaseChain.from_env(env={}).read_only
    assert not BaseChain.from_env(env={"PRIVATE_KEY": "0x" + "11" * 32}).read_only


# ---------------------------------------------------------------------------
# live -- deselect with -m "not live"
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def live() -> BaseChain:
    return BaseChain(config=BASE_MAINNET, retries=6, backoff=1.5)


@pytest.mark.live
def test_live_resolves_agent_20880(live: BaseChain):
    record = live.resolve_agent(AGENT_ID)
    assert record.owner.lower() == SIBYL_IDENTITY_WALLET.lower()
    assert record.wallet.lower() == SIBYL_IDENTITY_WALLET.lower()
    assert record.token_uri == "https://sibylcap.com/8004.json"
    assert record.registration is not None, "the manifest was reachable"
    assert record.registration["name"] == "SIBYL"
    assert record.self_declaration_matches, "the manifest points back at the registry"
    assert SIBYL_PAYMENT_WALLET in record.payment_wallets()


@pytest.mark.live
def test_live_registry_identity(live: BaseChain):
    """Go through ``_call``: the public endpoint rate-limits, and retrying is
    the client's job rather than something a caller should remember."""
    name = live._call(lambda: live.identity.functions.name().call(), "name()")
    linked = live._call(
        lambda: live.reputation.functions.getIdentityRegistry().call(), "getIdentityRegistry()"
    )
    assert name == "AgentIdentity"
    assert linked == IDENTITY_REGISTRY, "the two registries point at each other"


@pytest.mark.live
def test_live_summary_of_agent_20880(live: BaseChain):
    summary = live.get_summary(AGENT_ID, [KNOWN_CLIENT])
    assert (summary.count, summary.value, summary.decimals) == (4, 50, 0)


@pytest.mark.live
def test_live_get_summary_handles_the_empty_clients_revert(live: BaseChain):
    """The registry reverts on an empty client list; we fetch them instead."""
    clients = live.get_clients(AGENT_ID)
    assert len(clients) >= 31
    assert KNOWN_CLIENT in clients
    summary = live.get_summary(AGENT_ID)
    assert summary.count > 0 and len(summary.clients) == len(clients)


@pytest.mark.live
def test_live_read_feedback(live: BaseChain):
    record = live.read_feedback(AGENT_ID, KNOWN_CLIENT, 1)
    assert (record.value, record.value_decimals) == (80, 2)
    assert record.score == pytest.approx(0.8)
    assert (record.tag1, record.tag2) == ("ping", "positive")
    assert not record.is_revoked


@pytest.mark.live
def test_live_feedback_hash_comes_from_the_log_not_the_getter(live: BaseChain):
    """``readFeedback`` cannot return the digest. The event can."""
    found = live.read_feedback_hash(
        REPUTATION_REGISTRY,
        HASHED_FEEDBACK["agent_id"],
        HASHED_FEEDBACK["index"],
        8453,
        client=HASHED_FEEDBACK["client"],
        from_block=HASHED_FEEDBACK["block"] - 400,
    )
    assert found == HASHED_FEEDBACK["hash"]

    record = live.read_feedback(
        HASHED_FEEDBACK["agent_id"], HASHED_FEEDBACK["client"], HASHED_FEEDBACK["index"],
        with_hash=True, from_block=HASHED_FEEDBACK["block"] - 400,
    )
    assert record.commits_to_a_claim
    assert record.feedback_hash == HASHED_FEEDBACK["hash"]
    assert record.block == HASHED_FEEDBACK["block"]


@pytest.mark.live
def test_live_feedback_hash_refuses_a_foreign_registry(live: BaseChain):
    """A memory citing another registry must not be answered from this one."""
    assert live.read_feedback_hash("0x" + "de" * 20, AGENT_ID, 1, 8453) is None
    assert live.read_feedback_hash(REPUTATION_REGISTRY, AGENT_ID, 1, 1) is None


@pytest.mark.live
def test_live_verifies_a_real_x402_settlement(live: BaseChain):
    """A genuine $0.25 payment to agent 20880 for its evaluate endpoint."""
    facts = live.verify_settlement(
        SETTLEMENT_TX, 8453, expected_to=SIBYL_PAYMENT_WALLET,
        expected_amount=SETTLEMENT_VALUE, expected_token=USDC,
    )
    assert facts is not None and facts.settled
    assert facts.value == SETTLEMENT_VALUE
    assert facts.block == SETTLEMENT_BLOCK
    assert facts.timestamp is not None
    assert facts.recipient.lower() == SIBYL_PAYMENT_WALLET
    assert facts.token.lower() == USDC.lower()


@pytest.mark.live
def test_live_settlement_mismatches_are_still_three_answers(live: BaseChain):
    assert live.verify_settlement("0x" + "de" * 32, 8453) is None
    assert (
        live.verify_settlement(SETTLEMENT_TX, 8453, expected_to="0x" + "de" * 20).mismatch
        is Mismatch.RECIPIENT
    )
    assert (
        live.verify_settlement(
            SETTLEMENT_TX, 8453, expected_to=SIBYL_PAYMENT_WALLET, expected_amount=1
        ).mismatch
        is Mismatch.AMOUNT
    )


@pytest.mark.live
def test_live_b20_read(live: BaseChain):
    """A B20 read is an ordinary call, and the factory is the only proof."""
    assert live.is_b20(B20_TOKEN) is True
    assert live.is_b20(USDC) is False, "an ERC-20 is not a B20"
    assert live.b20_balance(B20_TOKEN, B20_HOLDER) > 0


@pytest.mark.live
def test_live_b20_address_prefix_proves_nothing(live: BaseChain):
    """Base is full of ordinary ERC-20s at vanity ``0xb200…`` addresses.

    Trusting the prefix is the bug; asking the factory precompile is the fix.
    """
    assert USDC.lower().startswith("0x8335")
    assert live.is_b20(IDENTITY_REGISTRY) is False
