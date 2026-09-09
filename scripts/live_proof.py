"""The mainnet proof chain, end to end, against a counterparty we did not invent.

Everything the demo does with recorded fixtures, done for real on Base mainnet
against ERC-8004 agent #20880 -- the hackathon organiser's own agent, which
genuinely sells x402 services. There is no mock in this path.

    1. fetch the 402 challenge from a real paid endpoint
    2. verify the payee against the agent's ONCHAIN manifest, not the response
    3. settle USDC on chain
    4. present the settled hash and take delivery
    5. write the outcome as an ATTESTED memory
    6. put it through the gate, which re-reads the chain to re-derive it
    7. write ERC-8004 feedback whose committed hash is that memory's digest
    8. anchor a Merkle root over everything the agent now holds admissible

Step 7 is the point. A published measurement found 98.7 to 100 percent of
ERC-8004 feedback carries no payment proof; our own scan of 8,690 events on Base
found 92.8 percent commit a zero hash (``scripts/measure_feedback.py`` re-runs
it, reads only, no key). The registry cannot check it for you --
``readFeedback`` does not even return the hash, which is why our reader parses
the ``NewFeedback`` event instead. So a feedback record that both carries a real
digest and has a settled payment behind it is a different kind of object from
the ones already in there.

    PRIVATE_KEY=0x...  python scripts/live_proof.py            # dry run, reads only
    PRIVATE_KEY=0x...  python scripts/live_proof.py --execute  # spends real USDC

Without --execute nothing is broadcast. With it, the run costs the price of one
service call plus gas.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "admissible" / "src"))
sys.path.insert(0, str(ROOT))

from admissible.anchor import commit  # noqa: E402
from admissible.chain import BaseChain, Mismatch  # noqa: E402
from admissible.envelope import Envelope, Evidence, Provenance, Tier  # noqa: E402
from admissible.store import AdmissibleStore  # noqa: E402
from admissible.wiring import build_gate  # noqa: E402
from admissible.x402_pay import X402Payer  # noqa: E402

BASE_RPC = os.environ.get("BASE_RPC_URL", "https://mainnet.base.org")
CHAIN_ID = 8453
SIBYL_AGENT_ID = 20880
REPUTATION = "0x8004BAa17C55a88189AE136b182e5fdA19dE9b63"
USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"

#: The service actually takes a token to evaluate. Its manifest advertises a
#: cheaper /api/check at $0.02 which returns 404 on mainnet today; we record that
#: rather than quietly picking the working one and calling it the cheapest.
SERVICE = "https://sibylcap.com/api/evaluate?token=" + USDC
PRICE_BASE_UNITS = 250_000

STORE_PATH = os.environ.get("ADMISSIBLE_DB", str(ROOT / ".live" / "mainnet.db"))


def step(n: int, title: str) -> None:
    print(f"\n{'=' * 74}\n  {n}. {title}\n{'=' * 74}")


def _tx_hash_of(receipt: object) -> str:
    """Pull a transaction hash out of whatever a write handed back.

    web3 receipts, plain mappings and bare hashes all turn up here depending on
    which path produced them, and a KeyError at this point would lose a
    transaction that has already been broadcast and paid for.
    """
    value = receipt
    if hasattr(receipt, "get"):
        for key in ("transactionHash", "tx_hash", "hash"):
            found = receipt.get(key)  # type: ignore[union-attr]
            if found is not None:
                value = found
                break
    if hasattr(value, "hex"):
        value = value.hex()
    text = str(value)
    return text if text.startswith("0x") else "0x" + text


def link(kind: str, value: str) -> str:
    return f"https://basescan.org/{kind}/{value}"


async def main(execute: bool) -> int:
    chain = BaseChain(rpc_url=BASE_RPC, chain_id=CHAIN_ID, private_key=os.environ.get("PRIVATE_KEY"))
    payer = X402Payer.from_env(chain=chain) if os.environ.get("PRIVATE_KEY") else X402Payer(chain=chain)
    proof: dict[str, object] = {"chain_id": CHAIN_ID, "service": SERVICE}

    step(1, "the counterparty, resolved from chain rather than from its website")
    agent = chain.resolve_agent(SIBYL_AGENT_ID)
    print(f"     agent id      {SIBYL_AGENT_ID}")
    print(f"     owner         {agent.owner}")
    print(f"     agent wallet  {agent.wallet}")
    print(f"     tokenURI      {agent.token_uri}")
    proof["agent"] = {"id": SIBYL_AGENT_ID, "owner": agent.owner, "wallet": agent.wallet}

    step(2, "the 402 challenge, and the payee checked against that manifest")
    challenge = await payer.challenge(SERVICE, method="POST", json_body={})
    recipient = payer.expected_recipient(challenge, agent_id=SIBYL_AGENT_ID)
    print(f"     asks          {challenge.amount} base units of {challenge.asset}")
    print(f"     payTo         {challenge.pay_to}")
    print(f"     vouched by    the agent's onchain manifest -> {recipient}")
    if challenge.amount != PRICE_BASE_UNITS:
        print(f"     note          price moved from {PRICE_BASE_UNITS}; using the live number")
    proof["challenge"] = {"pay_to": challenge.pay_to, "amount": challenge.amount, "asset": challenge.asset}

    tx_hash = os.environ.get("SETTLEMENT_TX")
    if not tx_hash:
        if not execute:
            print("\n  dry run: stopping before spending. pass --execute to settle.")
            return 0
        step(3, "settling on chain, before the request rather than inside it")
        tx_hash = chain.transfer_erc20(challenge.asset, challenge.pay_to, challenge.amount)
        print(f"     tx            {tx_hash}")
        print(f"                   {link('tx', tx_hash)}")
    else:
        step(3, "reusing a settlement already on chain")
        print(f"     tx            {tx_hash}")
    proof["settlement_tx"] = tx_hash

    step(4, "re-reading that settlement from the chain, not from a header")
    settled = chain.verify_settlement(
        tx_hash, CHAIN_ID, expected_to=challenge.pay_to,
        expected_amount=challenge.amount, expected_token=challenge.asset,
    )
    # Mismatch is a str enum, so Mismatch.NONE is truthy. Compare identity, not
    # truthiness: the difference between "verified" and "wrong recipient" is the
    # whole check.
    if settled is None or settled.mismatch is not Mismatch.NONE:
        print(f"     REFUSED       {settled}")
        return 1
    print(f"     from          {settled.sender}")
    print(f"     to            {settled.recipient}")
    print(f"     value         {settled.value} base units")
    print(f"     block         {settled.block}")

    step(5, "taking delivery with the settled hash")
    result = await payer.pay_with_settled_tx(SERVICE, tx_hash, method="POST", json_body={})
    status = result.response.status_code
    print(f"     http          {status}")
    body = result.response.json() if status == 200 else {}
    if status == 200:
        print(f"     delivered     {json.dumps(body)[:160]}...")
    else:
        # The hash is single-use and expires in about two minutes, which is the
        # right design on their side. Re-running against an old settlement lands
        # here, and the memory below records what actually happened rather than
        # the happy path we wanted.
        print("     note          the settlement is spent; delivery is not being claimed")
    proof["service_http"] = status

    step(6, "writing it down, with where to look to re-derive it")
    store = AdmissibleStore.open(STORE_PATH)
    memory = Envelope(
        # The counterparty is the address that was actually paid, which is the
        # agent's PAYMENT wallet and not its identity wallet -- 20880 uses two.
        # Naming the identity wallet here reads correct and is not: the gate
        # answered counterparty_mismatch the first time this script did it,
        # because the transfer genuinely does not involve that address. The
        # agent id records who the payee belongs to, vouched for by the manifest
        # read in step 1 rather than by this claim.
        claim={
            "counterparty": settled.recipient,
            "agent_id": SIBYL_AGENT_ID,
            "outcome": "delivered" if status == 200 else "not_delivered",
            "amount_usd": challenge.amount / 1_000_000,
            "service": "project-evaluation",
        },
        provenance=Provenance(
            tier=Tier.ATTESTED,
            source="x402:settlement",
            actor_address=settled.sender,
            evidence=Evidence(chain_id=CHAIN_ID, tx_hash=tx_hash, block=settled.block,
                              kind="x402:settlement"),
        ),
    )
    store.remember("interaction", f"sibylcap-{tx_hash[:10]}", memory)
    print(f"     digest        {memory.digest}")
    proof["memory_digest"] = memory.digest

    step(7, "the gate, pointed at mainnet, deciding whether it may move money")
    gate, _ = build_gate(store, chain, self_address=settled.sender)
    verdict = gate.admit(store.recall("interaction", f"sibylcap-{tx_hash[:10]}"))
    print(f"     verdict       {verdict.code.value}   admits={verdict.admits}")
    print(f"     because       {verdict.explain}")
    proof["verdict"] = verdict.to_dict()
    if not verdict.admits:
        print("\n  the gate refused its own evidence. stopping rather than papering over it.")
        return 1

    step(8, "ERC-8004 feedback whose committed hash is that memory")
    print(f"     registry      {REPUTATION}")
    print(f"     feedbackHash  {memory.digest}")
    if execute:
        # Score 1.00 on a two-decimal scale. The hash is the whole point: it
        # commits to the exact claim above, so anyone can fetch the NewFeedback
        # event and re-derive what this score was actually about.
        receipt = chain.give_feedback(
            SIBYL_AGENT_ID, 100, memory.digest,
            uri="", tag="admissible", score_decimals=2, tag2="settled",
        )
        fb = _tx_hash_of(receipt)
        print(f"     tx            {fb}")
        print(f"                   {link('tx', fb)}")
        proof["feedback_tx"] = fb
    else:
        print("     dry run, not sent")

    step(9, "anchoring everything currently admissible")
    admissible_now = []
    for env in store.recall_many("interaction"):
        if isinstance(env, Envelope) and gate.admit(env).admits:
            admissible_now.append((env.digest, env.provenance.observed_at))
    c = commit(admissible_now)
    print(f"     leaves        {c.leaf_count}")
    print(f"     root          {c.root_hex}")
    print(f"     asOf          {c.as_of}")
    anchor_address = os.environ.get("ANCHOR_ADDRESS")
    if execute and anchor_address:
        tx = chain.anchor(anchor_address, c.root_hex, c.as_of_unix, c.leaf_count)
        print(f"     tx            {tx}")
        print(f"                   {link('tx', tx)}")
        proof["anchor_tx"] = tx
    proof["anchor"] = {"root": c.root_hex, "leaves": c.leaf_count, "as_of": c.as_of}

    out = ROOT / "PROOF.json"
    out.write_text(json.dumps(proof, indent=2), encoding="utf-8")
    print(f"\n  written to {out}")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--execute", action="store_true", help="broadcast; without it nothing is sent")
    raise SystemExit(asyncio.run(main(ap.parse_args().execute)))
