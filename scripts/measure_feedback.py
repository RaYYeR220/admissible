"""Re-run the ERC-8004 feedback measurement quoted in the README and PROOF.md.

Three numbers get quoted about `feedbackHash` on Base mainnet, and they answer
three different questions about the same scan:

    per event          what fraction of NewFeedback logs commit bytes32(0)
    per event, minus   the same fraction once the single most prolific agent
      the outlier      stops carrying it
    per agent          how many distinct agents have never received a hashed
                       feedback at all

Quoting only the first overstates the typical case; quoting only the second
understates the aggregate. So all three are printed, from one pass, and this
script is the thing they come from.

The window is fixed by default -- the 300,000 blocks ending at 51,055,657 --
so the numbers are deterministic and re-derivable, not "whatever the chain
looked like the day someone ran it". Pass --to-block / --blocks to move it, and
--json for the machine-readable form.

Reads only. No key, no funds::

    python scripts/measure_feedback.py
    BASE_RPC_URL=https://... python scripts/measure_feedback.py --json

How long it takes is the endpoint's decision, not ours. Public Base RPCs cap the
span of a single ``eth_getLogs`` and move that cap without notice --
``https://mainnet.base.org`` served 10,000-block windows on one run and answered
``eth_getLogs is limited to a 2,000 range`` on the next -- so the scan narrows
its window when it is refused and keeps going: 30 calls and half a minute at
best, ~150 calls and a few minutes at the narrowest. The counts do not depend on
the window size; only the call count does. Point ``BASE_RPC_URL`` at an endpoint
you control and it is the fast path every time.

The decoding is not re-implemented here: the registry address, the ABI and the
NewFeedback topic all come from ``admissible.chain``, which is what the gate
itself uses. If this script and the gate ever disagree about what a feedback
record is, that is a bug in one shared place rather than in a copy.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packages" / "admissible" / "src"))

from admissible.chain import (  # noqa: E402
    BASE_MAINNET,
    NEW_FEEDBACK_TOPIC,
    ZERO_HASH,
    BaseChain,
    ChainUnreachable,
)

#: The block the published numbers were measured to. Fixed on purpose: a
#: measurement anybody can re-run has to name the window it was taken over.
DEFAULT_TO_BLOCK = 51_055_657
DEFAULT_BLOCKS = 300_000
#: Widest ``eth_getLogs`` span to try first. Public Base endpoints disagree about
#: their own limit and change it without notice -- the same endpoint answered a
#: 10,000-block request one hour and replied "eth_getLogs is limited to a 2,000
#: range" the next -- so this is a starting point, not a constant.
CHUNK = 9_999
#: Narrowest span worth trying before giving up. Below this, the endpoint is not
#: rate-limiting, it is broken, and pretending otherwise would take all day.
MIN_CHUNK = 499
#: How a range refusal reads on the wire, from the endpoints seen so far.
_RANGE_REFUSALS = ("range", "413", "too large", "limited to", "query returned more than")


def _is_range_refusal(exc: Exception) -> bool:
    """A window the endpoint thinks is too wide, as distinct from a dead endpoint."""
    text = str(exc).lower()
    return any(marker in text for marker in _RANGE_REFUSALS)


def scan(
    chain: BaseChain,
    *,
    to_block: int,
    blocks: int,
    chunk: int = CHUNK,
    verbose: bool = True,
) -> dict[str, Any]:
    """One pass over NewFeedback, counting hashes per event and per agent.

    The window narrows itself when the endpoint says the span is too wide, which
    changes how many calls this takes but not the answer: the same 300,000 blocks
    counted in spans of 10,000, 5,000, 2,500 and 2,000 blocks give the same 8,690
    events, and no single call has come near a result cap (the widest response
    seen was 234 logs).
    """
    from web3 import Web3

    address = Web3.to_checksum_address(chain.config.reputation_registry)
    decoder = chain.reputation.events.NewFeedback()
    from_block = to_block - blocks + 1

    events = 0
    zero_hash = 0
    per_agent: Counter[int] = Counter()
    hashed_per_agent: Counter[int] = Counter()

    start = from_block
    windows = 0
    spans: set[int] = set()
    while start <= to_block:
        end = min(start + chunk, to_block)
        try:
            logs = chain._call(  # noqa: SLF001 -- the retry/backoff policy, not a copy of it
                lambda s=start, e=end: chain.w3.eth.get_logs(
                    {
                        "address": address,
                        "fromBlock": s,
                        "toBlock": e,
                        "topics": [NEW_FEEDBACK_TOPIC],
                    }
                ),
                f"eth_getLogs({start}-{end})",
            )
        except ChainUnreachable as exc:
            if chunk > MIN_CHUNK and _is_range_refusal(exc):
                chunk = max(MIN_CHUNK, chunk // 5)
                if verbose:
                    print(
                        f"  endpoint refused the span; narrowing to {chunk + 1:,} blocks"
                        + " " * 20
                    )
                continue
            raise
        windows += 1
        spans.add(end - start + 1)
        for log in logs:
            decoded = decoder.process_log(log)
            agent = int(decoded["args"]["agentId"])
            digest = "0x" + bytes(decoded["args"]["feedbackHash"]).hex()
            events += 1
            per_agent[agent] += 1
            if digest == ZERO_HASH:
                zero_hash += 1
            else:
                hashed_per_agent[agent] += 1
        if verbose:
            print(
                f"  {end - from_block + 1:>7,} / {blocks:,} blocks   {events:>6,} events",
                end="\r",
                flush=True,
            )
        start = end + 1

    if verbose:
        print(" " * 60, end="\r")

    if not events:
        raise SystemExit(
            f"no NewFeedback events in blocks {from_block}-{to_block} at {address}. "
            "Either the window is wrong or the endpoint is not Base mainnet."
        )

    outlier, outlier_events = per_agent.most_common(1)[0]
    rest_events = events - outlier_events
    rest_zero = zero_hash - (outlier_events - hashed_per_agent[outlier])
    never_hashed = sum(1 for agent in per_agent if hashed_per_agent[agent] == 0)

    return {
        "registry": address,
        "chain_id": chain.chain_id,
        "from_block": from_block,
        "to_block": to_block,
        "blocks": blocks,
        "windows": windows,
        "window_spans": sorted(spans),
        "events": events,
        "zero_hash": zero_hash,
        "zero_hash_pct": round(100 * zero_hash / events, 2),
        "outlier_agent": outlier,
        "outlier_events": outlier_events,
        "rest_events": rest_events,
        "rest_zero_hash": rest_zero,
        "rest_zero_hash_pct": round(100 * rest_zero / rest_events, 2) if rest_events else None,
        "agents": len(per_agent),
        "agents_never_hashed": never_hashed,
        "agents_never_hashed_pct": round(100 * never_hashed / len(per_agent), 2),
    }


def report(r: dict[str, Any]) -> None:
    print()
    print(f"  registry     {r['registry']}  (chain {r['chain_id']})")
    print(f"  window       blocks {r['from_block']:,} to {r['to_block']:,}  ({r['blocks']:,})")
    spans = "/".join(f"{s:,}" for s in r["window_spans"])
    print(
        f"  events       {r['events']:,} NewFeedback in {r['windows']} eth_getLogs calls"
        f"  (spans of {spans} blocks)"
    )
    print()
    print("  per event")
    print(
        f"    {r['zero_hash']:,} of {r['events']:,} commit a zero feedbackHash"
        f"   {r['zero_hash_pct']}%"
    )
    print()
    print("  per event, excluding the single most prolific agent")
    print(f"    agent {r['outlier_agent']} alone emits {r['outlier_events']:,} of them")
    print(
        f"    {r['rest_zero_hash']:,} of the remaining {r['rest_events']:,}"
        f"          {r['rest_zero_hash_pct']}%"
    )
    print()
    print("  per agent")
    print(
        f"    {r['agents_never_hashed']} of {r['agents']} agents have never received"
        f" a hashed feedback   {r['agents_never_hashed_pct']}%"
    )
    print()


def main() -> int:
    ap = argparse.ArgumentParser(description="Measure ERC-8004 feedbackHash usage on Base.")
    ap.add_argument("--to-block", type=int, default=DEFAULT_TO_BLOCK, help="last block, inclusive")
    ap.add_argument("--blocks", type=int, default=DEFAULT_BLOCKS, help="how many blocks back")
    ap.add_argument(
        "--chunk",
        type=int,
        default=CHUNK,
        help="widest eth_getLogs span to try; narrows itself if the endpoint refuses",
    )
    ap.add_argument("--json", action="store_true", help="machine-readable, nothing else on stdout")
    args = ap.parse_args()

    chain = BaseChain.from_env(BASE_MAINNET)
    if not args.json:
        print(f"\n  scanning {chain.rpc_url}")
    result = scan(
        chain,
        to_block=args.to_block,
        blocks=args.blocks,
        chunk=args.chunk,
        verbose=not args.json,
    )

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        report(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
