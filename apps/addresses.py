"""The cast, by address.

Every address here is EIP-55 checksummed, and each one is marked REAL or
SYNTHETIC below. REAL means live on Base mainnet and checkable in a block
explorer; SYNTHETIC means a vanity placeholder that has never sent a transaction
there -- nonce 0, no bytecode -- standing in for a party the demo invents. (The
burn-shaped ones hold stray ETH other people sent them. Nothing here reads it.)
They are declared once, in one place, because the demo, the eval and the tests
all have to agree on who is who -- an attack story told with two different
spellings of the attacker's address is not a story anyone can check.

``bench/corpus.py`` declares the same four public constants for the offline
scorecard. They are not imported from there (the bench is a scoring harness, not
a library, and this package should not depend on it); ``apps/tests`` asserts the
two agree, so a drift is a test failure rather than a silent divergence.
"""

from __future__ import annotations

#: Base mainnet.
BASE_CHAIN_ID = 8453
#: REAL. USDC on Base. Six decimals, which is why money is compared in base units.
USDC_BASE = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
#: REAL. ERC-8004 reputation registry on Base mainnet.
REPUTATION_REGISTRY = "0x8004BAa17C55a88189AE136b182e5fdA19dE9b63"

#: REAL. Us: the buyer, the agent that holds the money and the memory.
OUR_AGENT = "0x8cDec2c69be9e200A8591da3e86e822B03f7cE1f"
OUR_HANDLE = "admissible-buyer"

#: REAL. The honest seller: @sibylcap, ERC-8004 agent #20880, selling real x402
#: services on Base. This is the identity wallet its onchain manifest declares --
#: its payment wallet is a different address. The demo's negative control is a
#: counterparty that exists.
SIBYLCAP = "0x4069ef1afC8A9b2a29117A3740fCAB2912499fBe"
SIBYLCAP_HANDLE = "sibylcap"
SIBYLCAP_AGENT_ID = 20880

#: SYNTHETIC. An address with no history at all. Every fabricated claim in the
#: demo points here, because the interesting failure is credit to a stranger.
STRANGER = "0x000000000000000000000000000000000000dEaD"
STRANGER_HANDLE = "brightwater-labs"

#: SYNTHETIC. The adversary. Writes into the same store the buyer reads.
POISONER = "0x0000000000000000000000000000000000bADa55"
POISONER_HANDLE = "helix-ops"

#: SYNTHETIC. The adversary's accomplice. It never forges anything itself -- it only
#: vouches -- which is exactly why it survives a per-claim check and only falls
#: to the relations walk.
PARTNER = "0x0000000000000000000000000000000000C0FFEE"
PARTNER_HANDLE = "meridian-referrals"

__all__ = [
    "BASE_CHAIN_ID",
    "OUR_AGENT",
    "OUR_HANDLE",
    "PARTNER",
    "PARTNER_HANDLE",
    "POISONER",
    "POISONER_HANDLE",
    "REPUTATION_REGISTRY",
    "SIBYLCAP",
    "SIBYLCAP_AGENT_ID",
    "SIBYLCAP_HANDLE",
    "STRANGER",
    "STRANGER_HANDLE",
    "USDC_BASE",
]
