"""Admissible -- memory that has to prove itself before it can move money.

An agent's memory is an attack surface. Anything that can write to it can steer
what it buys, from whom, and at what price, and most agent memory layers accept a
claim because it is in the store rather than because anything backs it.

This package adds one rule and the machinery to enforce it: a memory may not
justify moving more money than can be found on chain, moved to the party it vouches
for, by somebody who is not that party.

Layout
------
``envelope``     what a memory is: a claim, its provenance, and two clocks
``verdicts``     the vocabulary of refusal
``gate``         the admission controller -- the security boundary
``policy``       admissibility turned into pay / escrow / refuse
``store``        Sibyl Memory with provenance, journalling every write
``flagged``      the FLAGGED tier Sibyl's schema declares and never shipped
``relations``    the entity graph it also declares and never shipped
``timeline``     bi-temporal replay: what did the agent know when it decided
``consolidate``  many events folded into one counterparty dossier
``chain``        Base: settlements, ERC-8004 reputation, anchors
``wiring``       how the store and the chain meet the gate
"""

from .envelope import Envelope, Evidence, Provenance, Tier, digest_of, utcnow
from .gate import AdmissionGate, ChainUnreachable, SettlementFacts
from .policy import Decision, TrustPolicy, laundering_attempts
from .verdicts import Verdict, VerdictCode

__all__ = [
    "AdmissionGate",
    "ChainUnreachable",
    "Decision",
    "Envelope",
    "Evidence",
    "Provenance",
    "SettlementFacts",
    "Tier",
    "TrustPolicy",
    "Verdict",
    "VerdictCode",
    "digest_of",
    "laundering_attempts",
    "utcnow",
]

__version__ = "0.1.0"
