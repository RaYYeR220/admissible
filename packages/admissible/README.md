# admissible

Provenance-gated memory for agents that move money. A memory-extension layer over
[Sibyl Memory](https://github.com/Sibyl-Labs/Sibyl-Memory).

```bash
pip install -e .
```

## The rule

A memory may not justify moving more money than can be found on chain, moved to the party it
vouches for, by somebody who is not that party. Everything in this package exists to make that
checkable rather than aspirational. The sentence is narrow on purpose -- see `LIMITS.md` for the
broader one it replaced and why that one was not true.

```python
from admissible import AdmissionGate, Envelope, Provenance, Evidence, Tier, TrustPolicy
from admissible.store import AdmissibleStore
from admissible.wiring import build_gate

store = AdmissibleStore.open("~/.sibyl-memory/memory.db")
gate, history = build_gate(store, chain=None)      # offline: every chain check refuses

claim = {"counterparty": "0x4069...", "outcome": "delivered", "amount_usd": 0.25}
memory = Envelope(
    claim=claim,
    provenance=Provenance(
        tier=Tier.ATTESTED,
        source="x402:settlement",
        actor_address="0x8cDe...",
        evidence=Evidence(chain_id=8453, tx_hash="0x...", kind="x402:settlement"),
    ),
)
store.remember("interaction", "job-1", memory)

verdict = gate.admit(store.recall("interaction", "job-1"))
print(verdict.code, verdict.explain)

decision = TrustPolicy().decide("0x4069...", 0.25, [(memory, verdict)])
print(decision.action, decision.citations())
```

## Modules

| module | what it holds |
|---|---|
| `envelope` | what a memory is: a claim, its provenance, and two clocks |
| `verdicts` | the vocabulary of refusal, and the allowlist that admits |
| `gate` | the admission controller — the security boundary |
| `policy` | admissibility turned into pay / escrow / refuse |
| `store` | Sibyl Memory with provenance, journalling every write |
| `flagged` | the FLAGGED tier Sibyl's schema declares and never shipped |
| `relations` | the entity graph it also declares and never shipped |
| `timeline` | bi-temporal replay: what did the agent know when it decided |
| `consolidate` | many events folded into one counterparty dossier |
| `anchor` | the Merkle commitment published onchain |
| `chain` | Base: settlements, ERC-8004 reputation, B20 |
| `wiring` | how the store and the chain meet the gate |

## Two clocks

`observed_at` is *transaction time* — when the agent learned a claim. `valid_from` / `valid_to` is
*valid time* — when the claim was true of the world. Keeping both is what makes `as_of` replay
honest, and it is the cheapest tell there is for a memory injected today wearing an old date.

## Command line

```bash
admissible doctor                       # environment, store, chain, key presence
admissible verify interaction job-1     # exit 0 if admissible
admissible decide 0x4069... 0.25        # the decision with its citations
admissible flags                        # the FLAGGED tier
admissible timeline interaction job-1 --as-of 2026-09-08T12:00:00Z
admissible anchor                       # root, leaf count, watermark
admissible proof 0x<digest>             # inclusion proof against the latest commitment
```

Every subcommand takes `--json`. All of them work offline with no keys.

## Tests

```bash
pytest -q                       # offline
pytest -q -m live               # reads Base mainnet
ANCHOR_ADDRESS=0x... pytest -q -m anvil   # differential against a deployed contract
```

MIT.
