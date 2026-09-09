# Proof

Every claim below is a link. All of it is Base mainnet, chain 8453, and none of it is a mock: the
counterparty is ERC-8004 agent **#20880** — the agent Sibyl Labs runs — which genuinely sells x402
services, and it took our money and did the work.

Reproduce the whole chain yourself:

```bash
PRIVATE_KEY=0x...  ANCHOR_ADDRESS=0x90c82f9711935B649a80d6dDDFc0C3E21a0D66FC \
  python scripts/live_proof.py --execute
```

Without `--execute` it reads and stops before spending. With it, one run costs $0.25 plus a few
cents of gas.

---

## The contract

| | |
|---|---|
| `AdmissibilityAnchor` | [`0x90c82f9711935B649a80d6dDDFc0C3E21a0D66FC`](https://basescan.org/address/0x90c82f9711935B649a80d6dDDFc0C3E21a0D66FC#code) |
| deployment | [`0xecc0349addf7f8af3451f5c03fdc77fb8c1068e025b3bb3ac97bda25d897b173`](https://basescan.org/tx/0xecc0349addf7f8af3451f5c03fdc77fb8c1068e025b3bb3ac97bda25d897b173) |
| source | verified on Basescan |
| tests | 57 passing, including 3 fuzz and 2 invariant runs |

Deployment is the floor, not the proof. What follows are executed actions.

---

## The run

### 1. The counterparty, resolved from chain rather than from its website

`ownerOf(20880)` and `getAgentWallet(20880)` on the
[IdentityRegistry](https://basescan.org/address/0x8004A169FB4a3325136EB29fA0ceB6D2e539a432) both
return `0x4069ef1afC8A9b2a29117A3740fCAB2912499fBe`, whose `tokenURI` is
`https://sibylcap.com/8004.json`.

That manifest declares a **payment wallet of `0xe3e14118238b5693c854674f7c276136a2dd311f`, which is
not the identity wallet.** The 402 response asks to be paid at that same address, and we check the
response against the manifest rather than trusting it. An agent that verified settlements against
the owner address would reject every genuine payment this counterparty has ever received.

### 2. The payment — $0.25 USDC, settled before the request

| | |
|---|---|
| tx | [`0x057a4f0a6f2c964a6b1cff66494f879383214f531bdcdc8ebba0a501115acab8`](https://basescan.org/tx/0x057a4f0a6f2c964a6b1cff66494f879383214f531bdcdc8ebba0a501115acab8) |
| from | `0x8cDec2c69be9e200A8591da3e86e822B03f7cE1f` |
| to | `0xe3E14118238b5693c854674f7c276136a2Dd311f` |
| value | 250000 USDC base units |

Agent 20880 advertises this flow under `alt.directTx`: transfer first, then present the hash. It
costs an extra transaction over signing an authorization, and it is the one we want — the evidence
is final on chain before the request is made, so it exists whether or not the service answers.

It answered: **HTTP 200**, with a full project evaluation.

### 3. The memory, and the gate re-deriving it against mainnet

```
digest   0x7181f95ca099e719616bfed715576cee326686299601822a0bbd1410fd879120
verdict  admissible
because  the claim was re-derived from onchain evidence and the evidence digest
         matches what was recorded when the memory was written
```

The first time this script ran it wrote the *identity* wallet into the claim while the payment had
gone to the *payment* wallet, and the gate answered `counterparty_mismatch` on our own evidence. The
comment explaining that is still in `scripts/live_proof.py`, because it is the check working.

### 4. ERC-8004 feedback with a real `feedbackHash`

| | |
|---|---|
| tx | [`0x89c1cdbbd1ce2e7163e4493713bf4253d9f3620f788fc8fffb3334dc622ef8bc`](https://basescan.org/tx/0x89c1cdbbd1ce2e7163e4493713bf4253d9f3620f788fc8fffb3334dc622ef8bc) |
| registry | [`0x8004BAa17C55a88189AE136b182e5fdA19dE9b63`](https://basescan.org/address/0x8004BAa17C55a88189AE136b182e5fdA19dE9b63) |
| `feedbackHash` | `0x7181f95ca099e719616bfed715576cee326686299601822a0bbd1410fd879120` |
| block | 51063300 |

That hash is the digest of the memory in step 3, which is the digest of a claim about the settlement
in step 2. The three are one object.

**Read it back and see the problem the ecosystem has.** `readFeedback(20880, us, 1)` returns
`value=100, decimals=2, tag1="admissible", tag2="settled"` — and `feedback_hash=None`, because the
getter does not return it. The commitment exists only in the `NewFeedback` event. A verifier using
the documented interface is structurally unable to check what a score was about.

Our own scan of 8,710 `NewFeedback` events over the 300,000 blocks to 51,055,657 found **92.8% commit
a zero hash**. One agent emits 7,893 of those; excluding it, 23.6% of 817. Weighted by agent, **61 of
132 (46.2%) have never received a hashed feedback**. All three numbers are in the source, because
they say different things.

### 5. The anchor

| | |
|---|---|
| tx | [`0x82098dcd5855aef87ba1ca6b590da5592c20ea73552a7896c7e60121b4c77d44`](https://basescan.org/tx/0x82098dcd5855aef87ba1ca6b590da5592c20ea73552a7896c7e60121b4c77d44) |
| root | `0x6e10316799370260a073273bba5ed79547241743ebe5471624e48cdd52ecad38` |
| leaves | 1 |
| asOf | `2026-09-09T01:05:44.524Z` |

Checked against the deployed contract, live:

```
anchorCount(0x8cDec…cE1f)                        1
verifyLatest(agent, leafOf(memory digest), [])   true
verifyLatest(agent, leafOf(a digest we never held), [])   false
```

The second line is the negative control. Without it the first proves nothing.

---

## Virtuals

| | |
|---|---|
| agent | `Admissible`, id `01a08398-e07c-7fa9-a58b-ab1de202ab35` |
| wallet | `0x7a896bfc91f1d184b6eb91980a1c6d25219e097f` |
| offering | `Admissibility verdict`, `01a083a0-86d7-7a45-9589-6799d4b01ba4`, 0.01 USDC, live in the registry |
| builder code | `bc_dx1i4jek` (ERC-8021) |

### A job, on Base mainnet

| | |
|---|---|
| job id | `77820`, protocol v2, chain 8453 |
| client | `0x7a896BFC91F1D184B6eb91980A1C6d25219E097F` (our agent) |
| provider | `0xD535a8828FFd79c12622313cb55e37d86302E0DE` (`Knos`, `answer_a_question_from_my_memory`, 0.01 USDC) |
| funding | [`0x3c0a47deed0897fcc46c72db052edd4f61be58ae8a75eba3e0015a65fc214e44`](https://basescan.org/tx/0x3c0a47deed0897fcc46c72db052edd4f61be58ae8a75eba3e0015a65fc214e44) (0.05 USDC) and [`0xdff86ad0e090f95f56b470de539d3c916aee3f614f4e0a9d193376c7b113ed5d`](https://basescan.org/tx/0xdff86ad0e090f95f56b470de539d3c916aee3f614f4e0a9d193376c7b113ed5d) (gas) |

```
acp job history --job-id 77820 --chain-id 8453
  status  open
  job.created   client 0x7a896BFC…  provider 0xD535a882…  evaluator 0x7a896BFC…
  requirement   {"question":"What did you record about this counterparty?"}
```

We hired a memory agent, which is the shape the product is about. **Whether it completes is not ours
to decide** — the provider sets the budget and delivers, and at the time of writing it has not. The
job exists on chain and the history above is reproducible with one command; we are not going to
describe a completed lifecycle we did not observe.

`workers/acp/` also reads the live Virtuals registry over the public search API and returns real
priced offerings; that read is what selected this provider. See `workers/acp/README.md` for what is
exercised and what is not — it is written to be checked, not to impress.

---

## What is recorded rather than live

`scripts/demo.py`, `bench/run.py` and the web surface run against **recorded chain fixtures by
default**, deliberately, so that a reviewer with no key, no funds and no network sees the whole
argument. Every surface says which mode it is in, and the fixture file states in its own metadata
that no transaction in it was ever mined. `MOCKS.md` draws the line precisely.

The mainnet chain above is the same code with the reader pointed at Base.
