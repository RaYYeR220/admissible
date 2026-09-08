# What this gate does not protect against

The rule the gate enforces is one sentence:

> A memory may not justify moving more money than can be found on chain, moved
> to the party it vouches for, by somebody who is not that party.

That sentence is narrower than the one this project started with — *"a memory
may not justify moving money unless it can be re-derived from evidence somebody
other than its author can check"* — and it is narrower on purpose, because the
original overclaimed in two places. "Re-derived from evidence" said nothing
about **how much**, and a memory that re-derived perfectly could still assert
any number; the gate now takes the amount from the chain and never from the
claim. And "somebody other than its author" was simply not enforced: the author
of an ERC-8004 feedback record was free to be the agent it praised. Both are
fixed, and the sentence above is what the code now does.

One exception, stated in the rule's own terms: the agent's **own first-hand
notes** (`WITNESSED`) carry no chain evidence at all and are admitted on the
strength of a field in the memory. They are capped at **$5.00 of credit across
an entire decision**, precisely because they are the one thing here that nothing
independently checks.

This file is about the distance between that sentence and what the code
actually does. It is written for someone trying to decide whether to trust an
agent that runs this, so it leads with the failures.

Two framing facts before the list.

**The corpus was not adversarial enough.** The gate scored 12/12 on twelve
attacks and 5/5 on five controls before this pass. The same person wrote the
attacks and the defence, which is why that number meant nothing. A dedicated
attempt to break it afterwards found **twenty distinct problems**:

- **12** made the gate return `admissible` for a memory it should have refused;
- **3** let an attacker choose a softer refusal than the one they had earned;
- **2** inflated the credit behind memories that were correctly admitted;
- **3** crashed the payment path, or produced a digest no other reader can
  re-derive.

Fifteen of the twenty changed what the agent does with money. Nineteen are
fixed; one is not. The corpus is now 47 cases: 33 attacks over 18 families and
14 negative controls.

**Integrity is not authority, and the gate used to confuse them.** Re-deriving
that a memory says what it was sealed saying, and that the chain agrees the
cited event happened, establishes nothing about whether the party who created
that evidence had any standing to vouch for anybody. That was the worst hole in
the design and it is now closed for the path where it mattered — see
"reputation you wrote yourself" below. What survives it is an economic limit
rather than a verification one, and it is stated with a price attached.

---

## Found and fixed

Each of these admitted a memory, or downgraded a refusal, on the code as it
stood. Each now has a permanent case in `bench/corpus.py`.

| # | Attack | What it bought | Verdict now |
|---|---|---|---|
| 1 | **WITNESSED laundering.** `tier: WITNESSED, source: peer:reference` was admitted with no chain call, no evidence and no actor. Two strings the memory chose for itself. | Any amount of credit at zero cost. A note claiming `amount_usd: 1000000` produced a $250,000 credit line; `Infinity` produced an unbounded one and paid any request. | `inadmissible_hearsay` |
| 2 | **Counterfeit token.** The gate read `SettlementFacts.token` never. A self-deployed six-decimal ERC-20, minted free, sent to yourself, produced a "$0.25 settlement". | Arbitrary reputation for the price of gas. | `evidence_not_found` |
| 3 | **Self-dealing.** The counterparty had to be *either* the sender or the recipient. Sending USDC from one address you own to another satisfied that. | A real, verifiable track record with the money still in your pocket. | `counterparty_mismatch` |
| 4 | **Foreign chain.** `chain_id` was passed through unchecked, and `chain_id or 0` invented chain zero when it was absent. | Base Sepolia USDC comes from a faucet. Free mainnet reputation. | `evidence_not_found` |
| 5 | **Anonymous receipt.** The counterparty check was skipped when the claim carried no `counterparty`, or an empty one. | Any real receipt vouched for whoever the memory happened to be filed under. | `counterparty_mismatch` |
| 6 | **Unpriced settlement.** The amount check was skipped when the claim carried no `amount_usd`. | A 0.000001 USDC dust transfer proved an unstated amount. | `amount_mismatch` |
| 7 | **Reverted transaction.** A reverted transaction comes back from the reader as a populated record with `status=0`, not as `None`. The gate only asked whether the record was `None`. | A transaction that moved nothing read as a payment. | `evidence_not_found` |
| 8 | **Own registry.** `evidence.registry` was whatever the memory said. Deploy a registry, write your own review, commit the hash of your own claim. The digest matched perfectly. | Full ATTESTED credit for a self-written review. | `evidence_not_found` |
| 8b | **Reputation you wrote yourself.** Pinning the registry did not close #8, it only moved it: ERC-8004 registries are *permissionless to write*, so the attacker writes the same self-review into the **canonical** registry. Hash matches, registry allowlisted, admitted at full weight. Nothing asked who the author was. | Any credit line, for one transaction. The published Base measurement prices this forgery at **$0.0027** and finds **90.6%** of Base reviewers Sybil-flagged. | Author resolved from the `NewFeedback` log; `counterparty_mismatch` when the author is the subject, `inadmissible_hearsay` when no payment backs it |
| 9 | **Unreadable clock.** The backdating check computed a drift and returned "fine" when the drift was `None`. Writing `observed_at: "held since March"` skipped the check entirely. | A fabricated track record with no journal support. | `malformed` |
| 10 | **Respelled expiry.** Validity windows were compared as strings. `20260201T000000Z` is valid ISO-8601 for 1 February and sorts above `2026-09-08...` because `'0' > '-'`. | A window that closed seven months ago read as open. | `expired` |
| 11 | **Verdict masking.** `EXPIRED` and `SUPERSEDED` are not in the forgery set, so the policy escrows past them. Adding a closed `valid_to` to a forged memory turned `evidence_not_found` into `expired`. In a decision with genuine history beside it, that turned **refuse into pay** and suppressed the flag on the forger. | Unlimited forgery attempts at no risk of being flagged. | `evidence_not_found` |
| 12 | **Masking, one step earlier.** Same trick against `BACKDATED`, which ran after the validity check. | As above. | `backdated` |
| 13 | **Credit inflation by repetition.** Weight was computed per memory. One genuine $0.25 settlement, stored under four hundred names, was $100 of credit. Because de-duplication would have keyed on the digest, adding one space to the claim made four hundred *distinct* memories citing the same transaction. | 400x leverage on one real payment, no forgery involved. | Credit is attributed to the evidence, once: `$0.25` |
| 14 | **Claim/verify divergence.** The gate compared `amount_usd` against the chain in base units; the policy then weighed `float(claim["amount_usd"])`. Two different numbers, one of them attacker-written. | The lever behind #6 and #1. | The policy weighs the gate's verified amount |
| 15 | **Digest collisions.** `json.dumps` coerces non-string keys, so `{1: "a"}` and `{"1": "a"}` hashed identically, as did `{True: "a"}` and `{"true": "a"}`. NFC and NFD spellings of the same text hashed differently. `NaN` and `Infinity` serialised to tokens no conforming JSON reader accepts. | Two different claims under one digest; and digests nobody outside CPython can re-derive, which is the whole premise. | `malformed`, and text is NFC-normalised before hashing |
| 16 | **`admit()` raised.** Its docstring said "Never raises on bad input". It raised `KeyError` on a missing `tier`, `TypeError` on a provenance that was a list, `AttributeError` on an evidence block that was a list, `UnicodeEncodeError` on a lone surrogate, `ValueError` on `amount_usd: "free"`, and anything the RPC client threw for an attacker-chosen `tx_hash`. | An exception on the payment path is not a refusal. It is whatever the caller's `except` clause decides, which nobody wrote down. | `malformed` / `chain_unreachable` |

Two more were closed without a corpus case because they are properties of the
plumbing rather than verdicts:

- **Journal flooding disabled the backdating check.** `StoreHistory.recorded_at`
  reads the journal with `limit=100000`, which Sibyl clamps to `MAX_LIMIT =
  10_000`. Write a backdated memory, then emit ten thousand cheap ones, and your
  own journal record falls out of the window; `recorded_at` returns `None` and
  the check used to skip itself. It now falls back to comparing against the
  gate's own clock, which costs an honest memory nothing — an agent records what
  it sees as it sees it — and still makes a memory claiming six months of age
  explain the six months.
- **`Decision.to_dict()` crashed** on a memory refused for having an
  uncanonicalisable claim, because building the audit record recomputed the
  digest that was the reason for the refusal. The audit path is the last thing
  that should fall over when an attack lands.

---

## Found and not fixed

### Supersession names bytes, and it wants to name a subject

`_check_superseded` asks the history for `superseding_digest(env.digest)`. A
memory that was retracted can be resurrected by re-writing the same claim with
any no-op change — one space in a note field, one extra key. The digest is
different, so the lookup misses.

Reproduced: a retracted ATTESTED settlement memory plus `{"n": " "}` returns
`admissible`.

Why it is not fixed: the obvious patch is to also refuse anything citing the
same `(chain_id, tx_hash)` as a superseded record. That breaks the ordinary
correction, where the replacement memory cites the *same* transaction and says
something different about it — which is most supersessions. Closing this
properly needs a notion of claim identity that is not the digest, and inventing
one under time pressure would be worse than naming the gap.

What blunts it: the replacement still has to pass every evidence check, so it
can only restore credit that a real, correctly-bound settlement supports. What
it evades is the *interpretive* half of a retraction — "that settlement did not
mean what we thought" — not the evidence half. And credit is now attributed to
the transaction, so a resurrected copy sitting beside the original adds nothing.

### A crafted refusal is not treated as a forgery attempt

`FORGERY_CODES` — the five verdicts that make the policy refuse outright and
name the actor — does not include `MALFORMED` or `INADMISSIBLE_HEARSAY`. An
attacker who writes a deliberately malformed memory is refused but not flagged,
and can keep writing them.

Not fixed on purpose: a genuinely malformed row is also what a schema change or
an ordinary bug looks like, and flagging an actor for it would be a false
accusation with durable consequences. The trade is a real one and it is made in
favour of not flagging innocents.

### Amounts are compared at USDC's precision, and only there

`_to_base_units` rounds half-to-even at six decimals, so a claim of
`0.2500001` matches a settlement of `250000` base units. The difference is
one ten-millionth of a dollar, which USDC cannot represent. Rounding rather than
rejecting is deliberate: `0.1 + 0.2` is `0.30000000000000004` in any language
with IEEE floats, and refusing that would break every honest writer. If you need
exactness below the token's own precision, this is not the gate for it.

### The caches are only as fresh as the caller

`StoreHistory` memoises the supersession map and the journal timestamps until
someone calls `invalidate()`. Within a decision that is the point. Across
decisions, a supersession written by another process is invisible to a
long-lived gate until it is invalidated. `build_gate` returns the history object
specifically so the caller can do this; nothing forces them to. The FLAGGED
lookup is deliberately *not* cached, so flagging an actor mid-decision does take
effect on the next verdict.

### A gate built without `self_address` cannot see self-dealing

`self_address` defaults to `None`, and with it unset the party check degrades to
"the counterparty was one of the two parties" — which is exactly what attack #3
satisfies. `build_gate` names the parameter explicitly so omitting it looks like
a decision, but the default is still the weaker one, for compatibility with
existing callers. If you deploy this without setting it, you have attack #3.

---

## Structural limits that no amount of code in this repository closes

### 1. Reputation can still be bought, but now only at face value

This is the most serious thing still wrong with the design. It is what is left
after closing the authority gap, and it is an economic limit rather than a
verification one.

**What the gate now requires of a reputation record**, in order:

1. It lives in the canonical ERC-8004 registry, on the accepted chain.
2. Its committed `feedbackHash` equals the keccak of this exact claim.
3. The claim's `counterparty` is one of the addresses that *is* the agent under
   review: its owner, its registered wallet, or the payment wallets its
   registration declares. Those differ in practice -- agent 20880's identity
   wallet is `0x4069ef1a...` and its payment wallet is `0xe3e14118...` -- so
   this is a set membership test and never an equality.
4. The record's author, the `clientAddress` topic on the `NewFeedback` log, is
   **not** one of those addresses.
5. That author had a **settled USDC transfer to one of those addresses, at or
   before the block the review was written**. Payment first, then the review it
   justifies.
6. Credit equals **what was settled**, never what the claim asserts.

**What that costs an attacker now.** Before: one transaction, $0.0027, for a
credit line of any size. After: to obtain $X of credit, an address that is not
the agent must actually send $X of USDC to the agent, on chain, before writing
the review.

**What survives it.** The attacker controls both addresses, so the money comes
back. Measured against this code: one attacker address, twenty rounds of
sending $5,000 to their own agent, writing a review, and taking the $5,000
back, produces **$100,000 of credit from $5,000 of working capital** -- about
three transactions per round, each costing cents on Base. The capital is
committed, not spent.

**Why that is not fixed.** The obvious patch is to count one reviewer once, or
to credit only their largest single payment. It closes nothing: the attacker
spreads the same $5,000 across twenty funded addresses instead of twenty
rounds, arrives at the same $100,000, and pays for nineteen extra address
fundings. It *would* cost an honest repeat customer real signal, collapsing
forty genuine payments into one. So it buys nothing and charges for it. This is
Sybil resistance, which this design does not have (limit 8), and dressing a
de-duplication rule up as Sybil resistance is exactly the kind of fix that
looks closed and is not.

The honest summary: forging a reputation went from **$0.0027 for any amount**
to **you must move the money, it must land on the agent, and the credit is
capped at what moved**. That is a large change. It is not the same as
impossible, and an attacker with capital and patience still buys history.

### 2. WITNESSED rests on trusting our own ingest path

WITNESSED requires `source == "agent:self"` and, when configured,
`actor_address == self_address`. Both are fields **in the memory**. They are
only meaningful because our own ingest path is the only thing that writes them,
and nothing in `gate.py` enforces that. If anything else can write a row with
`source: agent:self`, the tier is free again.

This is the one remaining place where the gate admits on the strength of a
string the memory carries about itself. The credit cap --
`WITNESSED_CEILING_USD = $5.00` across an entire decision, shared between every
witnessed memory in it -- exists because that assumption cannot be verified from
inside the gate, so the blast radius is bounded instead of the assumption being
defended.

### 3. A payment older than the search window reads as no payment at all

Finding the settlement behind a review is a backwards `eth_getLogs` scan from
the review's block, bounded by `BaseChain.max_scan_chunks`: 64 windows of ~10k
blocks, roughly 640,000 blocks, about a fortnight of Base. Running out of budget
raises `ChainUnreachable`, which the gate turns into a refusal -- correct, and it
means **a genuine review written more than about two weeks after the payment it
refers to is refused rather than admitted**.

For the x402 flow this is generous: you pay, then you review, minutes later. For
a reputation record written long after the relationship it describes it is a
false refusal, and the remedies are a `from_block` hint or a larger scan budget,
both of which cost RPC calls. It fails closed, which is the right direction, but
it fails.

### 4. A true memory can be an irrelevant one

Nothing here reasons about relevance. A memory whose evidence is real, whose
counterparty is correctly bound, whose amount matches the chain exactly, and
whose claim is entirely true can still be the wrong basis for this decision:
a counterparty who reliably delivered forty $0.25 lookups has an admissible
$10 of history, and none of it says anything about whether they will deliver a
$10 job. The gate turns evidence into credit by adding up dollars settled. That
is a policy choice with no verification behind it, and an attacker who
establishes cheap genuine history is not attacking the gate at all — they are
using it as designed.

### 5. Whoever controls the RPC endpoint controls the verdict

The gate's entire notion of "somebody else can check it" is one `ChainReader`.
An endpoint that lies — reporting a transfer that did not happen, or the wrong
recipient, or the wrong token — produces admissible memories, and there is no
second source to disagree with it. The gate fails closed when the endpoint is
*unreachable*, which is the easy half; it has no defence at all against one
that answers confidently and wrongly. Anyone relying on this should be pointing
it at an endpoint they run, or at more than one.

### 6. Write access to the SQLite file is game over for half the checks

Three of the checks read the store rather than the chain:

- **SUPERSEDED** reads the journal. An attacker who can write to the journal can
  fabricate a supersession of a legitimate memory, or delete the one covering
  their own.
- **BACKDATED** compares the memory's clock against the journal's. An attacker
  who can write journal rows can supply whatever "our clock" said.
- **FLAGGED_SOURCE** reads `flagged_actors`. An attacker who can write there can
  unflag themselves, or flag a competitor.

The journal is append-only by convention, not by the database. Nothing in
SQLite stops an `UPDATE`. The evidence checks survive this — they re-read the
chain — but a store an attacker can write to reduces the gate to its chain
checks alone.

### 7. The digest is only canonical among readers that agree with us

`canonical()` now rejects non-string keys, non-finite numbers and unencodable
text, and normalises text to NFC, so two agents running this code agree. That is
not the same as agreeing with a Solidity verifier, or with a JSON library that
serialises `1.0` as `1`, or with one that keeps the first of two duplicate keys
where Python keeps the last. `digest_of({"a": 1})` and `digest_of({"a": 1.0})`
are different digests for numbers that are equal, and any round-trip through a
library that normalises number formatting will produce a `digest_mismatch` on an
honest memory. Anchoring a digest onchain commits you to this exact
serialisation.

### 8. Everything here is about one memory at a time

The gate judges memories individually. It has nothing to say about a set of
individually-admissible memories that is collectively a lie: forty genuine
$0.25 settlements from forty addresses one attacker controls, each one perfectly
re-derivable, none of them evidence of anything except that the attacker has
gas and a little capital. De-duplication counts one settlement once and the
payment rule makes each one cost real money, so the crowd is no longer free --
but nothing here can tell that forty payers share an owner.

Sybil resistance is not a property this design has. It is the root of limit 1,
it is why the payment rule raises a price rather than closing a door, and the
stranger ceiling ($0.05) is the only thing standing between the agent and a
large enough crowd of strangers.

---

## What the scorecard actually claims

`python bench/run.py` prints 33/33 attacks caught with the exact expected
verdict and 14/14 controls admitted. That claim is: *against these 33
mechanisms, this gate returns this verdict, offline, reproducibly, and does not
refuse these 14 sound memories while doing it.*

It is not a claim that 33 is the number of ways in. Twenty-one of the 33 were
found by one person attacking the code after it already scored 100%, and five of
those came from a second pass over a gate that had just been hardened against
the first. The honest prior is that the next person to look will find more.

The scorecard is also offline. It proves the gate reasons correctly about facts
it is handed; it proves nothing about whether the chain reader hands it the
right ones. That is limit 5, and no amount of green here touches it.
