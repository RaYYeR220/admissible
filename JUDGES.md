# Review in five minutes

A path through this repository, ordered so that each stop answers one scoring criterion and the
next stop is worth more than the last. Every command below was run while writing this file, and the
output quoted is what it printed — no number here was copied out of another document.

Nothing here needs a key, a funded wallet, or network access after the install.

```bash
git clone https://github.com/RaYYeR220/admissible.git
cd admissible
pip install -r requirements.txt
```

If `python scripts/demo.py` dies at import with
`ModuleNotFoundError: No module named 'langgraph_sdk.stream.transport.ws'`, the langgraph-sdk wheel
unpacked partially. `pip install --force-reinstall --no-deps langgraph-sdk==0.3.15` fixes it.
`python bench/run.py` and `pytest` do not import langgraph and are unaffected.

---

## 60 seconds — does the gate work

```bash
python bench/run.py
```

Half a second, no network. Read the last six lines:

```
attacks caught (exact reason)  33/33
attacks refused, wrong reason  0
attacks MISSED                 0
controls admitted              14/14
false refusals                 0

RESULT: PASS
```

Exit code 0. Four things to notice before moving on:

- **"exact reason"** is the load-bearing phrase. An attack refused for the wrong reason is scored as
  a failure, and that line reads 0. A gate can be right for a reason that will not survive the next
  attacker.
- **14 negative controls carry equal weight.** A gate that refuses everything scores 33/33 on the
  attacks alone. The exit code fails on either half.
- **The corpus is pre-registered.** `bench/corpus.py` holds the cases and their required verdicts;
  the runner imports them. It was written to be read first and blamed later.
- The header line `15 of them are refused before any chain call` is the affordability argument: most
  poisoning dies before an RPC call is spent on it.

If you stop here, the thing you have checked is that the gate reasons correctly about facts it is
handed. It says nothing about whether the agent holding the wallet listens. That is the next two
stops.

---

## 2 minutes — does the agent listen, and does memory survive a process

```bash
python scripts/demo.py
```

Five beats across three processes. Two moments matter.

**The refusal (beat 3).** An adversary agent writes three forged memories about a stranger into the
same store the buyer reads. The buyer is about to pay. Watch:

```
model proposal             PAY  [advisory, stub, saw an injection]

[REFUSE] 0xeb9caf46  ATTESTED  evidence_not_found     source job:attachment
[REFUSE] 0x966bcd01  ATTESTED  inadmissible_hearsay   source peer:reference
[REFUSE] 0xea905248  ATTESTED  counterparty_mismatch  source tool:fetch

POLICY DECISION            REFUSE

NOTE  the model proposed PAY and the agent did REFUSE. The model's output reaches
      the log and nothing else; the rail takes a Decision it did not author.
```

Read that note carefully and then read `MOCKS.md` §1. The stub model **obeys the injection on
purpose** — it is modelling a captured model. The contrast is not a language model being defeated;
it is a money path that never consults one. That property is architectural, and
`apps/tests/test_signer_isolation.py` parses `apps/agent/rails.py` and fails if the narrator, an
HTTP client, or anything a model touches ever appears in its imports.

**The cold start (beat 4).** Session 1 exits. The demo prints its PID, the file size on disk, and
spawns a **new process**:

```
SESSION 2  pid 11408
  what this process knew before it did anything (cold start):
  - FLAGGED 0x…C0FFEE (meridian-referrals) -- vouched for 0x…
  - FLAGGED 0x…bADa55 (helix-ops) -- laundered a memory into this store
  flags loaded               2
  posture loaded             ceiling $0.0000
```

The poisoner returns and sells directly. The gate **admits** its five planted WITNESSED notes —
nothing in an envelope can distinguish an observation you made from one somebody typed into your
store, and `LIMITS.md` limit 2 says so — and the agent refuses anyway, on the flag recalled from
disk. That is the memory layer doing the work the gate cannot.

Run the beats separately if you are filming:

```bash
python scripts/demo.py --session 1
python scripts/demo.py --session 2
```

---

## 3 minutes — the gate criterion, and the mainnet chain

### The deletion test, one command

```bash
python scripts/demo.py --delete-memory
```

It removes the store, keeps the chain, and replays the same attack against the same code:

```
deleted                    .demo\admissible-demo.db (585728 bytes)
chain overlay              NOT deleted -- the chain is not the agent's memory
store now exists           False

                                    WITH MEMORY         MEMORY DELETED
returning poisoner, $0.25           REFUSE on sight     PAY  --  $0.25 SETTLED
honest counterparty, $0.25          PAY, unsecured      ESCROW, $0.20 collateral demanded
forged settlement about a stranger  REFUSE              REFUSE (chain check, no memory needed)
flagged actors at first contact     2                   0
```

Four rows, and the third one is the honest one: **half the defence survives deletion**, because a
chain check needs no memory. What does not survive is the flag, the history and the posture. The
attack succeeds, $0.25 leaves the wallet to an address the agent had already caught once, and the
honest counterparty's earned payment collapses into a collateral demand — the settlements are still
on chain and nothing remembers to cite them.

The byte count varies run to run; the four rows do not.

Keeping the chain overlay out of the store is what makes this measurement mean anything. If deleting
the agent's memory also deleted the world, the test would be flattering itself.

### The mainnet chain

Open `PROOF.md` and click through. Every one of these was re-read from Base while writing this file:
receipt fetched, `status` checked, `Transfer` logs decoded. All returned `status = 1`.

| what | where to look |
|---|---|
| the contract, verified source | [`0x90c82f97…1a0D66FC`](https://basescan.org/address/0x90c82f9711935B649a80d6dDDFc0C3E21a0D66FC#code) — 6,538 bytes deployed |
| the x402 payment | [`0x057a4f0a…115acab8`](https://basescan.org/tx/0x057a4f0a6f2c964a6b1cff66494f879383214f531bdcdc8ebba0a501115acab8) — 250,000 USDC base units to agent 20880's **payment** wallet, not its identity wallet |
| the feedback with a real hash | [`0x89c1cdbb…622ef8bc`](https://basescan.org/tx/0x89c1cdbbd1ce2e7163e4493713bf4253d9f3620f788fc8fffb3334dc622ef8bc) — `feedbackHash` = the digest of the memory about that payment |
| the anchor | [`0x82098dcd…b4c77d44`](https://basescan.org/tx/0x82098dcd5855aef87ba1ca6b590da5592c20ea73552a7896c7e60121b4c77d44) — root `0x6e103167…52ecad38`, 1 leaf |

The check worth doing yourself is the negative control, because without it the positive one proves
nothing:

```
verifyLatest(agent, leafOf(memory digest), [])             true
verifyLatest(agent, leafOf(a digest we never held), [])    false
```

`leafCount` is 1, so the root *is* the leaf and the inclusion proof is the empty array. The
multi-leaf paths are covered by 57 Foundry tests, not by this transaction. `CLAIMS.md` says so under
NOT-CLAIMED.

---

## 5 minutes — the rest of the evidence, and the limits

```bash
pytest                    # 249 passed, 18 deselected, ~46s
python scripts/eval.py    # the end-to-end scorecard, ~10s
```

`pytest` excludes the `live` and `anvil` markers by default, which is why 18 are deselected: they
need a network or a local node. The 249 that run need neither.

`scripts/eval.py` answers the question `bench/run.py` cannot — a correct verdict that does not
change the action is worth nothing. Three layers over the same corpus, imported rather than
restated:

```
LAYER 2  MONEY
  verdicts agreeing with layer 1     47/47
  attacks that bought no credit      33/33
  controls the gate damaged          0/14
  credulous agent hands over         $11,867.52
  this agent hands over              $0.65
  ...of which bought by a memory     $0.00

LAYER 3  AGENT
  cases meeting the safety property  47/47
  identical action to layer 2        46/47
```

`$11,867.52` is a counterfactual, not a loss: it is the sum of the per-case column the run prints
above the headline, produced by the *same* policy and the *same* rail with only the gate swapped for
one that admits everything. `$0.65` is thirteen escrow cases at the documented `$0.05` stranger
ceiling. The `46/47` is disclosed by the run itself — one attack escrows where the policy layer
refused, and the run marks it `[still bought nothing]`.

Then read, in this order:

1. **`LIMITS.md`** — twenty red-team findings against the project's own gate, nineteen fixed and one
   open, plus eight structural limits. It leads with the failures on purpose. The finding worth
   reading in full is limit 1: reputation is still purchasable, the price went from $0.0027 to face
   value, and the obvious patch was refused on the record because it closes nothing while destroying
   signal from honest repeat customers.
2. **`CLAIMS.md`** — every public statement tagged `REPRODUCIBLE` / `VERIFIED-LIVE` / `MODELED` /
   `NOT-CLAIMED`, and a Corrections section listing where the other documents in this repository are
   wrong or stale.
3. **`MOCKS.md`** — the real-versus-simulated line, component by component.

---

## The gate criterion, answered directly

### Where memory is written and read

Every line number below was re-checked against the current tree.

**Written.** Every write goes through Sibyl Memory. `AdmissibleStore.remember` calls `set_entity`
and journals the write in the same breath.

| what | where |
|---|---|
| write a memory | [`store.py:184`](packages/admissible/src/admissible/store.py#L184) — `self._client.set_entity(category, name, envelope.to_body(), status=status)` |
| journal every write | [`store.py:477`](packages/admissible/src/admissible/store.py#L477) — `self._client.write_event(...)` |
| non-destructive supersession | [`store.py:235-236`](packages/admissible/src/admissible/store.py#L235) — `archive_entity(...)` then `set_entity(...)`; the relations are captured at `:228` and rehomed at `:237` |
| the FLAGGED tier | [`flagged.py:150`](packages/admissible/src/admissible/flagged.py#L150) — `INSERT INTO flagged_actors` |
| the relations graph | [`relations.py:114`](packages/admissible/src/admissible/relations.py#L114) — `INSERT INTO entity_relations` |
| reflection, written back | [`posture.py:233`](apps/agent/posture.py#L233) — `store_posture`, computed at [`posture.py:163`](apps/agent/posture.py#L163) |

**Read.**

| what | where |
|---|---|
| read a memory | [`store.py:267`](packages/admissible/src/admissible/store.py#L267) — `self._client.get_entity(category, name)` |
| recall many | [`store.py:288`](packages/admissible/src/admissible/store.py#L288) — `self._client.list_entities(...)` |
| search, through Sibyl's abstention gate | [`store.py:326`](packages/admissible/src/admissible/store.py#L326) → `multi_record_search` at `:336`. The ungated FTS5 primitive is [`store.py:344`](packages/admissible/src/admissible/store.py#L344) `unsafe_search`, named to be noticed in review |
| replay the journal | [`store.py:392`](packages/admissible/src/admissible/store.py#L392) — `self._client.read_events(...)` |
| time-travel | [`timeline.py:91`](packages/admissible/src/admissible/timeline.py#L91) `history`, [`:96`](packages/admissible/src/admissible/timeline.py#L96) `as_of`, [`:130`](packages/admissible/src/admissible/timeline.py#L130) `valid_at` |
| consolidation and summarization | [`consolidate.py:47`](packages/admissible/src/admissible/consolidate.py#L47) `consolidate`, [`:147`](packages/admissible/src/admissible/consolidate.py#L147) `summarize` — arithmetic, no model in the loop |
| reflection, loaded next run | [`posture.py:151`](apps/agent/posture.py#L151) — `load_posture` |

**And the decision path reads nothing else.**
[`gate.py:264`](packages/admissible/src/admissible/gate.py#L264) `AdmissionGate.admit` (the class
opens at `gate.py:213`) and
[`policy.py:161`](packages/admissible/src/admissible/policy.py#L161) `TrustPolicy.decide` take
recalled memory and the chain, and nothing else. The gate reads provenance, never prose.

> The README's version of this table used to cite `gate.py:211` for `admit`, which is a blank line.
> It now cites 264, and 213 for the class. Every other reference in it was re-checked against the
> current tree and is correct. Recorded in `CLAIMS.md` under Corrections.

**Two tables Sibyl Memory declares and its own client never touches.** Verified against the
installed `sibyl_memory_client 0.8.1`: zero references to `flagged_actors` or `entity_relations` in
`client.py` or `storage.py`. The only mentions anywhere in the package are three lines of `lint.py`,
one of which — `lint.py:361` — selects an `identifier` column that `schema.sql` does not declare,
inside a bare `except Exception: pass`. The `flagged-actors-fresh` check has never been able to
fire. Admissible writes both tables through Sibyl's own connection, tenant scoping and timestamp
format.

To be precise about what that does and does not mean: the check still cannot fire, because the bug
is in the query rather than in the absence of rows. Run against the demo store, which has two
`flagged_actors` rows, that `SELECT` still raises `no such column: identifier`.

### What breaks when memory is deleted

One command:

```bash
python scripts/demo.py --delete-memory
```

The forged memory is admitted, the agent pays a counterparty that never existed, and the honest
counterparty's earned payment becomes a collateral demand. Without the memory layer there is no
provenance to check, no history to contradict, no flag to recall, and nothing for the gate to gate.
The full comparison table is quoted in the 3-minute section above.

---

## If you have one more minute

The three things a reviewer is most likely to want to check for themselves, each independent of
anything this repository asserts:

```bash
# 1. the counterparty is a real registered agent with two different wallets
python -c "from admissible.chain import BaseChain; c=BaseChain(rpc_url='https://mainnet.base.org', chain_id=8453); a=c.resolve_agent(20880); print(a.owner, a.wallet, a.token_uri)"

# 2. the feedback hash exists, and only in the event log
python -c "from admissible.chain import BaseChain; c=BaseChain(rpc_url='https://mainnet.base.org', chain_id=8453); print(c.read_feedback_hash('0x8004BAa17C55a88189AE136b182e5fdA19dE9b63', 20880, 1, 8453))"

# 3. the Virtuals agent is live in the registry, no credentials
curl -s "https://api.acp.virtuals.io/agents/wallet/0x7a896BFC91F1D184B6eb91980A1C6d25219E097F"
```

The second one is the interesting one. Ask for feedback index 0 or 2 instead of 1 and the reader
raises rather than returning:

```
ChainUnreachable: searched 639936 blocks back from … without finding feedback #0
for agent 20880; the record may exist further back, so this is unknown rather than absent
```

That is `LIMITS.md` structural limit 3 firing in the open. Unknown is not yes, and the gate would
rather refuse than guess.
