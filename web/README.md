# The Admissible web surface

Two pages over the real core. A landing that makes one claim, and **the record**,
where the gate's enforcement is visible memory by memory.

No keys, no funds, no network.

## Run it

```bash
pip install fastapi uvicorn
pip install -e packages/admissible      # optional: the server also runs from source
python web/seed.py
uvicorn web.server:app --port 8000
```

Then open <http://127.0.0.1:8000>. The record is at `/app`.

`web/seed.py` rebuilds the demo store from scratch every time. Stop the server
first — SQLite holds the file open on Windows — or pass `--keep` to write into
the store that is already there.

```bash
python web/seed.py --db /tmp/demo.db --json    # somewhere else, machine-readable
```

## What is real and what is recorded

| | |
|---|---|
| The gate, the trust policy, the tiers, the verdicts | **real** — `packages/admissible`, unmodified, called per request |
| The FLAGGED tier, the relations graph, the bi-temporal replay, the dossier fold, the Merkle root | **real** — Sibyl Memory's own tables, through the package |
| The chain | **recorded** — `web/fixtures/base-mainnet.json`, synthetic, never mined |
| The operating history | **seeded** — one month of memories written in one pass by `web/seed.py` |

Every surface prints `offline fixtures` where a status light would go, and every
evidence link is tagged `fixture` beside the Basescan URL. Set `BASE_RPC_URL` and
the reader becomes `admissible.chain.BaseChain`, the chip turns green, and the
label changes to `base mainnet`. Nothing in between: the surface would rather
show a visible gap than an uncheckable claim.

Two things the seed fabricates, said plainly in `web/seed.py`'s own docstring:

- **The chain.** Real, public, checksummed addresses; the record shapes a Base
  USDC `Transfer` decodes to; @sibylcap's real published x402 price tiers. None
  of those transactions was ever mined.
- **The clock.** An agent running for a month has month-old memories; a store
  built in one pass does not. Seeded history moves `observed_at` *and* its
  journal entry together, because they are the same fiction. The alternative was
  to widen the gate's backdating tolerance until the seed fitted through it,
  which would have disarmed the check the demo shows catching an injected
  memory. The gate runs at its shipped default and that memory is caught.

Everything else — every verdict, every credit line, every refusal — is computed
by `admissible` at request time. No outcome is stored in the seed.

## The API

| endpoint | what it answers |
|---|---|
| `GET /api/counterparties` | every counterparty, its dossier, tier histogram, memory count and standing |
| `GET /api/counterparty/{address}` | every memory about it, each with its verdict, deciding fields, explanation and evidence links |
| `POST /api/decide` | `{counterparty, requested_usd, as_of?}` → the real `Decision`, plus the full trace |
| `GET /api/flags` | the FLAGGED tier, and what each flag reaches through the graph |
| `GET /api/graph` | the relations graph with contamination from every flagged actor |
| `GET /api/timeline/{category}/{name}?as_of=` | every recoverable version, the one held at `as_of`, and the versions that did not survive |
| `GET /api/anchor` | the Merkle root over what the gate admits right now, its leaf count and watermark |
| `GET /api/stream` | the same decision as Server-Sent Events, one frame per memory |
| `GET /api/proof` | the executed Base mainnet run, with the digest **recomputed** rather than transcribed |
| `GET /api/sourcing` | our agent in the Virtuals registry, a live registry read, and the ACP job we hired |
| `GET /api/scorecard` | the offline adversarial corpus, scored by running `bench/run.py` |
| `GET /api/site` | the rule, the chain label, and the off-site links (`null` when unpublished) |
| `GET /LIMITS.md` | the limits file, served from the repository root |

`/api/stream` paces its frames so the sequence is watchable; every frame says
`paced: true`, and the gate itself takes microseconds. `ADMISSIBLE_TRACE_DELAY_MS=0`
turns the pacing off.

The server is read-only. It opens the store, calls the package and renders the
answer; nothing on either page writes a memory, raises a flag or moves money.

## The two panels that are not the demo store

The deck, the trace and the graph read the seeded store against recorded
fixtures, and say `offline fixtures` while they do it. Two panels do not, and
they are labelled separately so neither borrows the other's credibility.

**Base mainnet (`/api/proof`, section 07 on the record, section 04 on the
landing).** The executed run from `PROOF.md`: $0.25 USDC settled to ERC-8004
agent #20880, the memory written about it, that digest committed as a
`feedbackHash`, and the same digest anchored under a Merkle root in a verified
contract. The digest is **not copied out of the file** — `web/fixtures/mainnet-proof.json`
carries the *claim*, and the server runs `keccak256` over its canonical form with
the same function the gate uses, hashes that into a Merkle leaf, builds the
one-leaf tree, and reports whether each result equals what was published. If the
fixture ever drifts from what was executed, the panel says `false` in public
instead of quietly agreeing with itself. The negative control — a well-formed
digest this agent never held, which fails against the same root — is rendered
beside it, because without it the green line proves nothing.

**Counterparty sourcing (`/api/sourcing`, section 08).** Prefers the ACP bridge
in `workers/acp/` on `:8787` and falls back to `web/fixtures/virtuals-acp.json`,
naming which it used. It reports *which registry answered*: the bridge can be
pointed at the mainnet registry or the dev one, and a dev-registry read presented
as a mainnet read would be the exact dishonesty this product argues against. When
the live read is not mainnet, the recorded mainnet read is carried beside it
rather than in place of it.

The ACP job is rendered at the status it is actually in. Job `77820` on chain
8453 is **open**: the provider sets the budget and delivers, and at the time of
writing it has not. The lifecycle shows one step done, one waiting and three
pending. Nothing draws a completed job we did not observe.

`pnpm serve` inside `workers/acp/` starts the bridge; without it the panel
degrades to the recorded values with the label `acp bridge offline · recorded`,
never to a spinner or a blank.

## Configuration

Names only — see `.env.example`. All optional; with none of them set the surface
runs against the fixtures and says so.

| variable | effect |
|---|---|
| `ADMISSIBLE_DB` | store to read (default `web/.data/admissible-web.db`) |
| `BASE_RPC_URL` | present ⇒ live reads against Base mainnet; absent ⇒ recorded fixtures |
| `ADMISSIBLE_CHAIN_FIXTURE` | a different recorded chain file |
| `ADMISSIBLE_SELF_ADDRESS` | the wallet the agent pays from; without it the gate cannot tell a settlement *to us* from a settlement between two addresses the counterparty owns |
| `ADMISSIBLE_ANCHOR_FILE` | a deployment artefact for the published anchor |
| `ADMISSIBLE_TRACE_DELAY_MS` | pacing of the SSE trace, in milliseconds |
| `ACP_WORKER_URL` | the ACP bridge (default `http://127.0.0.1:8787`) |
| `ACP_WORKER_TIMEOUT` | seconds to wait for it before falling back to recorded values |
| `ADMISSIBLE_REPO_URL`, `ADMISSIBLE_VIDEO_URL` | landing links; unset renders as unavailable rather than as a guess |

## The demo, in ninety seconds

1. **brightwater-labs** is slotted by default. Twelve memories, none admissible:
   a borrowed receipt, a transaction that does not exist, a self-dealt transfer,
   a registry the actor deployed itself, a review it wrote about itself, an
   unpaid review, a hash that commits a different claim, a memory injected now
   and dressed up as six weeks old, a claim from an actor already flagged, a body
   that is not an envelope, and two pieces of ordinary hearsay — one of which is
   a prompt injection the gate never reads. The shutter slams, the cartridge
   ejects, `DENIED` appears with the failing clause.
2. **sibylcap** pays. Four memories re-derive to Base, and the credit line is the
   sum of what settled — $1.58, not the $1.77 the file claims.
3. **meridian-referrals** escrows. Its history is entirely first-hand, which is
   discounted and capped, so $3.00 splits into $2.50 released and $0.50 held.
4. Drag the **as-of** scrubber back four days: meridian pays, because the
   settlement whose validity window has since closed was still open then. Switch
   to sibylcap and drag back past the correction: `sibylcap-0008` reads *late*
   again, which is what the agent believed at the time.
5. The **FLAGGED registry** carries an actor caught in session nine, and the
   **vouching graph** shows what that flag reaches.

## Screenshots

`web/screenshots/` — both surfaces at 1440×900 and 390×844, plus full-page
captures. Regenerate them with any headless browser; nothing on either page
depends on a build step.

## Notes

- Vanilla HTML, CSS and hand-authored SVG. No framework, no bundler, no build.
- Fonts come from the same two CDNs as the design prototype. There are no other
  external requests: no analytics, no trackers, no third-party scripts.
- Responsive at 1440×900 and 390×844, with no horizontal page scroll at either.
- The theme control (daylight ⇄ desk lamp) persists in `localStorage`.
- `prefers-reduced-motion` is respected: the shutter still changes state, the
  cartridge still ejects, neither animates.
