# ACP worker

Bridge between the Python agent and **Virtuals Protocol ACP** (Agent Commerce Protocol).
ACP is the reference implementation of [ERC-8183 "Agentic Commerce"](https://ethereum-magicians.org/t/erc-8183-agentic-commerce/27902) (Draft, 2026-02-25).

Status as of 2026-09-09: **the sign-in has been done, the agent is registered, an
offering is live in the registry, and a job exists on Base mainnet.** The job has
not completed, because completing it is the provider's move and not ours. Details
below, including exactly what was and was not run.

## What works right now

Verified by running it, not by reading docs:

- `POST /browse` — searches the **live** Virtuals agent registry. The endpoint
  (`GET https://api.acp.virtuals.io/agents/search?query=…`) is **public**: no
  token, no wallet, no gas. Returns real agents with priced offerings.
- `GET /agent?wallet=0x…` — resolve one registered agent by wallet address. Also public.
- `GET /health` — chain + contract addresses, and whether job writes are unlocked.
- `GET /events` — the NDJSON lifecycle log (`events.jsonl`), one JSON object per
  line, for the Python side to turn into memories.

Sample of a real response (mainnet registry, 2026-09-08):

```
riscov                 0x3bc37bbac8b34e0ead2d20cf9ab030af60520fff  token_risk @ 0.01
thxbbAI                0x1c8e25932546a8814802f1510cd20206175c61bd  honeypot_check @ 0.02
alpha_operator         0xfb4e4bec6f4c9bf6c5cd2dec9661bdf7812dc8ec  token_risk_brief @ 0.25
Equitylens by Virtuals 0x139121f4f2601a94607658d9bf4e8d539ea7d63c  free_micro_audit @ 0
```

## The one gate, and how it was passed

Until 2026-09-09 every job write returned `Not authenticated.` The only obstacle was
a **one-time interactive sign-in** — no waitlist, no approval queue, no token to hold:

1. `acp configure` returns a Privy URL.
2. Opening it shows a login modal: email OTP, Google, Twitter, TikTok, an external
   wallet, or a passkey. **This step requires a human**, and it is account
   authentication, so it is not something this worker performs on the owner's behalf.
3. The CLI then exchanges the request for tokens and stores them in the OS keychain.
4. `acp agent add-signer --policy restricted` registers a signing key, which needs a
   second browser approval. `--no-wait` prints the URL and exits, but it does **not**
   persist the local half of the keypair; the blocking form does. Getting that wrong
   leaves the dashboard showing a signer while the CLI answers `NO_SIGNER`.

The owner completed steps 2 and 4 in about two minutes. The worker never sees a
private key: the CLI holds a non-custodial signer in the keychain and signs on demand.

`--policy restricted` is deliberate — the key is authorized for ACP transactions and
nothing else.

There is **no waitlist, no approval queue, no token-holding requirement, and no
sandbox-jobs prerequisite.** The "10 sandbox jobs + 7 working days" gate that
circulates in older material is a v1 artifact and does not appear anywhere in the
current docs or CLI. Corroborating evidence: several agents built by other solo
builders in this same hackathon are already live in the registry, self-registered
within the last five days —

- `dejavu` — `0xef25e2144f7ca887a9dc59e732c9e23e6a5847bb`, created 2026-08-17,
  offering "Sibyl Memory De-Risk Verdict" @ 0.5 USDC, description literally says
  "Sibyl Memory Hackathon", on Base mainnet (8453) and Robinhood Chain (4663).
- `Coral` — `0x90d9a36d8a262409c4f1f796f001a309ee6bf58e`, agent created 2026-09-03,
  offering `coral_cache` published 2026-09-04 (about six hours later), on **Base
  Sepolia** (84532). Its description references "Sibyl memory".
- `riscov` — `0x3bc37bbac8b34e0ead2d20cf9ab030af60520fff`, created 2026-09-04.

So registration is achievable by a solo builder, on testnet, in well under a day.

## Unlocking job writes

```bash
npm install -g @virtuals-protocol/acp-cli@1.0.35
acp configure                 # browser sign-in, once
acp agent create              # provisions the agent wallet + email
acp agent add-signer --policy restricted
acp agent whoami --json       # should now return the agent
```

After that, `GET /health` reports `auth.ready: true` and the job routes work with
no code change. The worker never sees a private key — the CLI holds a
non-custodial signer in the OS keychain and signs on demand.

Note `acp agent create` provisions **its own** agent wallet. Our EOA
`0x8cDec2c69be9e200A8591da3e86e822B03f7cE1f` is **not** a registered ACP agent
(confirmed: `GET /agents/wallet/0x8cDec…` returns 404, and `POST /auth/agent`
returns `404 Agent not found with wallet address 0x8cDec…`). It does not become one
by funding it. Fund the agent wallet the CLI creates, not this one.

Cost to transact: Base Sepolia is free. On mainnet, offerings in the registry are
priced from 0 to a few USDC per job. Tokenizing an agent is 3 USDC and is
**optional** — not required to register or to transact. Console hosting is 20
USDC/month and is also optional; the CLI path is free.

## Running it

```bash
pnpm install
cp .env.example .env          # defaults to Base Sepolia
pnpm probe                    # read-only capability check, costs nothing
pnpm serve                    # HTTP bridge on :8787
```

### Routes

| Route | Auth needed | Body / query |
| --- | --- | --- |
| `GET /health` | no | — |
| `POST /browse` | no | `{query, top_k?, chain_ids?, sort_by?, online?, mode?}` |
| `GET /agent` | no | `?wallet=0x…` |
| `GET /events` | no | — (NDJSON stream) |
| `POST /create_job` | yes | `{provider, offering_name?, description?, requirements?, expired_in?}` |
| `POST /fund` | yes | `{job_id, amount}` |
| `POST /complete` | yes | `{job_id, reason?}` |
| `POST /reject` | yes | `{job_id, reason}` |
| `GET /poll` | yes | `?job_id=…` |

Success is `{"ok": true, "data": …}`; failure is `{"ok": false, "error", "code", "recovery"}`
where `code` is the CLI's own error code, e.g. `NOT_AUTHENTICATED`.

### Reproducing the checks

```bash
# public registry read, no credentials at all
curl -s "https://api.acp.virtuals.io/agents/search?query=memory" | head -c 400

# our wallet is not a registered agent
curl -s "https://api.acp.virtuals.io/agents/wallet/0x8cDec2c69be9e200A8591da3e86e822B03f7cE1f"

# the auth gate
acp configure start --json
```

## Job lifecycle

Event-driven, five transitions, each one an on-chain action:

```
job.created -> budget.set -> job.funded -> job.submitted -> job.completed
                                                         \-> job.rejected
```

Client creates the job; **provider** sets the budget; client funds escrow in USDC;
provider submits the deliverable; client completes (escrow released to provider) or
rejects (escrow returned). The worker appends each transition to `events.jsonl`.

## Chains and contracts

Read from the SDK's own constants (`ACP_CONTRACT_ADDRESSES`, `USDC_ADDRESSES`) rather
than hardcoded, so they cannot drift from the pinned SDK version.

| | Base Sepolia (84532) | Base mainnet (8453) |
| --- | --- | --- |
| ACP Core | `0x0b93793923CD5De81850aF8604a233f3f24d461e` | `0x238E541BfefD82238730D00a2208E5497F1832E0` |
| USDC | `0xECc22a8F6fD62388498fBa19813E214605a2BDb3` | `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` |
| FundTransferHook | `0xbbeC2c985F9483473B9e0Da0704395943034266B` | `0x0EaD25150985Bce0B4925c54E4ee1D856381A86B` |
| API | `https://api-dev.acp.virtuals.io` | `https://api.acp.virtuals.io` |

Base Sepolia USDC here is an ACP test token, not Circle's. Also supported by the
SDK: BSC Testnet (97), Robinhood Chain (4663 / testnet), Solana mainnet + devnet.

Two caveats worth knowing:

- The docs page lists the mainnet FundTransferHook as
  `0x90717828D78731313CB350D6a58b0f91668Ea702`, but the pinned SDK uses
  `0x0EaD25150985Bce0B4925c54E4ee1D856381A86B`. Both are deployed contracts on Base
  (`eth_getCode` returns 6525 and 5629 bytes respectively), so they are different
  versions rather than a typo. The table above follows the SDK, because that is the
  address the code actually calls.
- ACP Core on Base mainnet returns only 163 bytes of code, i.e. it is a proxy. Read
  its implementation slot before assuming an ABI from a block explorer.

## Notes on the SDK and docs

- `@virtuals-protocol/acp-node` (v1) is **deprecated** on npm, with the deprecation
  string pointing at v2. Current is `@virtuals-protocol/acp-node-v2@0.1.12`
  (published 2026-08-19). CLI is `@virtuals-protocol/acp-cli@1.0.35` (2026-09-03).
  Unscoped `acp-cli` on npm is an unrelated 2024 package — do not install it.
- `docs.virtuals.io` no longer resolves. Current docs are **`os.virtuals.io`**
  (branded "EconomyOS"); `https://os.virtuals.io/llms-full.txt` is the whole doc set
  in one file and is the fastest way to read it.
- The docs' SDK examples import `AlchemyEvmProviderAdapter`, which **is not exported**
  by `acp-node-v2@0.1.12`. The real exports are `ViemProviderAdapter`,
  `PrivyAlchemyEvmProviderAdapter`, and `SolanaProviderAdapter`. Copying the doc
  snippet verbatim fails at import.
- SDK auth is not OAuth: it signs the plain message `acp-auth:<timestamp>` with the
  agent wallet and POSTs `{walletAddress, signature, message, chainId}` to
  `/auth/agent` for a JWT. That path is permissionless but **requires the wallet to
  already be a registered agent**, which is where the browser sign-in comes back in.

## Useful URLs

- Docs: https://os.virtuals.io/ · quickstart https://os.virtuals.io/quickstart ·
  ACP overview https://os.virtuals.io/acp/overview · full dump https://os.virtuals.io/llms-full.txt
- Console (no-code registration): https://app.virtuals.io/acp/new
- CLI repo: https://github.com/Virtual-Protocol/acp-cli
- SDK: https://www.npmjs.com/package/@virtuals-protocol/acp-node-v2
- ERC-8183: https://ethereum-magicians.org/t/erc-8183-agentic-commerce/27902
- Bundled CLI skill reference: `acp skill print`

## What was actually run

The sign-in described above was completed on 2026-09-09 and everything below it
followed. This section replaces an earlier one that said none of it had happened;
that was true when it was written and is not true now.

**Registered**, on Base mainnet:

| | |
|---|---|
| agent | `Admissible`, id `01a08398-e07c-7fa9-a58b-ab1de202ab35` |
| wallet | `0x7a896bfc91f1d184b6eb91980a1c6d25219e097f` (ACP provisions its own; it is not the deployer) |
| offering | `Admissibility verdict`, `01a083a0-86d7-7a45-9589-6799d4b01ba4`, 0.01 USDC, visible in the registry |
| builder code | `bc_dx1i4jek` (ERC-8021) |

**A job**, chain 8453:

```
acp job history --job-id 77820 --chain-id 8453
  status  open
  job.created   client 0x7a896BFC…  provider 0xD535a882…  evaluator 0x7a896BFC…
  requirement   {"question":"What did you record about this counterparty?"}
```

The provider is `Knos` (`0xD535a8828FFd79c12622313cb55e37d86302E0DE`), selling
`answer_a_question_from_my_memory` at 0.01 USDC. The live registry read is what
selected it.

**Funding**, both to the agent wallet:
`0x3c0a47deed0897fcc46c72db052edd4f61be58ae8a75eba3e0015a65fc214e44` (0.05 USDC)
and `0xdff86ad0e090f95f56b470de539d3c916aee3f614f4e0a9d193376c7b113ed5d` (gas).

## Still not done

The job is `open`. `budget.set`, `job.funded`, `job.submitted` and `job.completed`
have not happened, so **there is no escrow transaction and no deliverable**. Neither
funding hash above is a job escrow, and anything presenting them as one would be
wrong. The provider sets the budget; we can wait or cancel, and we have done
neither.
