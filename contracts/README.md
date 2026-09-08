# Admissible - onchain layer

`AdmissibilityAnchor.sol` is the only contract. It makes an agent's memory tamper-evident and
time-anchored: you can prove what the agent's memory contained at a given block, and prove that a
specific memory was inside it.

Everything else about admissibility - the provenance envelope, the evidence, the tiering - lives
offchain. This contract deliberately knows none of it. It holds commitments and refusals, nothing
that could be leaked or that would need updating.

## What it does

| Surface | Question it answers |
| --- | --- |
| `anchor(root, asOf, leafCount)` | "Here is everything my memory contained up to `asOf`." Append-only, per-sender. |
| `anchorAt(agent, whenAsOf)` | "What did this agent's memory commit to at that moment?" Binary search over the watermark sequence. |
| `verifyMemory(agent, index, leaf, proof)` | "Was this specific memory inside that commitment?" Sorted-pair Merkle. |
| `verifyLatest(agent, leaf, proof)` | Same, against the agent's current commitment. |
| `flag` / `unflag` / `isFlagged` | Public mirror of the offchain FLAGGED tier, so a refusal is checkable by the accused and reusable by other agents. |
| `leafOf(digest)` | The canonical leaf encoding, so the offchain tree builder and the onchain verifier can never disagree. |

Three properties carry the weight:

1. **Append-only.** Anchors are pushed to a per-agent array. There is no path that edits or removes
   one.
2. **Monotonic `asOf`.** An anchor whose watermark predates the agent's last one is rejected. Without
   this, an agent could manufacture a more convenient version of what it knew at decision time and
   every point-in-time answer would be worthless.
3. **No governance.** No owner, no admin, no upgrade, no pause. Every write is namespaced to
   `msg.sender`. Nothing here custodies value or arbitrates disputes, so a privileged role could only
   censor anchors or forge history. Its absence is the feature, not an omission.

## Leaf convention

A memory's identity is `digest = keccak256(canonical claim bytes)`, produced by the provenance
envelope offchain. The Merkle **leaf** is one further hash of that digest:

```
leaf = keccak256(abi.encodePacked(digest))     // == AdmissibilityAnchor.leafOf(digest)
```

The second hash is a security requirement, not ceremony. Internal nodes are always `keccak256` over
a 64-byte preimage; leaves are `keccak256` over a 32-byte preimage. That length-based domain
separation is what stops the classic second-preimage forgery in which an attacker submits an
internal node as a leaf and "proves" a memory that was never written.

Tree shape used by the tests and by the Python client: sorted-pair `keccak256` at every internal
node, and a lone node at the end of an odd level is promoted unchanged to the next level.

## Build, test, gas

From a fresh clone, install the one dependency first (`contracts/lib/` is gitignored):

```bash
cd contracts
forge install --no-git foundry-rs/forge-std@v1.11.0
```

`--no-git` matters: this is a subdirectory of a larger repo, and without it `forge install` would
register forge-std as a submodule of the parent. Run it from `contracts/`, where `foundry.toml`
pins the project root.

```bash
forge build
forge test
forge test --gas-report
forge fmt --check
FOUNDRY_PROFILE=ci forge test    # 4096 fuzz runs, 512 invariant runs x 128 depth
```

forge-std is the only dependency, and it is test-only. The Merkle verification is written out in
the contract rather than imported, so the deployed code has nothing external to audit alongside it.

Current state: **57 tests passing** (unit + 3 fuzz + 2 invariants).

Measured gas, optimizer on at 20 000 runs:

| Function | Avg | Max |
| --- | --- | --- |
| `anchor` | 101 358 | 115 611 |
| `anchorAt` | 14 009 | 22 284 |
| `verifyMemory` | 8 053 | 8 572 |
| `flag` | 81 985 | 96 256 |
| `unflag` | 46 706 | 98 298 |
| deployment | 1 459 953 | - |

## Deploy

```bash
export PRIVATE_KEY=0x...           # deployer
export ETHERSCAN_API_KEY=...       # one key covers every chain on Etherscan V2

# Base Sepolia
forge script script/Deploy.s.sol:Deploy --rpc-url base_sepolia --broadcast --verify -vvvv

# Base mainnet
forge script script/Deploy.s.sol:Deploy --rpc-url base --broadcast --verify -vvvv
```

## Verify an already-deployed instance

Basescan's own API V1 was retired on **2025-08-15**. Verification for Base now goes through the
unified Etherscan V2 endpoint, which selects the chain with a `chainid` query parameter:

```bash
# Base mainnet (chain id 8453)
forge verify-contract \
  --chain-id 8453 \
  --num-of-optimizations 20000 \
  --compiler-version v0.8.28+commit.7893614a \
  --verifier etherscan \
  --verifier-url "https://api.etherscan.io/v2/api?chainid=8453" \
  --etherscan-api-key "$ETHERSCAN_API_KEY" \
  --watch \
  <DEPLOYED_ADDRESS> \
  src/AdmissibilityAnchor.sol:AdmissibilityAnchor

# Base Sepolia (chain id 84532) - same command, swap both chain ids
forge verify-contract \
  --chain-id 84532 \
  --num-of-optimizations 20000 \
  --compiler-version v0.8.28+commit.7893614a \
  --verifier etherscan \
  --verifier-url "https://api.etherscan.io/v2/api?chainid=84532" \
  --etherscan-api-key "$ETHERSCAN_API_KEY" \
  --watch \
  <DEPLOYED_ADDRESS> \
  src/AdmissibilityAnchor.sol:AdmissibilityAnchor
```

The constructor takes no arguments, so no `--constructor-args` is needed. `foundry.toml` sets
`bytecode_hash = "none"` and `cbor_metadata = false`, so the same source tree produces byte-identical
bytecode on any machine and verification is reproducible rather than a leap of faith.

## ABI

```
contracts/out/AdmissibilityAnchor.sol/AdmissibilityAnchor.json
```

Standard Foundry artifact - the ABI is the `.abi` field, the deploy bytecode is
`.bytecode.object`. Regenerate with `forge build`.
