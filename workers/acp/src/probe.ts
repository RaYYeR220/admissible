// Reproducible check of what the ACP integration can and cannot do right now.
// Costs nothing and touches no chain. Run: pnpm probe

import "dotenv/config";
import { agentByWallet, authStatus, browse, chainInfo, serverUrl } from "./acp.js";
import { BASE_MAINNET, BASE_SEPOLIA } from "./acp.js";

const WALLET = process.env.ACP_WALLET_ADDRESS ?? "";

async function main() {
  console.log("chain:", JSON.stringify(chainInfo(BASE_SEPOLIA)));
  console.log("chain:", JSON.stringify(chainInfo(BASE_MAINNET)));

  // 1. Public registry read - the capability the product actually depends on.
  const agents = await browse("memory", { topK: 5 });
  console.log(`\nregistry hits for "memory": ${agents.length}`);
  for (const a of agents) {
    const chains = (a.chains ?? []).map((c) => c.chainId).join(",");
    const offers = (a.offerings ?? []).map((o) => `${o.name}@${o.priceValue}`).join("; ");
    console.log(`  ${a.name} | ${a.walletAddress} | chains=[${chains}] | ${offers}`);
  }

  // 2. Does our wallet resolve to a registered agent?
  if (WALLET) {
    const me = await agentByWallet(WALLET);
    console.log(`\nagent for ${WALLET}:`, me ? me.name : "NOT REGISTERED");
  }

  // 3. Is the CLI signed in, i.e. can we do job lifecycle writes?
  const auth = await authStatus();
  console.log("\ncli auth:", auth.ready ? "ready" : `blocked - ${auth.reason}`);

  console.log("\nserver:", serverUrl());
}

main().catch((e) => {
  console.error("probe failed:", e.message);
  process.exit(1);
});
