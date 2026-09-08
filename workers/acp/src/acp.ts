// Bridge to Virtuals Protocol ACP (Agent Commerce Protocol).
//
// Two transports, deliberately:
//   - Registry reads go straight to the public ACP REST API. No auth, no wallet,
//     no gas. This is what lets the product pick a counterparty at runtime.
//   - Job lifecycle writes shell out to the `acp` CLI, which owns the agent's
//     non-custodial signer (OS keychain). Nothing here ever sees a private key.
//
// Chain/contract constants are re-exported from the SDK rather than hardcoded,
// so they cannot drift from whatever @virtuals-protocol/acp-node-v2 is pinned.

import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { appendFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import {
  ACP_CONTRACT_ADDRESSES,
  ACP_SERVER_URL,
  ACP_TESTNET_SERVER_URL,
  USDC_ADDRESSES,
} from "@virtuals-protocol/acp-node-v2";

const execFileAsync = promisify(execFile);

export const BASE_MAINNET = 8453;
export const BASE_SEPOLIA = 84532;

export const EVENT_LOG = process.env.ACP_EVENT_LOG ?? "events.jsonl";
const CLI_BIN = process.env.ACP_CLI_BIN ?? "acp";
const CLI_TIMEOUT_MS = Number(process.env.ACP_CLI_TIMEOUT_MS ?? 120_000);

export function chainId(): number {
  return Number(process.env.ACP_CHAIN_ID ?? BASE_SEPOLIA);
}

export function serverUrl(id = chainId()): string {
  return id === BASE_MAINNET ? ACP_SERVER_URL : ACP_TESTNET_SERVER_URL;
}

export function chainInfo(id = chainId()) {
  return {
    chainId: id,
    network: id === BASE_MAINNET ? "base-mainnet" : "base-sepolia",
    acpCore: ACP_CONTRACT_ADDRESSES[id],
    usdc: USDC_ADDRESSES[id],
    api: serverUrl(id),
  };
}

/** Append one lifecycle event as a JSON line for the Python agent to turn into a memory. */
export async function emit(type: string, data: Record<string, unknown>): Promise<void> {
  const line = JSON.stringify({ ts: new Date().toISOString(), type, ...data });
  process.stdout.write(line + "\n");
  await appendFile(EVENT_LOG, line + "\n").catch(() => {});
}

export interface Offering {
  name: string;
  description?: string;
  deliverable?: string;
  requirements?: string;
  priceValue?: number;
  priceType?: string;
  slaMinutes?: number;
}

export interface Agent {
  id: string;
  name: string;
  description?: string;
  walletAddress: string;
  role?: string;
  rating?: number | null;
  chains?: Array<{ chainId: number; active: boolean }>;
  offerings?: Offering[];
}

export interface BrowseOptions {
  topK?: number;
  chainIds?: number[];
  sortBy?: string;
  online?: "all" | "online" | "offline";
  mode?: "relevance" | "recency" | "mixed";
}

/**
 * Search the live Virtuals agent registry. Public endpoint - works with no
 * credentials, which is why the product can rely on it during a demo.
 */
export async function browse(query: string, opts: BrowseOptions = {}): Promise<Agent[]> {
  const params = new URLSearchParams({ query });
  if (opts.chainIds?.length) params.set("chainIds", opts.chainIds.join(","));
  if (opts.topK) params.set("top_k", String(opts.topK));
  if (opts.sortBy) params.set("sort_by", opts.sortBy);
  if (opts.online) params.set("online", opts.online);
  if (opts.mode) params.set("mode", opts.mode);

  const res = await fetch(`${serverUrl()}/agents/search?${params}`);
  if (!res.ok) throw new Error(`browse failed: ${res.status} ${res.statusText}`);
  const body = (await res.json()) as { data: Agent[] };
  const agents = body.data ?? [];
  await emit("registry.browsed", { query, resultCount: agents.length });
  return agents;
}

/** Look up a single agent by wallet address. Also public. */
export async function agentByWallet(wallet: string): Promise<Agent | null> {
  const res = await fetch(`${serverUrl()}/agents/wallet/${wallet}`);
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`agentByWallet failed: ${res.status} ${res.statusText}`);
  return ((await res.json()) as { data: Agent }).data ?? null;
}

/** Turn a thrown child-process failure into an Error carrying code + recovery. */
function cliError(raw: { stderr?: string; stdout?: string }, args: string[]): Error {
  const text = `${raw.stderr ?? ""}\n${raw.stdout ?? ""}`;
  const message = /CliError:\s*(.+)/.exec(text)?.[1]?.trim();
  const code = /\bcode:\s*'([^']+)'/.exec(text)?.[1];
  const recovery = /\brecovery:\s*'([^']+)'/.exec(text)?.[1];
  const err = new Error(message ?? `acp ${args.join(" ")} failed`);
  Object.assign(err, { code, recovery, command: `acp ${args.join(" ")}` });
  return err;
}

/** Absolute path to the ACP CLI's JS entry point, if it can be located. */
function resolveCliEntry(): string | null {
  if (process.env.ACP_CLI_JS) return process.env.ACP_CLI_JS;
  const roots = [
    process.env.npm_config_prefix && join(process.env.npm_config_prefix, "node_modules"),
    dirname(process.execPath) + "/node_modules",
  ].filter(Boolean) as string[];
  for (const root of roots) {
    const p = join(root, "@virtuals-protocol", "acp-cli", "dist", "bin", "acp.js");
    if (existsSync(p)) return p;
  }
  return null;
}

/**
 * Run an `acp` CLI command with --json and parse the result.
 * The CLI prints a JSON object on success and a {error, code, recovery}
 * envelope on failure, both on stdout with exit code 0, so parse before judging.
 */
export async function cli<T = unknown>(args: string[]): Promise<T> {
  // Prefer invoking the CLI's JS entry with the current node binary. On Windows
  // the `acp` shim is a .cmd, which execFile can only run through a shell, and a
  // shell would concatenate rather than escape these arguments.
  const js = resolveCliEntry();
  const [bin, argv] = js
    ? [process.execPath, [js, ...args, "--json"]]
    : [CLI_BIN, [...args, "--json"]];

  let stdout: string;
  try {
    ({ stdout } = await execFileAsync(bin, argv, {
      timeout: CLI_TIMEOUT_MS,
      maxBuffer: 16 * 1024 * 1024,
      shell: !js && process.platform === "win32",
    }));
  } catch (raw) {
    // A CLI that exits non-zero prints a stack trace, not JSON. Pull the
    // structured bits out so callers can branch on a code instead of a string.
    throw cliError(raw as { stderr?: string; stdout?: string }, args);
  }

  const line = stdout.trim().split("\n").find((l) => l.trim().startsWith("{"));
  if (!line) throw new Error(`acp ${args[0]}: no JSON on stdout`);
  const parsed = JSON.parse(line);
  if (parsed.error) {
    const err = new Error(`acp ${args.join(" ")}: ${parsed.error}`);
    Object.assign(err, parsed);
    throw err;
  }
  return parsed as T;
}

export interface CreateJobInput {
  provider: string;
  offeringName?: string;
  description?: string;
  requirements?: Record<string, unknown>;
  expiredIn?: number;
}

/**
 * Create a job against a provider. Uses the offering flow when an offering name
 * is given (requirements are validated against its schema server-side), and a
 * freeform custom job otherwise.
 */
export async function createJob(input: CreateJobInput): Promise<{ jobId: string }> {
  const id = chainId();
  const args = input.offeringName
    ? [
        "client", "create-job",
        "--provider", input.provider,
        "--offering-name", input.offeringName,
        "--requirements", JSON.stringify(input.requirements ?? {}),
        "--chain-id", String(id),
      ]
    : [
        "client", "create-custom-job",
        "--provider", input.provider,
        "--description", input.description ?? "",
        "--expired-in", String(input.expiredIn ?? 3600),
        "--chain-id", String(id),
      ];

  const out = await cli<{ jobId?: string | number }>(args);
  const jobId = String(out.jobId ?? "");
  await emit("job.created", { jobId, provider: input.provider, chainId: id });
  return { jobId };
}

/** Lock USDC in escrow. Amount must match the provider's budget.set exactly. */
export async function fundJob(jobId: string, amount: number) {
  const out = await cli(["client", "fund", "--job-id", jobId, "--amount", String(amount)]);
  await emit("job.funded", { jobId, amount, chainId: chainId() });
  return out;
}

/** Release escrow to the provider. */
export async function completeJob(jobId: string, reason = "accepted") {
  const out = await cli(["client", "complete", "--job-id", jobId, "--reason", reason]);
  await emit("job.completed", { jobId, reason, chainId: chainId() });
  return out;
}

/** Return escrow to the client. */
export async function rejectJob(jobId: string, reason: string) {
  const out = await cli(["client", "reject", "--job-id", jobId, "--reason", reason]);
  await emit("job.rejected", { jobId, reason, chainId: chainId() });
  return out;
}

/** Current job state. Non-blocking; call on an interval from the Python side. */
export async function poll(jobId: string): Promise<Record<string, unknown>> {
  const job = await cli<Record<string, unknown>>([
    "job", "history", "--job-id", jobId, "--chain-id", String(chainId()),
  ]);
  await emit("job.polled", { jobId, phase: job.phase ?? job.status ?? null });
  return job;
}

/** Whether the CLI is installed and signed in. Reported by /health. */
export async function authStatus(): Promise<{ ready: boolean; agent?: unknown; reason?: string }> {
  try {
    const agent = await cli(["agent", "whoami"]);
    return { ready: true, agent };
  } catch (err) {
    return { ready: false, reason: (err as Error).message };
  }
}
