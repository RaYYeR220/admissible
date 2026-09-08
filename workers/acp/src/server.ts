// Local HTTP bridge so the Python agent can reach ACP without a Node dependency.
// Every route returns JSON; every lifecycle transition is also appended to
// events.jsonl as one JSON object per line.

import { createServer } from "node:http";
import { createReadStream, existsSync } from "node:fs";
import "dotenv/config";
import {
  EVENT_LOG,
  agentByWallet,
  authStatus,
  browse,
  chainInfo,
  completeJob,
  createJob,
  fundJob,
  poll,
  rejectJob,
} from "./acp.js";

const PORT = Number(process.env.ACP_WORKER_PORT ?? 8787);

type Handler = (body: any, url: URL) => Promise<unknown>;

const routes: Record<string, Handler> = {
  "GET /health": async () => ({
    ok: true,
    chain: chainInfo(),
    auth: await authStatus(),
  }),

  // Read-only registry search. Works with no credentials.
  "POST /browse": async (body) =>
    browse(body.query, {
      topK: body.top_k ?? body.topK,
      chainIds: body.chain_ids ?? body.chainIds,
      sortBy: body.sort_by ?? body.sortBy,
      online: body.online,
      mode: body.mode,
    }),

  "GET /agent": async (_b, url) => {
    const wallet = url.searchParams.get("wallet");
    if (!wallet) throw new Error("wallet query param required");
    return agentByWallet(wallet);
  },

  // Job lifecycle. Requires a signed-in agent (see README).
  "POST /create_job": async (body) =>
    createJob({
      provider: body.provider,
      offeringName: body.offering_name ?? body.offeringName,
      description: body.description,
      requirements: body.requirements ?? body.payload,
      expiredIn: body.expired_in ?? body.expiredIn,
    }),

  "POST /fund": async (body) => fundJob(String(body.job_id ?? body.jobId), Number(body.amount)),
  "POST /complete": async (body) => completeJob(String(body.job_id ?? body.jobId), body.reason),
  "POST /reject": async (body) => rejectJob(String(body.job_id ?? body.jobId), body.reason),

  "GET /poll": async (_b, url) => {
    const jobId = url.searchParams.get("job_id") ?? url.searchParams.get("jobId");
    if (!jobId) throw new Error("job_id query param required");
    return poll(jobId);
  },
};

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://localhost:${PORT}`);
  const key = `${req.method} ${url.pathname}`;

  // Event tail is streamed rather than buffered so a long run stays cheap.
  if (key === "GET /events") {
    res.writeHead(200, { "content-type": "application/x-ndjson" });
    if (existsSync(EVENT_LOG)) createReadStream(EVENT_LOG).pipe(res);
    else res.end();
    return;
  }

  const handler = routes[key];
  if (!handler) {
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not found", routes: Object.keys(routes) }));
    return;
  }

  try {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const raw = Buffer.concat(chunks).toString("utf8");
    const body = raw ? JSON.parse(raw) : {};
    const result = await handler(body, url);
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true, data: result }));
  } catch (err) {
    const e = err as Error & { code?: string; recovery?: string };
    res.writeHead(400, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: false, error: e.message, code: e.code, recovery: e.recovery }));
  }
});

server.listen(PORT, () => {
  const chain = chainInfo();
  process.stderr.write(
    `acp worker on http://localhost:${PORT} (${chain.network}, core ${chain.acpCore})\n`,
  );
});
