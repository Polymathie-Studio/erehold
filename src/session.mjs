// erehold v0 session: holds provider keys in this process only, hands the child stand-ins,
// and swaps each stand-in for the real key as a request leaves for its one fixed provider.
// Built-in modules only. See SPEC.md.

import http from "node:http";
import https from "node:https";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

// The destination for each provider is fixed here. Nothing the child sends can change it.
export const PROVIDERS = {
  anthropic: {
    host: "api.anthropic.com",
    envKey: "ANTHROPIC_API_KEY",
    envBase: "ANTHROPIC_BASE_URL",
    basePath: "",
    setAuth: (headers, key) => { headers["x-api-key"] = key; },
  },
  openai: {
    host: "api.openai.com",
    envKey: "OPENAI_API_KEY",
    envBase: "OPENAI_BASE_URL",
    basePath: "/v1",
    setAuth: (headers, key) => { headers["authorization"] = `Bearer ${key}`; },
  },
  // Google's libraries read GEMINI_API_KEY or GOOGLE_API_KEY (GOOGLE_API_KEY wins), so the child
  // gets the stand-in under both. They take a different address only in code, so GEMINI_BASE_URL
  // is erehold's own variable: a program passes it as its base URL.
  gemini: {
    host: "generativelanguage.googleapis.com",
    envKey: "GEMINI_API_KEY",
    alsoEnvKeys: ["GOOGLE_API_KEY"],
    envBase: "GEMINI_BASE_URL",
    basePath: "",
    setAuth: (headers, key) => { headers["x-goog-api-key"] = key; },
  },
};

// Only these variables pass from erehold's environment to the child.
const ENV_ALLOW = [
  "PATH", "HOME", "USER", "LOGNAME", "SHELL", "TERM", "COLORTERM", "TERM_PROGRAM",
  "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TZ",
];

// Headers never forwarded upstream: credentials the child sent, and hop-by-hop headers.
const STRIP = new Set([
  "host", "x-api-key", "x-goog-api-key", "authorization", "proxy-authorization", "connection", "keep-alive",
  "proxy-connection", "transfer-encoding", "upgrade", "te", "trailer",
]);

export const HOLDER_LEVEL = "level 2: separate process, same user; the agent is not sandboxed";

function standin(provider) {
  return `erehold-standin-${provider}-${crypto.randomBytes(24).toString("hex")}`;
}

function sameValue(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

function presented(req, url) {
  const k = req.headers["x-api-key"] ?? req.headers["x-goog-api-key"];
  if (k) return String(k);
  if (url.searchParams.has("key")) return url.searchParams.get("key");
  const a = req.headers["authorization"];
  if (a && /^Bearer\s+/i.test(a)) return a.replace(/^Bearer\s+/i, "");
  return null;
}

// The session record: one JSON line per event, each carrying a hash of the line before it.
class Record {
  constructor(file, session) {
    this.file = file;
    this.session = session;
    this.seq = 0;
    this.prev = "genesis";
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  }
  write(entry) {
    const body = { seq: this.seq++, ts: new Date().toISOString(), session: this.session, ...entry, prev: this.prev };
    const hash = crypto.createHash("sha256").update(JSON.stringify(body)).digest("hex");
    fs.appendFileSync(this.file, JSON.stringify({ ...body, hash }) + "\n", { mode: 0o600 });
    this.prev = hash;
  }
}

// Check a record file's chain. Returns { ok, lines, error }.
export function verifyRecord(file) {
  const lines = fs.readFileSync(file, "utf8").split("\n").filter(Boolean);
  let prev = "genesis";
  for (let i = 0; i < lines.length; i++) {
    let rec;
    try { rec = JSON.parse(lines[i]); } catch { return { ok: false, lines: lines.length, error: `line ${i + 1}: not valid JSON` }; }
    const { hash, ...body } = rec;
    if (body.seq !== i) return { ok: false, lines: lines.length, error: `line ${i + 1}: sequence ${body.seq}, expected ${i}` };
    if (body.prev !== prev) return { ok: false, lines: lines.length, error: `line ${i + 1}: does not follow the line before it` };
    const want = crypto.createHash("sha256").update(JSON.stringify(body)).digest("hex");
    if (hash !== want) return { ok: false, lines: lines.length, error: `line ${i + 1}: contents changed after writing` };
    prev = hash;
  }
  return { ok: true, lines: lines.length, error: null };
}

// Start a session.
//   secrets:   { provider: realKey }            (the CLI reads these from the keychain)
//   keyNames:  { provider: nameShownInRecord }
//   recordDir: where the session record is written
//   recordKey: secret used for the keyed fingerprints in the record
//   upstream:  test hook only, { provider: "http://127.0.0.1:port" }; the CLI never sets it
export async function startSession({ secrets, keyNames = {}, recordDir, recordKey, upstream = null, holder = HOLDER_LEVEL }) {
  const id = `${new Date().toISOString().replace(/[:.]/g, "-")}-${crypto.randomBytes(3).toString("hex")}`;
  const record = new Record(path.join(recordDir, `${id}.jsonl`), id);
  const held = new Map();
  for (const [p, value] of Object.entries(secrets)) {
    if (!PROVIDERS[p]) throw new Error(`unknown provider: ${p}`);
    if (!value) throw new Error(`no key for ${p}`);
    held.set(p, { value, standin: standin(p), name: keyNames[p] ?? p });
  }
  const fingerprint = (value) => crypto.createHmac("sha256", recordKey).update(value).digest("hex").slice(0, 32);
  let open = true;

  const server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://relay");
    const [, p, ...rest] = url.pathname.split("/");
    const entry = held.get(p);
    const base = { event: "request", provider: p || null, method: req.method, path: "/" + rest.join("/") };
    const refuse = (status, outcome) => {
      record.write({ ...base, outcome, status });
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: `erehold: ${outcome}` }));
      req.resume();
    };
    if (!open) return refuse(503, "refused: session closed");
    if (!entry) return refuse(404, "refused: unknown provider");
    const got = presented(req, url);
    if (!got || !sameValue(got, entry.standin)) return refuse(403, "refused: not this session's stand-in");

    const spec = PROVIDERS[p];
    const headers = {};
    for (const [k, v] of Object.entries(req.headers)) if (!STRIP.has(k.toLowerCase())) headers[k] = v;
    spec.setAuth(headers, entry.value);
    const target = upstream?.[p] ? new URL(upstream[p]) : new URL(`https://${spec.host}`);
    headers.host = target.host;
    const lib = target.protocol === "http:" ? http : https;
    url.searchParams.delete("key"); // a key sent in the address travels as a header instead
    let bytesOut = 0;
    req.on("data", (c) => { bytesOut += c.length; });
    const up = lib.request({
      protocol: target.protocol, hostname: target.hostname, port: target.port || undefined,
      method: req.method, path: "/" + rest.join("/") + url.search, headers,
    }, (ures) => {
      let bytesIn = 0;
      ures.on("data", (c) => { bytesIn += c.length; });
      ures.on("end", () => record.write({
        ...base, outcome: "forwarded", status: ures.statusCode, key: entry.name,
        fingerprint: fingerprint(entry.value), destination: target.host, bytesOut, bytesIn,
      }));
      res.writeHead(ures.statusCode, ures.headers);
      ures.pipe(res);
    });
    up.on("error", (e) => {
      record.write({ ...base, outcome: "upstream error", error: e.code || "error", key: entry.name, destination: target.host });
      if (!res.headersSent) res.writeHead(502, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "erehold: upstream error" }));
    });
    req.pipe(up);
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  record.write({
    event: "open", holder,
    keys: [...held.entries()].map(([p, e]) => ({ provider: p, key: e.name, fingerprint: fingerprint(e.value) })),
  });

  return {
    id,
    port,
    recordFile: record.file,
    // The child's environment: the allow list from parentEnv, plus stand-ins and relay addresses.
    childEnv(parentEnv = process.env, pass = []) {
      const env = {};
      for (const k of [...ENV_ALLOW, ...pass]) if (parentEnv[k] !== undefined) env[k] = parentEnv[k];
      for (const [p, e] of held) {
        env[PROVIDERS[p].envKey] = e.standin;
        for (const k of PROVIDERS[p].alsoEnvKeys ?? []) env[k] = e.standin;
        env[PROVIDERS[p].envBase] = `http://127.0.0.1:${port}/${p}${PROVIDERS[p].basePath}`;
      }
      return env;
    },
    async close(exitCode = null) {
      if (!open) return;
      open = false;
      held.clear();
      await new Promise((resolve) => { server.close(resolve); server.closeAllConnections(); });
      record.write({ event: "close", childExit: exitCode });
    },
  };
}
