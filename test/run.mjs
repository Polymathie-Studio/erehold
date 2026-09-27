// erehold v0 tests: one per "Done when" check in SPEC.md. Harmless fake keys and a fake
// provider on 127.0.0.1, so every run is repeatable and nothing leaves the machine.
// Run: node test/run.mjs

import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { startSession, verifyRecord, crossCheckLedger, ledgerProtection } from "../src/session.mjs";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { keysFromEnvFile } from "../src/envfile.mjs";

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const CANARY_A = "sk-ant-FAKE-canary-7f3e9a1c5b2d4e6f8a0b";
const CANARY_O = "sk-FAKE-openai-canary-2c4e6a8b0d1f3e5a7c9b";
const CANARY_G = "AIzaFAKE-gemini-canary-9d8c7b6a5f4e3d2c1b0a";

let passed = 0, failed = 0;
const check = (name, ok) => { ok ? passed++ : failed++; console.log(`${ok ? "PASS" : "FAIL"}  ${name}`); };

// Fake provider: records the credentials it receives, answers "ok", never echoes a key.
const seen = [];
const fake = http.createServer((req, res) => {
  seen.push({ path: req.url, xApiKey: req.headers["x-api-key"] ?? null, auth: req.headers["authorization"] ?? null, goog: req.headers["x-goog-api-key"] ?? null });
  req.resume();
  req.on("end", () => { res.writeHead(200, { "content-type": "application/json" }); res.end('{"reply":"ok"}'); });
});
await new Promise((r) => fake.listen(0, "127.0.0.1", r));
const UP = `http://127.0.0.1:${fake.address().port}`;

const recordDir = fs.mkdtempSync(path.join(os.tmpdir(), "erehold-test-"));
const session = await startSession({
  secrets: { anthropic: CANARY_A, openai: CANARY_O, gemini: CANARY_G },
  keyNames: { anthropic: "test-anthropic", openai: "test-openai", gemini: "test-gemini" },
  recordDir, recordKey: "test-record-key", upstream: { anthropic: UP, openai: UP, gemini: UP },
});

// A child program sees only what erehold gives it. It prints its environment and arguments,
// then makes the same calls an SDK would, using only what is in its environment.
const childScript = `
  const out = { env: process.env, argv: process.argv, results: {} };
  const A = process.env.ANTHROPIC_BASE_URL, O = process.env.OPENAI_BASE_URL, G = process.env.GEMINI_BASE_URL;
  const post = (u, h) => fetch(u, { method: "POST", headers: { "content-type": "application/json", ...h }, body: "{}" })
    .then(async r => ({ status: r.status, body: await r.text() }));
  out.results.anthropicGood = await post(A + "/v1/messages", { "x-api-key": process.env.ANTHROPIC_API_KEY });
  out.results.openaiGood = await post(O + "/chat/completions", { authorization: "Bearer " + process.env.OPENAI_API_KEY });
  out.results.geminiHeader = await post(G + "/v1beta/models/m:generateContent", { "x-goog-api-key": process.env.GEMINI_API_KEY });
  out.results.geminiQuery = await post(G + "/v1beta/models/m:generateContent?key=" + process.env.GOOGLE_API_KEY, {});
  out.results.anthropicWrong = await post(A + "/v1/messages", { "x-api-key": "sk-ant-guessed-value" });
  out.results.anthropicNone = await post(A + "/v1/messages", {});
  out.results.unknownProvider = await post(A.replace("/anthropic", "/elsewhere") + "/v1/x", { "x-api-key": process.env.ANTHROPIC_API_KEY });
  console.log(JSON.stringify(out));
`;
const parentEnv = { ...process.env, FAKE_PARENT_SECRET: "parent-secret-should-not-pass", ANTHROPIC_API_KEY: CANARY_A };
// The child must run asynchronously: the relay lives in this process and has to keep answering.
const r = await new Promise((resolve) => execFile(process.execPath, ["--input-type=module", "-e", childScript],
  { env: session.childEnv(parentEnv), encoding: "utf8" }, (err, stdout, stderr) => resolve({ stdout, stderr })));
const childOut = r.stdout + r.stderr;
let child = {};
try { child = JSON.parse(r.stdout); } catch { console.log(childOut); }
const res = child.results ?? {};

// 1. The fake key appears nowhere the child can see.
check("1. the real key is not in the child's environment, arguments, or output",
  !childOut.includes(CANARY_A) && !childOut.includes(CANARY_O) && !childOut.includes(CANARY_G));
check("1. the child holds stand-ins, not keys",
  child.env?.ANTHROPIC_API_KEY?.startsWith("erehold-standin-anthropic-") && child.env?.OPENAI_API_KEY?.startsWith("erehold-standin-openai-"));

// 2. A secret in erehold's own environment does not reach the child.
check("2. a secret set in erehold's environment does not reach the child", child.env && !("FAKE_PARENT_SECRET" in child.env));

// 3. The session stand-in reaches the provider as the real key.
const hits = seen;
check("3. anthropic: the provider receives the real key", res.anthropicGood?.status === 200 && hits.some((s) => s.xApiKey === CANARY_A));
check("3. openai: the provider receives the real key", res.openaiGood?.status === 200 && hits.some((s) => s.auth === `Bearer ${CANARY_O}`));
check("3. gemini: the provider receives the real key, by header or by key= in the address",
  res.geminiHeader?.status === 200 && res.geminiQuery?.status === 200 && seen.filter((s) => s.goog === CANARY_G).length === 2);
check("3. gemini: a key sent in the address is removed from the address", !seen.some((s) => s.path.includes("key=")));
check("1. gemini stand-in is given under both GEMINI_API_KEY and GOOGLE_API_KEY",
  child.env?.GEMINI_API_KEY?.startsWith("erehold-standin-gemini-") && child.env?.GOOGLE_API_KEY === child.env?.GEMINI_API_KEY);
check("3. the provider never receives a stand-in", !seen.some((s) => JSON.stringify(s).includes("erehold-standin")));

// 4. Any other value is refused and never forwarded.
check("4. a wrong value is refused (403)", res.anthropicWrong?.status === 403);
check("4. a missing value is refused (403)", res.anthropicNone?.status === 403);
check("4. refused requests never reach the provider", seen.length === 4);

// 5. An unknown provider path is refused.
check("5. an unknown provider path is refused (404)", res.unknownProvider?.status === 404);

// 7. After the session closes, the stand-in no longer works.
const standinA = child.env?.ANTHROPIC_API_KEY;
const baseA = child.env?.ANTHROPIC_BASE_URL;
await session.close(0);
let afterClose;
try { afterClose = (await fetch(baseA + "/v1/messages", { method: "POST", headers: { "x-api-key": standinA }, body: "{}" })).status; }
catch { afterClose = "connection refused"; }
check("7. after close, the stand-in no longer works", afterClose !== 200 && seen.length === 4);

// 6. One record line per request, no key in the record, and the chain catches tampering.
const recText = fs.readFileSync(session.recordFile, "utf8");
const lines = recText.split("\n").filter(Boolean).map((l) => JSON.parse(l));
const requests = lines.filter((l) => l.event === "request");
check("6. one record line per request (7 requests)", requests.length === 7);
check("6. forwarded requests are recorded with key name and fingerprint",
  requests.filter((l) => l.outcome === "forwarded").every((l) => l.key && /^[0-9a-f]{32}$/.test(l.fingerprint)));
check("6. the record never contains a key or a stand-in",
  !recText.includes(CANARY_A) && !recText.includes(CANARY_O) && !recText.includes(CANARY_G) && !recText.includes("erehold-standin"));
check("6. the record opens and closes", lines[0].event === "open" && lines.at(-1).event === "close");
check("6. the chain verifies", verifyRecord(session.recordFile).ok);
const edited = path.join(recordDir, "edited.jsonl");
fs.writeFileSync(edited, recText.replace('"status":403', '"status":200'));
check("6. an edited line fails verification", !verifyRecord(edited).ok);
const cut = path.join(recordDir, "cut.jsonl");
fs.writeFileSync(cut, recText.split("\n").filter((_, i) => i !== 2).join("\n"));
check("6. a deleted line fails verification", !verifyRecord(cut).ok);

// 8. No dependencies.
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
check("8. the package declares no dependencies", !pkg.dependencies && !pkg.devDependencies && !pkg.optionalDependencies);

// 9. Keys are read correctly out of a .env file.
const envText = [
  "# comment", "OTHER_SECRET=nope", `export ANTHROPIC_API_KEY="${CANARY_A}"`,
  `OPENAI_API_KEY=${CANARY_O}   # trailing comment`, "ANTHROPIC_BASE_URL=http://x",
  `GEMINI_API_KEY='${CANARY_G}'`, "MISTRAL_API_KEY=abc123", "GITHUB_TOKEN=ghp_x",
].join("\n");
const { found: fromEnv, unsupported } = keysFromEnvFile(envText);
check("9. .env import reads all three provider keys, quoted or not, and nothing else",
  fromEnv.anthropic === CANARY_A && fromEnv.openai === CANARY_O && fromEnv.gemini === CANARY_G && Object.keys(fromEnv).length === 3);
check("9. .env import names the keys it does not handle instead of skipping them silently",
  ["MISTRAL_API_KEY", "GITHUB_TOKEN", "OTHER_SECRET"].every((n) => unsupported.includes(n)) && unsupported.length === 3);

// 10. The shared ledger: a full rewrite of a session file passes its own chain check but not the
// comparison with the ledger, and an append-only ledger refuses rewriting while accepting additions.
const ledgerDir = fs.mkdtempSync(path.join(os.tmpdir(), "erehold-ledger-"));
const ledger = path.join(ledgerDir, "ledger.jsonl");
fs.writeFileSync(ledger, "", { mode: 0o600 });
check("10. an unflagged ledger reports no protection", ledgerProtection(ledger) === "none");
execFileSync("chflags", ["uappnd", ledger]);
check("10. the owner's append-only flag is reported as user-level, not system", ledgerProtection(ledger) === "user");
const s2 = await startSession({ secrets: { anthropic: CANARY_A }, recordDir: ledgerDir, recordKey: "k", upstream: { anthropic: UP }, ledgerFile: ledger });
await fetch(`http://127.0.0.1:${s2.port}/anthropic/v1/messages`, { method: "POST", headers: { "x-api-key": s2.childEnv({}).ANTHROPIC_API_KEY }, body: "{}" });
await s2.close(0);
check("10. every session line also reaches the ledger, and the two match", crossCheckLedger(s2.recordFile, ledger).ok);
check("10. the session's open line declares the ledger's protection",
  JSON.parse(fs.readFileSync(s2.recordFile, "utf8").split("\n")[0]).ledger?.protection === "user");
// Rewrite the session file consistently, recomputing every hash, as code running as you could.
const forged = []; let prev = "genesis";
for (const l of fs.readFileSync(s2.recordFile, "utf8").split("\n").filter(Boolean)) {
  const { hash, ...body } = JSON.parse(l);
  if (body.event === "request") body.status = 418;
  body.prev = prev;
  const h = crypto.createHash("sha256").update(JSON.stringify(body)).digest("hex");
  forged.push(JSON.stringify({ ...body, hash: h })); prev = h;
}
fs.writeFileSync(s2.recordFile, forged.join("\n") + "\n");
check("10. a full, consistent rewrite of the session file still passes its own chain check", verifyRecord(s2.recordFile).ok);
check("10. but the comparison with the ledger catches it", !crossCheckLedger(s2.recordFile, ledger).ok);
let rewriteRefused = false;
try { fs.writeFileSync(ledger, "rewritten\n"); } catch (e) { rewriteRefused = e.code === "EPERM"; }
let appendWorked = false;
try { fs.appendFileSync(ledger, ""); appendWorked = true; } catch {}
check("10. the append-only ledger refuses rewriting and still accepts additions", rewriteRefused && appendWorked);
execFileSync("chflags", ["nouappnd", ledger]);
fs.rmSync(ledgerDir, { recursive: true, force: true });

// 11. An action that cannot be recorded does not happen: with the record unwritable, the relay
// refuses, the provider is never reached, and erehold keeps running rather than crashing.
const nwDir = fs.mkdtempSync(path.join(os.tmpdir(), "erehold-nowrite-"));
const before = seen.length;
const s3 = await startSession({ secrets: { anthropic: CANARY_A }, recordDir: nwDir, recordKey: "k", upstream: { anthropic: UP } });
fs.chmodSync(s3.recordFile, 0o400);
const post3 = () => fetch(`http://127.0.0.1:${s3.port}/anthropic/v1/messages`, { method: "POST", headers: { "x-api-key": s3.childEnv({}).ANTHROPIC_API_KEY }, body: "{}" }).then((r) => r.status, () => "FAIL");
const first = await post3(), second = await post3();
check("11. with the record unwritable, the request is refused (503) and never reaches the provider", first === 503 && seen.length === before);
check("11. erehold keeps refusing, and keeps running, once the record has failed", second === 503 && !s3.recordHealthy());
fs.chmodSync(s3.recordFile, 0o600);
await s3.close(0);
fs.rmSync(nwDir, { recursive: true, force: true });

fake.close();
fs.rmSync(recordDir, { recursive: true, force: true });
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
