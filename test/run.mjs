// erehold v0 tests: one per "Done when" check in SPEC.md. Harmless fake keys and a fake
// provider on 127.0.0.1, so every run is repeatable and nothing leaves the machine.
// Run: node test/run.mjs

import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { startSession, verifyRecord } from "../src/session.mjs";
import { keysFromEnvFile } from "../src/envfile.mjs";

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const CANARY_A = "sk-ant-FAKE-canary-7f3e9a1c5b2d4e6f8a0b";
const CANARY_O = "sk-FAKE-openai-canary-2c4e6a8b0d1f3e5a7c9b";

let passed = 0, failed = 0;
const check = (name, ok) => { ok ? passed++ : failed++; console.log(`${ok ? "PASS" : "FAIL"}  ${name}`); };

// Fake provider: records the credentials it receives, answers "ok", never echoes a key.
const seen = [];
const fake = http.createServer((req, res) => {
  seen.push({ path: req.url, xApiKey: req.headers["x-api-key"] ?? null, auth: req.headers["authorization"] ?? null });
  req.resume();
  req.on("end", () => { res.writeHead(200, { "content-type": "application/json" }); res.end('{"reply":"ok"}'); });
});
await new Promise((r) => fake.listen(0, "127.0.0.1", r));
const UP = `http://127.0.0.1:${fake.address().port}`;

const recordDir = fs.mkdtempSync(path.join(os.tmpdir(), "erehold-test-"));
const session = await startSession({
  secrets: { anthropic: CANARY_A, openai: CANARY_O },
  keyNames: { anthropic: "test-anthropic", openai: "test-openai" },
  recordDir, recordKey: "test-record-key", upstream: { anthropic: UP, openai: UP },
});

// A child program sees only what erehold gives it. It prints its environment and arguments,
// then makes the same calls an SDK would, using only what is in its environment.
const childScript = `
  const out = { env: process.env, argv: process.argv, results: {} };
  const A = process.env.ANTHROPIC_BASE_URL, O = process.env.OPENAI_BASE_URL;
  const post = (u, h) => fetch(u, { method: "POST", headers: { "content-type": "application/json", ...h }, body: "{}" })
    .then(async r => ({ status: r.status, body: await r.text() }));
  out.results.anthropicGood = await post(A + "/v1/messages", { "x-api-key": process.env.ANTHROPIC_API_KEY });
  out.results.openaiGood = await post(O + "/chat/completions", { authorization: "Bearer " + process.env.OPENAI_API_KEY });
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
  !childOut.includes(CANARY_A) && !childOut.includes(CANARY_O));
check("1. the child holds stand-ins, not keys",
  child.env?.ANTHROPIC_API_KEY?.startsWith("erehold-standin-anthropic-") && child.env?.OPENAI_API_KEY?.startsWith("erehold-standin-openai-"));

// 2. A secret in erehold's own environment does not reach the child.
check("2. a secret set in erehold's environment does not reach the child", child.env && !("FAKE_PARENT_SECRET" in child.env));

// 3. The session stand-in reaches the provider as the real key.
const hits = seen.filter((s) => s.path === "/v1/messages" || s.path === "/v1/chat/completions");
check("3. anthropic: the provider receives the real key", res.anthropicGood?.status === 200 && hits.some((s) => s.xApiKey === CANARY_A));
check("3. openai: the provider receives the real key", res.openaiGood?.status === 200 && hits.some((s) => s.auth === `Bearer ${CANARY_O}`));
check("3. the provider never receives a stand-in", !seen.some((s) => String(s.xApiKey ?? s.auth ?? "").includes("erehold-standin")));

// 4. Any other value is refused and never forwarded.
check("4. a wrong value is refused (403)", res.anthropicWrong?.status === 403);
check("4. a missing value is refused (403)", res.anthropicNone?.status === 403);
check("4. refused requests never reach the provider", seen.length === 2);

// 5. An unknown provider path is refused.
check("5. an unknown provider path is refused (404)", res.unknownProvider?.status === 404);

// 7. After the session closes, the stand-in no longer works.
const standinA = child.env?.ANTHROPIC_API_KEY;
const baseA = child.env?.ANTHROPIC_BASE_URL;
await session.close(0);
let afterClose;
try { afterClose = (await fetch(baseA + "/v1/messages", { method: "POST", headers: { "x-api-key": standinA }, body: "{}" })).status; }
catch { afterClose = "connection refused"; }
check("7. after close, the stand-in no longer works", afterClose !== 200 && seen.length === 2);

// 6. One record line per request, no key in the record, and the chain catches tampering.
const recText = fs.readFileSync(session.recordFile, "utf8");
const lines = recText.split("\n").filter(Boolean).map((l) => JSON.parse(l));
const requests = lines.filter((l) => l.event === "request");
check("6. one record line per request (5 requests)", requests.length === 5);
check("6. forwarded requests are recorded with key name and fingerprint",
  requests.filter((l) => l.outcome === "forwarded").every((l) => l.key && /^[0-9a-f]{32}$/.test(l.fingerprint)));
check("6. the record never contains a key or a stand-in",
  !recText.includes(CANARY_A) && !recText.includes(CANARY_O) && !recText.includes("erehold-standin"));
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
].join("\n");
const fromEnv = keysFromEnvFile(envText);
check("9. .env import reads both provider keys, quoted or not, and nothing else",
  fromEnv.anthropic === CANARY_A && fromEnv.openai === CANARY_O && Object.keys(fromEnv).length === 2);

fake.close();
fs.rmSync(recordDir, { recursive: true, force: true });
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
