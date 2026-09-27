// erehold sandbox tests: run a real command inside srt through a real session, with a fake
// provider, and check what the command can and cannot reach. Skipped when srt is not installed.
// Run: node test/sandbox.mjs

import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFile } from "node:child_process";
import { startSession } from "../src/session.mjs";
import { sandboxAvailable, sandboxCommand, SANDBOXED_LEVEL } from "../src/sandbox.mjs";

if (!sandboxAvailable()) { console.log("SKIP  sandbox tests: srt is not installed"); process.exit(0); }

let passed = 0, failed = 0;
const check = (name, ok) => { ok ? passed++ : failed++; console.log(`${ok ? "PASS" : "FAIL"}  ${name}`); };
const CANARY = "sk-ant-FAKE-sandbox-canary-4b6d8f0a2c4e";

const seen = [];
const fake = http.createServer((req, res) => { seen.push(req.headers["x-api-key"] ?? null); req.resume(); req.on("end", () => res.end('{"reply":"ok"}')); });
const other = http.createServer((req, res) => res.end("OTHER-LOCAL-SERVICE"));
await new Promise((r) => fake.listen(0, "127.0.0.1", r));
await new Promise((r) => other.listen(0, "127.0.0.1", r));

// A secret-looking file in erehold's own folder, and a .env inside the working folder.
const ereholdDir = path.join(os.homedir(), ".erehold");
fs.mkdirSync(ereholdDir, { recursive: true, mode: 0o700 });
const homeCanary = path.join(ereholdDir, "sandbox-test-canary");
fs.writeFileSync(homeCanary, "HOME-CANARY-SECRET", { mode: 0o600 });
const work = fs.mkdtempSync(path.join(os.tmpdir(), "erehold-work-"));
fs.writeFileSync(path.join(work, ".env"), "WORK_ENV_SECRET=do-not-read");
fs.writeFileSync(path.join(work, "notes.txt"), "ordinary file");
const outsideWrite = path.join(ereholdDir, "sandbox-test-written");

const recordDir = fs.mkdtempSync(path.join(os.tmpdir(), "erehold-sbx-rec-"));
const session = await startSession({
  secrets: { anthropic: CANARY }, recordDir, recordKey: "k",
  upstream: { anthropic: `http://127.0.0.1:${fake.address().port}` }, holder: SANDBOXED_LEVEL,
});

const script = `
  const fs = require("fs");
  const tryRead = (p) => { try { return fs.readFileSync(p, "utf8"); } catch (e) { return "DENIED:" + e.code; } };
  const tryWrite = (p) => { try { fs.writeFileSync(p, "x"); return "WROTE"; } catch (e) { return "DENIED:" + e.code; } };
  const get = (u, h) => fetch(u, { method: "POST", headers: h, body: "{}" }).then(r => r.status + ":" + "ok", e => "FAIL:" + (e.cause?.code || e.message));
  (async () => {
    const out = {};
    out.relay = await get(process.env.ANTHROPIC_BASE_URL + "/v1/messages", { "x-api-key": process.env.ANTHROPIC_API_KEY });
    out.otherLocal = await fetch("http://127.0.0.1:${other.address().port}/").then(r => r.text(), e => "FAIL");
    out.outside = await fetch("https://example.com/").then(r => "REACHED:" + r.status, e => "FAIL");
    out.homeCanary = tryRead(${JSON.stringify(homeCanary)});
    out.workEnv = tryRead(".env");
    out.workFile = tryRead("notes.txt");
    out.writeWork = tryWrite("made-inside.txt");
    out.writeOutside = tryWrite(${JSON.stringify(outsideWrite)});
    console.log(JSON.stringify(out));
  })();
`;
const sbx = sandboxCommand({ port: session.port, cwd: work, cmd: ["node", "-e", script] });
const r = await new Promise((resolve) => execFile("srt", sbx.argv, { cwd: work, env: session.childEnv(process.env), encoding: "utf8", timeout: 60000 },
  (err, stdout, stderr) => resolve({ stdout, stderr })));
let out = {};
try { out = JSON.parse(r.stdout.trim().split("\n").pop()); } catch { console.log(r.stdout, r.stderr); }

check("S1. the sandboxed command reaches erehold's relay, and the provider gets the real key", out.relay === "200:ok" && seen.includes(CANARY));
check("S2. it cannot reach another service on this machine", out.otherLocal === "FAIL");
check("S3. it cannot reach the internet directly", out.outside === "FAIL");
check("S4. it cannot read a file in your home folder outside the working folder", String(out.homeCanary).startsWith("DENIED"));
check("S5. it cannot read a .env file, even inside the working folder", String(out.workEnv).startsWith("DENIED"));
check("S6. it can read ordinary files in the working folder", out.workFile === "ordinary file");
check("S7. it can write in the working folder", out.writeWork === "WROTE" && fs.existsSync(path.join(work, "made-inside.txt")));
check("S8. it cannot write outside the working folder", String(out.writeOutside).startsWith("DENIED") && !fs.existsSync(outsideWrite));
check("S9. the record declares the sandboxed holder level",
  JSON.parse(fs.readFileSync(session.recordFile, "utf8").split("\n")[0]).holder === SANDBOXED_LEVEL);

await session.close(0);
sbx.cleanup();
fake.close(); other.close();
for (const p of [homeCanary, outsideWrite]) fs.rmSync(p, { force: true });
fs.rmSync(work, { recursive: true, force: true });
fs.rmSync(recordDir, { recursive: true, force: true });
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
