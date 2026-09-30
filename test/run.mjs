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
import { checkMode, loadMode, modeFromArgs, modeHash, describeMode, modeLocations, checkCeiling, trustOf,
  resolveAllowances, modeFileHashes, unacceptedChanges, reservedInEnvironment } from "../src/mode.mjs";
import { recordEvent } from "../src/session.mjs";

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

// 12. Modes: a declared profile of what a session allows, checked, fixed, and recorded with its hash.
const work12 = fs.mkdtempSync(path.join(os.tmpdir(), "erehold-mode-"));
const home12 = fs.mkdtempSync(path.join(os.tmpdir(), "erehold-home-"));
const managed12 = fs.mkdtempSync(path.join(os.tmpdir(), "erehold-managed-"));
const locs = modeLocations(work12, { home: home12, managedRoot: managed12, managedOwner: process.getuid() });
const refuses = (m) => { try { checkMode(m, work12); return false; } catch { return true; } };
const lock = loadMode("lockdown", work12, locs);
check("12. the lockdown preset loads: sandbox on, nothing allowed beyond the working folder",
  lock.source === "preset:lockdown" && lock.mode.name === "lockdown" && lock.mode.sandbox === true &&
  !lock.mode.allowRead.length && !lock.mode.allowWrite.length && !lock.mode.pass.length);
check("12. a mode missing its format declaration is refused", refuses({ sandbox: true }));
check("12. a mode with an unknown field is refused", refuses({ "erehold-mode": 1, allowNetwork: ["example.com"] }));
check("12. a mode with a wrong type is refused", refuses({ "erehold-mode": 1, sandbox: "yes" }) && refuses({ "erehold-mode": 1, allowRead: "/tmp" }));
check("12. a mode may not pass a variable erehold sets itself", refuses({ "erehold-mode": 1, pass: ["ANTHROPIC_API_KEY"] }));
check("12. a mode may not pass something that is not a variable name", refuses({ "erehold-mode": 1, pass: ["A=B"] }));
const mA = checkMode({ "erehold-mode": 1, name: "a", allowRead: ["x", "y"], pass: ["B", "A"] }, work12);
const mB = checkMode({ "erehold-mode": 1, name: "b", allowRead: ["y", "x"], pass: ["A", "B"] }, work12);
const mC = checkMode({ "erehold-mode": 1, name: "a", allowRead: ["x"], pass: ["A", "B"] }, work12);
check("12. the hash covers what a mode allows, not its name or the order it lists things in", modeHash(mA) === modeHash(mB));
check("12. the hash changes when an allowance changes", modeHash(mA) !== modeHash(mC));
check("12. a missing sandbox field means the sandbox, the stricter choice", checkMode({ "erehold-mode": 1 }, work12).sandbox === true);
check("12. relative folders are resolved against the working folder", mA.allowRead.includes(path.join(work12, "x")));
let frozen = false;
try { "use strict"; mA.allowRead.push("/"); } catch { frozen = true; }
check("12. a checked mode is fixed: it cannot be changed after it is read", frozen && Object.isFrozen(mA));
const fromOpts = modeFromArgs(["--allow-read", "docs", "--pass", "FOO", "--", "cmd", "arg"], work12, locs);
check("12. options build a mode, recorded as coming from options",
  fromOpts.source === "options" && fromOpts.fromOptions && fromOpts.mode.pass[0] === "FOO" && fromOpts.cmd.join(" ") === "cmd arg");
let both = false;
try { modeFromArgs(["--mode", "lockdown", "--pass", "FOO", "--", "cmd"], work12, locs); } catch { both = true; }
check("12. --mode and mode-building options together are refused", both);
const modeFile = path.join(work12, "mine.json");
fs.writeFileSync(modeFile, JSON.stringify({ "erehold-mode": 1, name: "mine", allowWrite: ["out"] }));
const fromFile = modeFromArgs(["--mode", "mine.json", "--", "cmd"], work12, locs);
check("12. a mode file outside the trusted folders is read with project trust, within lockdown",
  fromFile.source === `project:${modeFile}` && fromFile.trust === "project" && fromFile.base?.mode.name === "lockdown" &&
  fromFile.mode.allowWrite[0] === path.join(work12, "out"));
const described = describeMode(fromFile.mode, fromFile.source, { cwd: work12, trust: fromFile.trust, base: fromFile.base, alwaysUnreadable: ["~/.ssh"] });
const s4 = await startSession({ secrets: { anthropic: CANARY_A }, recordDir: work12, recordKey: "k", upstream: { anthropic: UP }, mode: described });
await s4.close(0);
const open4 = JSON.parse(fs.readFileSync(s4.recordFile, "utf8").split("\n")[0]);
check("12. the record's opening line declares the mode: name, source, hash, and every allowance",
  open4.mode?.name === "mine" && open4.mode?.hash === modeHash(fromFile.mode) && open4.mode?.workingFolder === work12 &&
  open4.mode?.allowWrite?.[0] === path.join(work12, "out") && open4.mode?.network === "erehold's relay only" &&
  open4.mode?.alwaysUnreadable?.[0] === "~/.ssh" && open4.mode?.trust === "project" && open4.mode?.within?.name === "lockdown");
check("12. a record with a declared mode still verifies", verifyRecord(s4.recordFile).ok);
const shown = execFileSync(process.execPath, [path.join(ROOT, "bin", "erehold.mjs"), "mode", "lockdown"], { encoding: "utf8" });
check("12. `erehold mode` shows a mode with the hash a session records for it", JSON.parse(shown).hash === modeHash(lock.mode));
// 13. The four locations: managed, user, preset, project, trusted in that order.
const writeMode = (dir, name, body) => { fs.mkdirSync(dir, { recursive: true }); const f = path.join(dir, `${name}.json`); fs.writeFileSync(f, JSON.stringify({ "erehold-mode": 1, name, ...body })); return f; };
const refusesLoad = (ref) => { try { loadMode(ref, work12, locs); return false; } catch { return true; } };
const outside = fs.mkdtempSync(path.join(os.tmpdir(), "erehold-outside-"));
writeMode(locs.user, "research", { allowRead: [outside] });
const research = loadMode("research", work12, locs);
check("13. a mode in the user folder loads with user trust", research.trust === "user" && research.source === "user:research");
writeMode(locs.user, "lockdown", {});
check("13. a name that exists in two places is refused", refusesLoad("lockdown"));
fs.rmSync(path.join(locs.user, "lockdown.json"));
writeMode(locs.project, "wide", { allowRead: [outside] });
check("13. a project mode that allows more than lockdown is refused", refusesLoad("wide"));
writeMode(locs.project, "narrow", { within: "research", allowRead: [outside] });
const narrow = loadMode("narrow", work12, locs);
check("13. a project mode within a user mode that allows the same folder loads, and names its base",
  narrow.trust === "project" && narrow.base?.mode.name === "research" && narrow.base?.trust === "user");
writeMode(locs.project, "open", { within: "research", sandbox: false });
check("13. a project mode cannot turn the sandbox off inside a sandboxed base", refusesLoad("open"));
writeMode(locs.project, "chained", { within: "narrow" });
check("13. a project mode cannot stay within another project mode", refusesLoad("chained"));
writeMode(locs.user, "selfedit", { allowWrite: [locs.ereholdHome] });
check("13. a mode that allows writing where erehold keeps modes or records is refused", refusesLoad("selfedit"));
writeMode(locs.user, "loop-a", { within: "loop-b" });
writeMode(locs.user, "loop-b", { within: "loop-a" });
check("13. modes declared within each other in a loop are refused", refusesLoad("loop-a"));
const target = writeMode(outside, "linked", { allowRead: [outside] });
fs.symlinkSync(target, path.join(locs.user, "linked.json"));
const linked = (() => { try { return loadMode("linked", work12, locs); } catch (e) { return { error: e.message }; } })();
check("13. a link in the user folder to a file elsewhere gets project trust, not user trust",
  trustOf(path.join(locs.user, "linked.json"), locs) === "project" && String(linked.error).includes("allows more than"));
writeMode(locs.managed, "team", { allowRead: [outside] });
fs.chmodSync(locs.managed, 0o777);
check("13. a managed folder anyone can write to is not trusted as managed",
  refusesLoad("team") && trustOf(path.join(locs.managed, "team.json"), locs) === "project");
fs.chmodSync(locs.managed, 0o755);
check("13. a managed folder only its owner can write is trusted as managed", loadMode("team", work12, locs).trust === "managed");
fs.writeFileSync(locs.ceiling, JSON.stringify({ "erehold-mode": 1, name: "ceiling", sandbox: true, allowRead: [outside] }));
const noSandbox = modeFromArgs(["--no-sandbox", "--", "cmd"], work12, locs);
let overCeiling = false;
try { checkCeiling(noSandbox.mode, work12, locs); } catch { overCeiling = true; }
check("13. a mode that allows more than the managed ceiling is refused", overCeiling);
check("13. a mode within the managed ceiling passes, and the ceiling is reported", checkCeiling(research.mode, work12, locs)?.name === "ceiling");
for (const d of [work12, home12, managed12, outside]) fs.rmSync(d, { recursive: true, force: true });

// 14. Three gaps closed: the reserved EREHOLD_ namespace; allowances resolved to real paths at
// the moment of use; mode files changed during a session recorded and refused until accepted.
const work14 = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "erehold-g-work-")));
const home14 = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "erehold-g-home-")));
const managed14 = fs.mkdtempSync(path.join(os.tmpdir(), "erehold-g-managed-"));
const locs14 = modeLocations(work14, { home: home14, managedRoot: managed14, managedOwner: process.getuid() });
const refuses14 = (m) => { try { checkMode(m, work14); return false; } catch { return true; } };
check("14. a mode may not pass an EREHOLD_ variable", refuses14({ "erehold-mode": 1, pass: ["EREHOLD_HOME"] }));
check("14. EREHOLD_ variables in erehold's own environment are found, and nothing else is",
  reservedInEnvironment({ EREHOLD_MODE: "x", PATH: "/bin", NOT_EREHOLD_X: "y" }).join() === "EREHOLD_MODE");

const realA = fs.mkdtempSync(path.join(os.tmpdir(), "erehold-g-A-"));
fs.symlinkSync(realA, path.join(work14, "link-to-A"));
const viaLink = checkMode({ "erehold-mode": 1, allowRead: ["link-to-A"] }, work14);
const resolvedA = resolveAllowances(viaLink, work14, locs14);
check("14. an allowed folder reached through a link is resolved to the real folder the sandbox is given",
  resolvedA.allowRead[0] === fs.realpathSync(realA) && resolvedA.cwd === work14);
let missing = false;
try { resolveAllowances(checkMode({ "erehold-mode": 1, allowRead: ["no-such-folder"] }, work14), work14, locs14); } catch { missing = true; }
check("14. an allowed folder that does not exist at launch is refused", missing);
fs.mkdirSync(locs14.ereholdHome, { recursive: true });
let insideHome = false;
try { resolveAllowances(checkMode({ "erehold-mode": 1 }, locs14.ereholdHome), locs14.ereholdHome, locs14); } catch { insideHome = true; }
let aboveHome = false;
try { resolveAllowances(checkMode({ "erehold-mode": 1 }, home14), home14, locs14); } catch { aboveHome = true; }
check("14. running from inside erehold's own folder, or from a folder that contains it, is refused", insideHome && aboveHome);

fs.mkdirSync(locs14.user, { recursive: true });
const userMode = path.join(locs14.user, "work.json");
fs.writeFileSync(userMode, JSON.stringify({ "erehold-mode": 1, name: "work" }));
const ledger14 = path.join(home14, "ledger.jsonl");
fs.writeFileSync(ledger14, "");
const s5 = await startSession({ secrets: { anthropic: CANARY_A }, recordDir: work14, recordKey: "k", upstream: { anthropic: UP },
  ledgerFile: ledger14, watch: () => modeFileHashes(locs14) });
fs.writeFileSync(userMode, JSON.stringify({ "erehold-mode": 1, name: "work", sandbox: false }));
const changed = await s5.close(0);
const close5 = JSON.parse(fs.readFileSync(s5.recordFile, "utf8").trim().split("\n").at(-1));
check("14. a mode file changed during a session is reported at close and written into the closing line",
  changed.length === 1 && close5.modesChanged?.[0]?.file === fs.realpathSync(userMode) && verifyRecord(s5.recordFile).ok);
locs14.pending = unacceptedChanges(ledger14);
let refusedChanged = false;
try { loadMode("work", work14, locs14); } catch (e) { refusedChanged = e.message.includes("accept-mode"); }
check("14. that changed mode is refused until it is accepted", refusedChanged);
const originalText = JSON.stringify({ "erehold-mode": 1, name: "work" });
fs.writeFileSync(userMode, originalText);
check("14. restoring the file to what it was before the session lifts the refusal", loadMode("work", work14, locs14).mode.sandbox === true);
fs.writeFileSync(userMode, JSON.stringify({ "erehold-mode": 1, name: "work", sandbox: false }));
recordEvent({ recordDir: work14, ledgerFile: ledger14, entry: { event: "accept-mode", file: fs.realpathSync(userMode), fileHash: "x" } });
locs14.pending = unacceptedChanges(ledger14);
check("14. once accepted, with the acceptance in the ledger, the changed mode loads", loadMode("work", work14, locs14).mode.sandbox === false);
check("14. the acceptance line is in the ledger", fs.readFileSync(ledger14, "utf8").includes('"event":"accept-mode"'));
for (const d of [work14, home14, managed14, realA]) fs.rmSync(d, { recursive: true, force: true });

fake.close();
fs.rmSync(recordDir, { recursive: true, force: true });
console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
