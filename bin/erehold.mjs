#!/usr/bin/env node
// erehold command-line tool. See SPEC.md.
//
//   erehold add <anthropic|openai|gemini> store a provider key in the macOS keychain (hidden prompt)
//   erehold import <path/to/.env>         copy provider keys from a .env file into the keychain
//   erehold run [options] -- <cmd>        run a command with stand-ins in place of the keys
//        --mode NAME|FILE     run under a declared mode (a preset name, or a mode file)
//        or, to build a mode from options:
//        --pass VAR           let one more environment variable through to the command
//        --allow-read PATH    let the sandboxed command read one more folder
//        --allow-write PATH   let the sandboxed command write one more folder
//        --no-sandbox         run without the sandbox (holder level 2 instead of 3)
//   erehold mode <NAME|FILE>              show a mode as erehold reads it, with its hash
//   erehold accept-mode <FILE|NAME>       accept a mode file that changed during a session
//   erehold verify <record.jsonl>         check a session record's chain, and compare it with the ledger
//   erehold protect                       lock the shared ledger so it can only be added to

import { spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { startSession, recordEvent, verifyRecord, crossCheckLedger, ledgerProtection, PROVIDERS, HOLDER_LEVEL } from "../src/session.mjs";
import { keysFromEnvFile } from "../src/envfile.mjs";
import { sandboxAvailable, sandboxCommand, SANDBOXED_LEVEL, ALWAYS_DENY_READ } from "../src/sandbox.mjs";
import { modeFromArgs, loadMode, checkMode, checkCeiling, modeHash, modeLocations, describeMode, resolveAllowances,
  modeFileHashes, unacceptedChanges, reservedInEnvironment, RESERVED_PREFIX, trustOf } from "../src/mode.mjs";

const SERVICE = "erehold";
const HOME = path.join(os.homedir(), ".erehold");
const RECORDS = path.join(HOME, "records");
const LEDGER = path.join(HOME, "ledger.jsonl");
const PROTECTION = {
  system: "the ledger is locked: code running as you can add to it but never rewrite or delete it",
  user: "the ledger has only the owner's append-only flag, which code running as you can clear; run `erehold protect`",
  none: "the ledger is not locked, so code running as you could rewrite it; run `erehold protect`",
};
const say = (m) => process.stderr.write(`erehold: ${m}\n`);

function keychainRead(provider) {
  const r = spawnSync("security", ["find-generic-password", "-s", SERVICE, "-a", provider, "-w"], { encoding: "utf8" });
  return r.status === 0 ? r.stdout.replace(/\n$/, "") : null;
}

// The record key signs the fingerprints in session records. It lives in a file only you can read.
function recordKey() {
  const f = path.join(HOME, "record.key");
  if (!fs.existsSync(f)) {
    fs.mkdirSync(HOME, { recursive: true, mode: 0o700 });
    fs.writeFileSync(f, crypto.randomBytes(32).toString("hex"), { mode: 0o600 });
  }
  return fs.readFileSync(f, "utf8").trim();
}

const USAGE_RUN = "usage: erehold run [--mode NAME|FILE | --pass VAR --allow-read PATH --allow-write PATH --no-sandbox] -- <command> [args...]";

async function run(args) {
  const cwd = process.cwd();
  const reserved = reservedInEnvironment(process.env);
  if (reserved.length) { say(`${reserved.join(", ")} set in the environment; erehold takes no settings from environment variables and the ${RESERVED_PREFIX} names are reserved, so nothing was started`); process.exit(2); }
  const locations = modeLocations(cwd);
  // Mode files changed during an earlier session are refused until the person accepts them.
  locations.pending = unacceptedChanges(LEDGER);
  let declared;
  try { declared = modeFromArgs(args, cwd, locations); } catch (e) { say(`${e.message}`); say(USAGE_RUN); process.exit(2); }
  let { mode } = declared;
  const { source, trust, base, cmd, fromOptions } = declared;
  if (!cmd.length) { say(USAGE_RUN); process.exit(2); }
  if (mode.sandbox && !sandboxAvailable()) {
    const install = "install it with: npm install -g @anthropic-ai/sandbox-runtime";
    // A declared mode that needs the sandbox cannot be honored without it, so nothing starts.
    if (!fromOptions) { say(`the mode "${mode.name}" runs the command in the sandbox, and the sandbox runtime (srt) is not installed; nothing was started. ${install}`); process.exit(1); }
    say(`the sandbox runtime (srt) is not installed, so the command runs without it; ${install}`);
    mode = checkMode({ "erehold-mode": 1, name: mode.name, sandbox: false, allowRead: mode.allowRead, allowWrite: mode.allowWrite, pass: mode.pass }, cwd);
  }
  // Checked after any fallback, so the mode that actually runs is the one held to the ceiling.
  let ceiling;
  try { ceiling = checkCeiling(mode, cwd, locations); } catch (e) { say(`${e.message}; nothing was started`); process.exit(1); }
  const useSandbox = mode.sandbox;
  // Resolve every folder to its real path at the moment of use, and check them again there.
  let resolved;
  try { resolved = resolveAllowances(mode, cwd, locations); } catch (e) { say(`${e.message}; nothing was started`); process.exit(1); }

  const secrets = {};
  for (const p of Object.keys(PROVIDERS)) { const v = keychainRead(p); if (v) secrets[p] = v; }
  if (!Object.keys(secrets).length) { say(`no keys stored; run \`erehold add <${Object.keys(PROVIDERS).join("|")}>\` or \`erehold import <.env>\` first`); process.exit(1); }

  const holder = useSandbox ? SANDBOXED_LEVEL : HOLDER_LEVEL;
  if (!fs.existsSync(LEDGER)) { fs.mkdirSync(HOME, { recursive: true, mode: 0o700 }); fs.writeFileSync(LEDGER, "", { mode: 0o600 }); }
  const described = describeMode(mode, source, { cwd, trust, base, ceiling, resolved, alwaysUnreadable: [os.homedir(), ...ALWAYS_DENY_READ] });
  const session = await startSession({ secrets, recordDir: RECORDS, recordKey: recordKey(), holder, ledgerFile: LEDGER, mode: described, watch: () => modeFileHashes(locations) });
  say(`session ${session.id}: ${Object.keys(secrets).join(", ")} via stand-ins`);
  say(`mode ${mode.name} (${source}), hash ${described.hash.slice(0, 16)}${base ? `, within ${base.mode.name}` : ""}${ceiling ? `, under the managed ceiling` : ""}`);
  say(`holder ${holder}`);
  say(`record ${session.recordFile}`);
  say(PROTECTION[ledgerProtection(LEDGER)]);

  let launch = [cmd[0], cmd.slice(1)], sandbox = null;
  if (useSandbox) {
    sandbox = sandboxCommand({ port: session.port, cwd: resolved.cwd, cmd, allowRead: [...resolved.allowRead], allowWrite: [...resolved.allowWrite] });
    launch = ["srt", sandbox.argv];
  }
  const child = spawn(launch[0], launch[1], { stdio: "inherit", env: session.childEnv(process.env, [...mode.pass]) });
  const forward = (sig) => child.kill(sig);
  process.on("SIGINT", forward);
  process.on("SIGTERM", forward);
  const reportChanges = (changed) => {
    for (const c of changed) say(`WARNING: ${c.file} was ${c.after === null ? "deleted" : c.before === null ? "created" : "changed"} while the session was open; it is on the record and will be refused until you review and accept it with: erehold accept-mode "${c.file}"`);
  };
  child.on("error", async (e) => { say(`could not start ${launch[0]}: ${e.message}`); sandbox?.cleanup(); reportChanges(await session.close(null)); process.exit(127); });
  child.on("exit", async (code, signal) => {
    sandbox?.cleanup();
    reportChanges(await session.close(code ?? signal));
    say(`session closed; check the record with: erehold verify "${session.recordFile}"`);
    process.exit(code ?? 1);
  });
}

function add(provider) {
  if (!PROVIDERS[provider]) { say(`unknown provider "${provider}"; use one of: ${Object.keys(PROVIDERS).join(", ")}`); process.exit(2); }
  say(`paste the ${provider} key at the hidden prompt (it is asked twice)`);
  const r = spawnSync("security", ["add-generic-password", "-U", "-s", SERVICE, "-a", provider, "-w"], { stdio: "inherit" });
  if (r.status !== 0) { say("the keychain did not store the key"); process.exit(1); }
  say(`${provider} key stored in the keychain under service "${SERVICE}"`);
}

// Store a key without it ever appearing in a command line: the keychain tool reads the
// command from standard input, so no other program can see the value in a process listing.
function keychainWrite(provider, value) {
  if (!/^[A-Za-z0-9_\-.]+$/.test(value)) return false;
  const r = spawnSync("security", ["-i"], {
    input: `add-generic-password -U -s ${SERVICE} -a ${provider} -w ${value}\n`, encoding: "utf8",
  });
  return r.status === 0 && keychainRead(provider) === value;
}

function importEnv(file) {
  if (!file || !fs.existsSync(file)) { say("usage: erehold import <path/to/.env>"); process.exit(2); }
  const { found, unsupported } = keysFromEnvFile(fs.readFileSync(file, "utf8"));
  for (const name of unsupported) say(`${name}: skipped; erehold does not handle this key yet, so it stays only in the file`);
  if (!Object.keys(found).length) { say(`no provider keys found in ${file} (looked for ${Object.values(PROVIDERS).map((s) => s.envKey).join(", ")})`); process.exit(1); }
  for (const [p, value] of Object.entries(found)) {
    if (keychainWrite(p, value)) say(`${PROVIDERS[p].envKey}: stored in the keychain as "${p}"`);
    else say(`${PROVIDERS[p].envKey}: NOT stored (unexpected characters, or the keychain refused); use \`erehold add ${p}\``);
  }
  say(`${file} was not changed and still holds these keys in plain text; any program running as you can read it`);
}

// Show a mode as erehold reads it: normalized, with the hash a session records for it.
function showMode(ref) {
  if (!ref) { say("usage: erehold mode <preset name | mode file>"); process.exit(2); }
  let loaded;
  try { loaded = loadMode(ref, process.cwd()); } catch (e) { say(e.message); process.exit(2); }
  const within = loaded.base ? { name: loaded.base.mode.name, source: loaded.base.source, hash: modeHash(loaded.base.mode) } : null;
  process.stdout.write(JSON.stringify({ ...loaded.mode, source: loaded.source, trust: loaded.trust, within, hash: modeHash(loaded.mode) }, null, 2) + "\n");
  process.exit(0);
}

// Accept a mode file that changed during a session: show it as erehold reads it, then record
// the acceptance, with the file's current hash, in the ledger. Only a changed file that is
// still pending can be accepted, and the acceptance is itself on the record.
function acceptMode(ref) {
  if (!ref) { say("usage: erehold accept-mode <mode file path or name>"); process.exit(2); }
  const cwd = process.cwd();
  const locations = modeLocations(cwd);
  let file = path.resolve(cwd, ref);
  if (!fs.existsSync(file)) {
    for (const dir of [locations.user, locations.managed]) {
      const f = path.join(dir, `${ref}.json`);
      if (fs.existsSync(f)) { file = f; break; }
    }
  }
  const pending = unacceptedChanges(LEDGER);
  const key = fs.existsSync(file) ? fs.realpathSync(file) : file;
  if (!(key in pending)) { say(`${file} has no change awaiting acceptance`); process.exit(1); }
  let hash = null;
  if (fs.existsSync(file)) {
    const text = fs.readFileSync(file, "utf8");
    let written;
    try { written = JSON.parse(text); } catch { say(`${file} is not valid JSON; fix it before accepting`); process.exit(1); }
    let mode;
    try { mode = checkMode(written, cwd); } catch (e) { say(`${file}: ${e.message}; fix it before accepting`); process.exit(1); }
    hash = crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
    process.stdout.write(JSON.stringify({ file: key, trust: trustOf(file, locations), ...mode, hash: modeHash(mode) }, null, 2) + "\n");
  } else {
    say(`${file} was deleted during a session; accepting records the deletion`);
  }
  if (!fs.existsSync(LEDGER)) { say("there is no ledger to record the acceptance in"); process.exit(1); }
  try { recordEvent({ recordDir: RECORDS, ledgerFile: LEDGER, entry: { event: "accept-mode", file: key, fileHash: hash } }); }
  catch (e) { say(`the acceptance could not be recorded (${e.message}); nothing changed`); process.exit(1); }
  say(`accepted ${key}; the acceptance is in the ledger`);
  process.exit(0);
}

function verify(file) {
  if (!file || !fs.existsSync(file)) { say("usage: erehold verify <record.jsonl>"); process.exit(2); }
  const r = verifyRecord(file);
  if (!r.ok) { say(`record FAILED verification: ${r.error}`); process.exit(1); }
  say(`record intact: ${r.lines} lines, chain verified`);
  const opening = JSON.parse(fs.readFileSync(file, "utf8").split("\n")[0]);
  if (opening.mode) say(`ran under mode ${opening.mode.name} (${opening.mode.source}), hash ${opening.mode.hash}`);
  else say("the record does not declare a mode (written before erehold 0.4)");
  if (!fs.existsSync(LEDGER)) { say("no ledger to compare with"); process.exit(0); }
  const c = crossCheckLedger(file, LEDGER);
  if (!c.ok) { say(`record DIFFERS from the ledger: ${c.error}`); process.exit(1); }
  say(`record matches the ledger; ${PROTECTION[ledgerProtection(LEDGER)]}`);
  process.exit(0);
}

function protect() {
  if (!fs.existsSync(LEDGER)) { fs.mkdirSync(HOME, { recursive: true, mode: 0o700 }); fs.writeFileSync(LEDGER, "", { mode: 0o600 }); }
  const p = ledgerProtection(LEDGER);
  if (p === "system") { say(PROTECTION.system); process.exit(0); }
  say("to lock the ledger so it can only be added to, run this once (it asks for your Mac password):");
  process.stdout.write(`sudo chflags sappnd "${LEDGER}"\n`);
  say("undoing it later also needs administrator rights: sudo chflags nosappnd <ledger>");
  process.exit(1);
}

const [cmd, ...rest] = process.argv.slice(2);
if (cmd === "run") await run(rest);
else if (cmd === "add") add(rest[0]);
else if (cmd === "import") importEnv(rest[0]);
else if (cmd === "mode") showMode(rest[0]);
else if (cmd === "accept-mode") acceptMode(rest[0]);
else if (cmd === "verify") verify(rest[0]);
else if (cmd === "protect") protect();
else {
  process.stderr.write(`usage:\n  erehold add <${Object.keys(PROVIDERS).join("|")}>\n  erehold import <path/to/.env>\n  erehold run [--mode NAME|FILE | --pass VAR --allow-read PATH --allow-write PATH --no-sandbox] -- <command> [args...]\n  erehold mode <NAME|FILE>\n  erehold accept-mode <FILE|NAME>\n  erehold verify <record.jsonl>\n  erehold protect\n`);
  process.exit(cmd ? 2 : 0);
}
