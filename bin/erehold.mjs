#!/usr/bin/env node
// erehold command-line tool. See SPEC.md.
//
//   erehold add <anthropic|openai>        store a provider key in the macOS keychain (hidden prompt)
//   erehold run [--pass VAR]... -- <cmd>  run a command with stand-ins in place of the keys
//   erehold verify <record.jsonl>         check a session record's chain

import { spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { startSession, verifyRecord, PROVIDERS, HOLDER_LEVEL } from "../src/session.mjs";

const SERVICE = "erehold";
const HOME = path.join(os.homedir(), ".erehold");
const RECORDS = path.join(HOME, "records");
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

async function run(args) {
  const pass = [];
  let i = 0;
  for (; i < args.length && args[i] !== "--"; i++) {
    if (args[i] === "--pass" && args[i + 1]) pass.push(args[++i]);
    else { say(`unknown option ${args[i]}`); process.exit(2); }
  }
  const cmd = args.slice(i + 1);
  if (!cmd.length) { say("usage: erehold run [--pass VAR]... -- <command> [args...]"); process.exit(2); }
  const blocked = pass.filter((v) => Object.values(PROVIDERS).some((s) => s.envKey === v || s.envBase === v));
  if (blocked.length) { say(`refusing to pass ${blocked.join(", ")}: erehold sets these itself`); process.exit(2); }

  const secrets = {};
  for (const p of Object.keys(PROVIDERS)) { const v = keychainRead(p); if (v) secrets[p] = v; }
  if (!Object.keys(secrets).length) { say("no keys stored; run `erehold add anthropic` or `erehold add openai` first"); process.exit(1); }

  const session = await startSession({ secrets, recordDir: RECORDS, recordKey: recordKey() });
  say(`session ${session.id}: ${Object.keys(secrets).join(", ")} via stand-ins`);
  say(`holder ${HOLDER_LEVEL}`);
  say(`record ${session.recordFile}`);

  const child = spawn(cmd[0], cmd.slice(1), { stdio: "inherit", env: session.childEnv(process.env, pass) });
  const forward = (sig) => child.kill(sig);
  process.on("SIGINT", forward);
  process.on("SIGTERM", forward);
  child.on("error", async (e) => { say(`could not start ${cmd[0]}: ${e.message}`); await session.close(null); process.exit(127); });
  child.on("exit", async (code, signal) => {
    await session.close(code ?? signal);
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

function verify(file) {
  if (!file || !fs.existsSync(file)) { say("usage: erehold verify <record.jsonl>"); process.exit(2); }
  const r = verifyRecord(file);
  if (r.ok) { say(`record intact: ${r.lines} lines, chain verified`); process.exit(0); }
  say(`record FAILED verification: ${r.error}`);
  process.exit(1);
}

const [cmd, ...rest] = process.argv.slice(2);
if (cmd === "run") await run(rest);
else if (cmd === "add") add(rest[0]);
else if (cmd === "verify") verify(rest[0]);
else {
  process.stderr.write("usage:\n  erehold add <anthropic|openai>\n  erehold run [--pass VAR]... -- <command> [args...]\n  erehold verify <record.jsonl>\n");
  process.exit(cmd ? 2 : 0);
}
