// erehold modes. A mode is a short declared profile of what a session allows: whether the
// command runs in the sandbox, which extra folders it may read and write, and which extra
// environment variables pass through. It is read once when the session starts, fixed for the
// session, and written with its hash into the record's opening line. See SPEC.md, "Modes".
//
// Where a mode file lives decides how far it is trusted. Four locations, most trusted first:
//   managed  set by an administrator, in a folder only an administrator can change; may also
//            hold a ceiling that every session's mode must stay within
//   user     your own modes, in ~/.erehold/modes, which the sandboxed command can neither read
//            nor write
//   preset   modes shipped with erehold
//   project  anywhere else, including a project's own .erehold/modes folder. A project mode can
//            only tighten: it must stay within a mode from a trusted location, so a file the
//            agent or a dependency could write never loosens what a session allows.
// Built-in modules only.

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { PROVIDERS } from "./session.mjs";

export const MODE_FORMAT = 1;
const FIELDS = new Set(["erehold-mode", "name", "within", "sandbox", "allowRead", "allowWrite", "pass"]);
const NAME = /^[a-z0-9][a-z0-9-]*$/;
const PRESETS = path.join(path.dirname(path.dirname(fileURLToPath(import.meta.url))), "modes");
const TRUSTED = ["managed", "user", "preset"];

// Variables erehold sets itself. No mode may pass them through.
export const RESERVED_VARS = Object.values(PROVIDERS).flatMap((s) => [s.envKey, s.envBase, ...(s.alsoEnvKeys ?? [])]);

// erehold takes no settings from environment variables, so nothing a repository sets (a .env
// file, direnv) can steer it or move its folders. The whole EREHOLD_ namespace is reserved:
// such a variable in erehold's environment stops a session, and no mode may pass one through.
export const RESERVED_PREFIX = "EREHOLD_";
export function reservedInEnvironment(env) {
  return Object.keys(env).filter((k) => k.startsWith(RESERVED_PREFIX));
}

// The four locations. `managedOwner` is the user id a managed folder must belong to (the
// administrator, 0); the tests set it to their own id, since they cannot create such a folder.
export function modeLocations(cwd, { home = os.homedir(), managedRoot = "/Library/Application Support/erehold", managedOwner = 0 } = {}) {
  return {
    managed: path.join(managedRoot, "modes"),
    ceiling: path.join(managedRoot, "ceiling.json"),
    managedOwner,
    user: path.join(home, ".erehold", "modes"),
    ereholdHome: path.join(home, ".erehold"),
    preset: PRESETS,
    project: path.join(cwd, ".erehold", "modes"),
  };
}

const sortedUnique = (xs) => [...new Set(xs)].sort();
const real = (p) => { try { return fs.realpathSync(p); } catch { return path.resolve(p); } };
const inside = (p, dir) => p === dir || p.startsWith(dir.endsWith(path.sep) ? dir : dir + path.sep);

function strings(value, field) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || !value.every((v) => typeof v === "string" && v.length)) {
    throw new Error(`"${field}" must be a list of non-empty strings`);
  }
  return value;
}

// A managed folder counts only if an administrator owns it and nobody else can write to it.
function managedIsGenuine(locations) {
  try {
    const st = fs.statSync(locations.managed);
    return st.isDirectory() && st.uid === locations.managedOwner && (st.mode & 0o022) === 0;
  } catch { return false; }
}

// Which location a file is in. Anything outside the three trusted folders is project trust.
export function trustOf(file, locations) {
  const f = real(file);
  if (managedIsGenuine(locations) && inside(f, real(locations.managed))) return "managed";
  if (fs.existsSync(locations.user) && inside(f, real(locations.user))) return "user";
  if (inside(f, real(locations.preset))) return "preset";
  return "project";
}

// Check a mode as written and return it normalized and frozen. Refuses rather than guesses: an
// unknown field, a wrong type, or a variable erehold sets itself stops the session from starting.
// A missing allowance is the empty allowance; a missing "sandbox" is true, the stricter choice.
// Relative folders are resolved against the working folder.
export function checkMode(written, cwd) {
  if (!written || typeof written !== "object" || Array.isArray(written)) throw new Error("a mode must be a JSON object");
  if (written["erehold-mode"] !== MODE_FORMAT) throw new Error(`a mode must declare "erehold-mode": ${MODE_FORMAT}`);
  for (const k of Object.keys(written)) if (!FIELDS.has(k)) throw new Error(`unknown field "${k}"`);
  if (written.name !== undefined && (typeof written.name !== "string" || !written.name.length)) throw new Error(`"name" must be a non-empty string`);
  if (written.within !== undefined && (typeof written.within !== "string" || !NAME.test(written.within))) throw new Error(`"within" must be the name of a mode`);
  if (written.sandbox !== undefined && typeof written.sandbox !== "boolean") throw new Error(`"sandbox" must be true or false`);
  const pass = strings(written.pass, "pass");
  for (const v of pass) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(v)) throw new Error(`"${v}" is not an environment variable name`);
    if (RESERVED_VARS.includes(v)) throw new Error(`"${v}" cannot be passed: erehold sets it itself`);
    if (v.startsWith(RESERVED_PREFIX)) throw new Error(`"${v}" cannot be passed: names starting with ${RESERVED_PREFIX} are reserved for erehold`);
  }
  return Object.freeze({
    name: written.name ?? "unnamed",
    within: written.within ?? null,
    sandbox: written.sandbox ?? true,
    allowRead: Object.freeze(sortedUnique(strings(written.allowRead, "allowRead").map((p) => path.resolve(cwd, p)))),
    allowWrite: Object.freeze(sortedUnique(strings(written.allowWrite, "allowWrite").map((p) => path.resolve(cwd, p)))),
    pass: Object.freeze(sortedUnique(pass)),
  });
}

// The hash covers what a mode allows, not what it is called or which mode it declares itself
// within: two modes that allow the same things have the same hash.
export function modeHash(mode) {
  const allows = { format: MODE_FORMAT, sandbox: mode.sandbox, allowRead: mode.allowRead, allowWrite: mode.allowWrite, pass: mode.pass };
  return crypto.createHash("sha256").update(JSON.stringify(allows)).digest("hex");
}

// Whether `inner` allows nothing that `outer` does not. The working folder is allowed in every
// mode, so a folder inside it counts as within.
export function isWithin(inner, outer, cwd) {
  if (outer.sandbox && !inner.sandbox) return false;
  const covered = (p, list) => inside(p, cwd) || list.some((q) => inside(p, q));
  return inner.allowRead.every((p) => covered(p, outer.allowRead)) &&
    inner.allowWrite.every((p) => covered(p, outer.allowWrite)) &&
    inner.pass.every((v) => outer.pass.includes(v));
}

const hashFile = (file) => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");

// The mode files a session must not change: every mode in the user and managed folders, and
// the ceiling. Keyed by real path. A session records these when it opens and again when it
// closes, so a change made during the session is on the record.
export function modeFileHashes(locations) {
  const out = {};
  for (const dir of [locations.user, locations.managed]) {
    if (!fs.existsSync(dir)) continue;
    for (const name of fs.readdirSync(dir)) {
      const f = path.join(dir, name);
      if (name.endsWith(".json") && fs.statSync(f).isFile()) out[real(f)] = hashFile(f);
    }
  }
  if (fs.existsSync(locations.ceiling)) out[real(locations.ceiling)] = hashFile(locations.ceiling);
  return out;
}

// Mode files changed during a session and not accepted since, read from the ledger. Returns
// { realPath: hashBefore }. A change is accepted by an "accept-mode" line carrying the file's
// new hash, which `erehold accept-mode` writes after showing the mode to the person.
export function unacceptedChanges(ledgerFile) {
  const pending = {};
  if (!ledgerFile || !fs.existsSync(ledgerFile)) return pending;
  for (const line of fs.readFileSync(ledgerFile, "utf8").split("\n")) {
    if (!line) continue;
    let e;
    try { e = JSON.parse(line); } catch { continue; }
    if (e.event === "close" && Array.isArray(e.modesChanged)) {
      for (const c of e.modesChanged) if (!(c.file in pending)) pending[c.file] = c.before;
    }
    if (e.event === "accept-mode" && e.file in pending) delete pending[e.file];
  }
  return pending;
}

function readModeFile(file, cwd, locations = null) {
  if (locations?.pending) {
    const key = real(file);
    if (key in locations.pending && hashFile(file) !== locations.pending[key]) {
      throw new Error(`${file} was changed during an erehold session and has not been accepted since; review it with \`erehold mode ${file}\`, then accept it with \`erehold accept-mode ${file}\``);
    }
  }
  let written;
  try { written = JSON.parse(fs.readFileSync(file, "utf8")); } catch { throw new Error(`${file} is not valid JSON`); }
  return checkMode(written, cwd);
}

// Find a mode by name. A name that exists in more than one location is refused, so a file in a
// less trusted place can never stand in for one of the same name in a more trusted place.
function findByName(name, locations, { trustedOnly = false } = {}) {
  const places = [];
  if (managedIsGenuine(locations)) places.push(["managed", locations.managed]);
  places.push(["user", locations.user], ["preset", locations.preset]);
  if (!trustedOnly) places.push(["project", locations.project]);
  const found = places.map(([trust, dir]) => ({ trust, file: path.join(dir, `${name}.json`) })).filter((c) => fs.existsSync(c.file));
  if (found.length > 1) throw new Error(`the mode "${name}" exists in more than one place (${found.map((c) => c.trust).join(", ")}); remove or rename one`);
  return found[0] ?? null;
}

// No mode may let the command write where modes, or erehold's own records, are kept: that would
// let an agent change the rules that govern its next session.
function checkWritesAvoidModes(mode, locations) {
  const guarded = [locations.managed, locations.ereholdHome, locations.preset].map(real);
  for (const w of mode.allowWrite.map(real)) {
    for (const g of guarded) {
      if (inside(g, w) || inside(w, g)) throw new Error(`the mode "${mode.name}" allows writing to ${w}, where erehold keeps modes or records; that is refused`);
    }
  }
}

// Load a mode by name or path and apply every location rule. Returns { mode, source, trust, base }.
export function loadMode(ref, cwd, locations = modeLocations(cwd), seen = new Set()) {
  let file, trust;
  if (NAME.test(ref)) {
    const hit = findByName(ref, locations);
    if (!hit) throw new Error(`no mode named "${ref}" in the managed, user, preset, or project folders`);
    file = hit.file;
    // Trust follows where the file really is: a link in the user folder to a file elsewhere is
    // trusted as that elsewhere.
    trust = trustOf(file, locations);
  } else {
    file = path.resolve(cwd, ref);
    if (!fs.existsSync(file)) throw new Error(`no mode file at ${file}`);
    trust = trustOf(file, locations);
  }
  const key = real(file);
  if (seen.has(key)) throw new Error(`the modes declare themselves within each other in a loop`);
  seen.add(key);
  const mode = readModeFile(file, cwd, locations);
  checkWritesAvoidModes(mode, locations);

  // A project mode must stay within a mode from a trusted location: the one it names, or the
  // lockdown preset if it names none. Other modes are checked against the base they name.
  let base = null;
  const baseName = mode.within ?? (trust === "project" ? "lockdown" : null);
  if (baseName) {
    const hit = findByName(baseName, locations, { trustedOnly: true });
    if (!hit) throw new Error(`the mode "${mode.name}" is declared within "${baseName}", which is not a managed, user, or preset mode`);
    base = loadMode(hit.file, cwd, locations, seen);
    if (!isWithin(mode, base.mode, cwd)) throw new Error(`the mode "${mode.name}" allows more than "${base.mode.name}", the mode it must stay within`);
  }
  const source = `${trust}:${NAME.test(ref) ? ref : file}`;
  return { mode, source, trust, base };
}

// The managed ceiling, if an administrator has set one: every session's mode must stay within it.
export function checkCeiling(mode, cwd, locations) {
  // A ceiling removed during a session must not silently lift the limit it set.
  if (locations.pending && real(locations.ceiling) in locations.pending && !fs.existsSync(locations.ceiling)) {
    throw new Error(`the managed ceiling was removed during an erehold session and the removal has not been accepted; accept it with \`erehold accept-mode "${locations.ceiling}"\``);
  }
  if (!managedIsGenuine(locations) || !fs.existsSync(locations.ceiling)) return null;
  const ceiling = readModeFile(locations.ceiling, cwd, locations);
  if (!isWithin(mode, ceiling, cwd)) throw new Error(`the mode "${mode.name}" allows more than the managed ceiling`);
  return { name: ceiling.name, hash: modeHash(ceiling) };
}

// Resolve what a session allows at the moment it is used, just before the command starts.
// Each folder is taken to its real path, so the sandbox is given the folder itself and not a
// link that could be pointed elsewhere during the session; a folder that does not exist is
// refused rather than guessed; and the guarded-location check runs again on the real paths.
// The working folder is checked too: running inside erehold's own folder, or a folder that
// contains it, would make the modes and records writable. Returns { cwd, allowRead, allowWrite }.
export function resolveAllowances(mode, cwd, locations) {
  const resolve = (p) => {
    if (!fs.existsSync(p)) throw new Error(`the allowed folder ${p} does not exist`);
    return fs.realpathSync(p);
  };
  const resolved = Object.freeze({
    cwd: resolve(cwd),
    allowRead: Object.freeze(sortedUnique(mode.allowRead.map(resolve))),
    allowWrite: Object.freeze(sortedUnique(mode.allowWrite.map(resolve))),
  });
  checkWritesAvoidModes({ name: mode.name, allowWrite: [resolved.cwd, ...resolved.allowWrite] }, locations);
  return resolved;
}

// Read `erehold run` options. A session's mode comes either from --mode or from the options
// that build one, never from both, so what the record declares is exactly what was asked for.
// Returns { mode, source, trust, base, cmd, fromOptions }.
export function modeFromArgs(args, cwd, locations = modeLocations(cwd)) {
  const written = { "erehold-mode": MODE_FORMAT, name: "options", allowRead: [], allowWrite: [], pass: [] };
  let ref = null, options = false, i = 0;
  for (; i < args.length && args[i] !== "--"; i++) {
    const a = args[i], next = args[i + 1];
    if (a === "--mode" && next) ref = args[++i];
    else if (a === "--pass" && next) { written.pass.push(args[++i]); options = true; }
    else if (a === "--allow-read" && next) { written.allowRead.push(args[++i]); options = true; }
    else if (a === "--allow-write" && next) { written.allowWrite.push(args[++i]); options = true; }
    else if (a === "--no-sandbox") { written.sandbox = false; options = true; }
    else throw new Error(`unknown option ${a}`);
  }
  const cmd = args.slice(i + 1);
  if (ref && options) throw new Error("use --mode or the options that build a mode, not both");
  if (ref) return { ...loadMode(ref, cwd, locations), cmd, fromOptions: false };
  const mode = checkMode(written, cwd);
  checkWritesAvoidModes(mode, locations);
  return { mode, source: "options", trust: "options", base: null, cmd, fromOptions: true };
}

// What the record's opening line says about the mode: its name, where it came from and how far
// that place is trusted, its hash, the mode it stays within, the ceiling it was checked against,
// and everything it allows, including the working folder and the network limit.
// When `resolved` is given (from resolveAllowances), the folders recorded are the real paths the
// sandbox was actually given; the hash stays the hash of the mode as declared.
export function describeMode(mode, source, { cwd, trust = null, base = null, ceiling = null, alwaysUnreadable = [], resolved = null }) {
  return {
    name: mode.name,
    source,
    trust,
    hash: modeHash(mode),
    within: base ? { name: base.mode.name, source: base.source, hash: modeHash(base.mode) } : null,
    ceiling,
    sandbox: mode.sandbox,
    workingFolder: resolved?.cwd ?? cwd,
    network: mode.sandbox ? "erehold's relay only" : "not limited: the command runs without the sandbox",
    allowRead: resolved?.allowRead ?? mode.allowRead,
    allowWrite: resolved?.allowWrite ?? mode.allowWrite,
    pass: mode.pass,
    alwaysUnreadable: mode.sandbox ? alwaysUnreadable : [],
  };
}
