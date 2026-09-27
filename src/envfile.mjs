// Read provider keys out of a .env file's text. Handles `KEY=value`, `export KEY=value`,
// quotes, and trailing comments.

import { PROVIDERS } from "./session.mjs";

function parse(text) {
  const vars = new Map();
  for (const raw of text.split(/\r?\n/)) {
    const m = raw.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (!m) continue;
    let v = m[2].trim();
    if ((v.startsWith('"') && v.includes('"', 1)) || (v.startsWith("'") && v.includes("'", 1))) {
      v = v.slice(1, v.indexOf(v[0], 1));
    } else {
      v = v.replace(/\s+#.*$/, "").trim();
    }
    if (v) vars.set(m[1], v);
  }
  return vars;
}

// Returns { found: { provider: value }, unsupported: [NAMES] }. `unsupported` lists names that
// look like secrets (ending in _API_KEY, _TOKEN, or _SECRET) that erehold does not handle yet,
// so an import never passes over a key silently.
export function keysFromEnvFile(text) {
  const vars = parse(text);
  const found = {};
  const used = new Set();
  for (const [p, s] of Object.entries(PROVIDERS)) {
    for (const name of [s.envKey, ...(s.alsoEnvKeys ?? [])]) {
      if (vars.has(name)) { used.add(name); if (!found[p]) found[p] = vars.get(name); }
    }
  }
  const unsupported = [...vars.keys()].filter((k) => !used.has(k) && /(_API_KEY|_TOKEN|_SECRET)$/.test(k));
  return { found, unsupported };
}
