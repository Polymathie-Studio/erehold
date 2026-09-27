// Read provider keys out of a .env file's text. Returns { provider: value } for the providers
// erehold knows. Handles `KEY=value`, `export KEY=value`, quotes, and trailing comments.

import { PROVIDERS } from "./session.mjs";

export function keysFromEnvFile(text) {
  const wanted = new Map(Object.entries(PROVIDERS).map(([p, s]) => [s.envKey, p]));
  const found = {};
  for (const raw of text.split(/\r?\n/)) {
    const m = raw.match(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (!m || !wanted.has(m[1])) continue;
    let v = m[2].trim();
    if ((v.startsWith('"') && v.includes('"', 1)) || (v.startsWith("'") && v.includes("'", 1))) {
      v = v.slice(1, v.indexOf(v[0], 1));
    } else {
      v = v.replace(/\s+#.*$/, "").trim();
    }
    if (v) found[wanted.get(m[1])] = v;
  }
  return found;
}
