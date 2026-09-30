// Run the agent inside Anthropic's sandbox runtime (srt), so it can reach only erehold's relay
// and cannot read the home folder outside its working folder. Behavior checked on macOS 27
// against srt 0.0.77 (see SPEC.md, "Holder level").

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const SANDBOXED_LEVEL = "level 3: the agent is sandboxed; its network reaches only erehold's relay, and your home folder is unreadable to it outside the working folder";

export function sandboxAvailable() {
  return spawnSync("srt", ["--version"], { encoding: "utf8" }).status === 0;
}

// Places that commonly hold secrets. Denied even inside the working folder, because a more
// specific deny wins over the working-folder allow.
export const ALWAYS_DENY_READ = [
  "**/.env", "**/.env.*", "**/*.env", "**/.envrc",
  "~/.erehold", "~/.ssh", "~/.aws", "~/.gnupg", "~/.config/gh", "~/.netrc",
  "~/.anthropic_env", "~/.secrets.env", "~/Library/Keychains",
];

// Build the sandbox settings and the command line that runs `cmd` inside it.
//   port:       the relay's port, the one address the agent may reach
//   cwd:        the working folder, readable and writable
//   allowRead / allowWrite: extra folders the user names with --allow-read / --allow-write
export function sandboxCommand({ port, cwd, cmd, allowRead = [], allowWrite = [], settingsDir = os.tmpdir() }) {
  const settings = {
    network: { allowedDomains: [`127.0.0.1:${port}`], deniedDomains: [] },
    filesystem: {
      denyRead: [os.homedir(), ...ALWAYS_DENY_READ],
      allowRead: [cwd, ...allowRead],
      allowWrite: [cwd, ...allowWrite],
      denyWrite: [],
    },
  };
  const file = path.join(fs.mkdtempSync(path.join(settingsDir, "erehold-srt-")), "settings.json");
  fs.writeFileSync(file, JSON.stringify(settings, null, 2), { mode: 0o600 });
  // srt tells programs to connect to local addresses directly, and its own rules then block
  // direct connections. Clearing NO_PROXY sends relay traffic through srt's gatekeeper, which
  // allows exactly the relay's address. NODE_USE_ENV_PROXY makes Node's fetch use the gatekeeper.
  const argv = ["-s", file, "--", "env", "NO_PROXY=", "no_proxy=", "NODE_USE_ENV_PROXY=1", ...cmd];
  return { file, argv, settings, cleanup: () => fs.rmSync(path.dirname(file), { recursive: true, force: true }) };
}
