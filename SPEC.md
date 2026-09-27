# erehold v0.3: specification

This is the build specification for the first working versions of erehold. The approach behind it is in `README.md`.

## Scope

v0 protects one kind of secret: API keys for AI model providers (Anthropic, OpenAI, and Google Gemini), used by a program you start through erehold. Those keys travel inside outbound requests, which is the middle rung of the ladder in the README: the agent is given a stand-in, and the real key is added only as the request leaves.

Out of scope for now: other secret kinds (SSH and signing keys, database passwords, registry tokens) and other providers. Each is a later version.

## How it works

1. You store each provider key once in the macOS keychain, either with `erehold add <provider>` (the key is typed at a hidden prompt) or with `erehold import <file>` from an existing `.env` file. Either way the key never appears in a command line. An import names any key in the file that erehold does not handle, so nothing is skipped silently.
2. `erehold run -- <command>` starts a session. erehold reads the keys from the keychain into its own memory and makes one stand-in per provider. Stand-ins are random, begin with `erehold-standin-`, and are not valid keys, so a stand-in written back into a file can never be mistaken for a real one.
3. erehold starts a relay on `127.0.0.1` at a random port, and launches your command with:
   - an environment built from an allow list (paths, user, shell, terminal, locale, temporary directory), so no secret in erehold's own environment reaches the child;
   - `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, and `GEMINI_API_KEY` set to the stand-ins (the Gemini stand-in also as `GOOGLE_API_KEY`, which Google's libraries read first);
   - `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, and `GEMINI_BASE_URL` pointed at the relay. Google's libraries take a different address only in code, not from an environment variable, so a Gemini program passes `GEMINI_BASE_URL` as its base URL.
4. When the command calls a provider, the request goes to the relay. The relay checks that the stand-in presented (in the provider's usual header, or for Gemini in a `key=` part of the address) is this session's stand-in for that provider, replaces it with the real key, and sends the request to that provider's one fixed address over HTTPS. A request with any other value is refused and never forwarded.
5. Every request writes one line to the session record: time, provider, key name, destination, method, path, result, and a keyed fingerprint of the key (never the key). Each line carries a hash of the line before it, so a deleted or edited line shows up when the record is checked with `erehold verify`. Every line is also added to one shared ledger, `~/.erehold/ledger.jsonl`, and `erehold verify` compares the session's file with its lines in the ledger.
5b. The chain alone cannot stop a full rewrite: code running as you could rewrite a session file and recompute every hash. What stops that is the ledger's macOS system append-only flag, set once with `erehold protect` (which shows the one administrator command to run). With the flag set, code running as you can add to the ledger but cannot rewrite, truncate, rename, or delete it, so a rewritten session file no longer matches the ledger. Each session's opening line declares whether the ledger was locked.
5a. When Anthropic's sandbox runtime (`srt`) is installed, the command runs inside it, on by default (`--no-sandbox` turns it off). Inside the sandbox:
   - the only network address the command can reach is erehold's relay; other services on the machine and the internet are refused;
   - your home folder is unreadable, except the working folder and any folder named with `--allow-read`;
   - files that commonly hold secrets stay unreadable even inside the working folder (`.env` files and their variants, `~/.ssh`, `~/.aws`, `~/.gnupg`, the keychain folder, erehold's own folder);
   - writing is allowed only in the working folder and any folder named with `--allow-write`.
   The sandbox tells programs to reach local addresses directly and then blocks direct connections, so erehold routes relay traffic through the sandbox's own gatekeeper, which is set to allow exactly the relay's address.
6. When the command exits, the session closes: the relay stops, the stand-ins stop working, erehold lets go of the keys, and a closing line is written.

## What erehold claims, and what it does not

**Holder level, with the sandbox:** level 3 of the four in the README. The agent is behind a real boundary: it cannot reach anything but the relay, cannot read your home folder or common secret files, and cannot reach the keychain. A key it somehow obtained would have nowhere to go.

**Holder level, without the sandbox:** level 2, a separate program running as the same user. The key is never in the agent's environment, arguments, output, or erehold's record, but the agent can read files and reach the network directly.

**The record:** with the ledger locked, a rewrite of any session's record by code running as you is caught when that session is verified. Without the lock, the record catches edits and deletions of single lines but not a full rewrite, and each session says which applies. An administrator, or code that obtains administrator rights, can clear the lock; so can anyone at a macOS recovery console.

**Not claimed at either level:** protection from code that runs as you outside erehold. That code can read the keychain item through the macOS `security` tool, and it can read erehold's memory. The sandbox is Anthropic's research preview and rests on macOS `sandbox-exec`, which Apple marks as deprecated though it still enforces on macOS 27. Anything the command writes in the working folder runs later outside the sandbox if you run it.

## Design rules

- No outside packages. The core uses only Node's built-in modules, because the protecting part must be the hardest thing on the machine to poison.
- Refuse rather than guess: an unknown stand-in, an unknown provider path, or a missing key is refused, and the refusal is recorded.
- The destination for each provider is fixed in code. Nothing in the child's environment or the request can redirect a real key.
- Test hooks (a fake upstream, a secret source other than the keychain) exist only in the library interface used by the tests. The command-line tool cannot reach them.

## Done when

Each check below is an automated test in `test/run.mjs` using a harmless fake key and a fake provider running locally, so every run is repeatable:

1. The fake key appears nowhere a child program can see: its environment, its arguments, or anything it prints.
2. A secret set in erehold's own environment does not reach the child.
3. A request carrying the session stand-in reaches the fake provider with the real key.
4. A request carrying any other value is refused and never reaches the fake provider.
5. An unknown provider path is refused.
6. Every request produces exactly one record line; no line contains the key; the chain verifies; editing or deleting a line makes verification fail.
7. After the session closes, the stand-in no longer works.
8. The package declares no dependencies.

Sandbox checks, in `test/sandbox.mjs`, run for real inside `srt` (skipped when it is not installed):

9. The sandboxed command reaches the relay, and the provider receives the real key.
10. It cannot reach another service on the machine, or the internet.
11. It cannot read a file in the home folder outside the working folder, or a `.env` file inside it.
12. It can read and write ordinary files in the working folder, and cannot write outside it.
13. The session record declares the sandboxed holder level.

Ledger checks, in `test/run.mjs`:

14. Every session line reaches the ledger, and the session's opening line declares the ledger's protection.
15. A full, consistent rewrite of a session file passes its own chain check but fails the comparison with the ledger.
16. An append-only ledger refuses rewriting and still accepts additions.

One live run against the real Anthropic API completes end to end, done by hand with a real key.
