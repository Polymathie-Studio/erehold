# erehold v0: specification

This is the build specification for the first working version of erehold. The approach behind it is in `README.md`.

## Scope

v0 protects one kind of secret: API keys for AI model providers (Anthropic, OpenAI, and Google Gemini), used by a program you start through erehold. Those keys travel inside outbound requests, which is the middle rung of the ladder in the README: the agent is given a stand-in, and the real key is added only as the request leaves.

Out of scope for v0: other secret kinds (SSH and signing keys, database passwords, registry tokens), other providers, and the sandbox. Each is a later version.

## How it works

1. You store each provider key once in the macOS keychain, either with `erehold add <provider>` (the key is typed at a hidden prompt) or with `erehold import <file>` from an existing `.env` file. Either way the key never appears in a command line. An import names any key in the file that erehold does not handle, so nothing is skipped silently.
2. `erehold run -- <command>` starts a session. erehold reads the keys from the keychain into its own memory and makes one stand-in per provider. Stand-ins are random, begin with `erehold-standin-`, and are not valid keys, so a stand-in written back into a file can never be mistaken for a real one.
3. erehold starts a relay on `127.0.0.1` at a random port, and launches your command with:
   - an environment built from an allow list (paths, user, shell, terminal, locale, temporary directory), so no secret in erehold's own environment reaches the child;
   - `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, and `GEMINI_API_KEY` set to the stand-ins (the Gemini stand-in also as `GOOGLE_API_KEY`, which Google's libraries read first);
   - `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, and `GEMINI_BASE_URL` pointed at the relay. Google's libraries take a different address only in code, not from an environment variable, so a Gemini program passes `GEMINI_BASE_URL` as its base URL.
4. When the command calls a provider, the request goes to the relay. The relay checks that the stand-in presented (in the provider's usual header, or for Gemini in a `key=` part of the address) is this session's stand-in for that provider, replaces it with the real key, and sends the request to that provider's one fixed address over HTTPS. A request with any other value is refused and never forwarded.
5. Every request writes one line to the session record: time, provider, key name, destination, method, path, result, and a keyed fingerprint of the key (never the key). Each line carries a hash of the line before it, so a deleted or edited line shows up when the record is checked with `erehold verify`.
6. When the command exits, the session closes: the relay stops, the stand-ins stop working, erehold lets go of the keys, and a closing line is written.

## What v0 claims, and what it does not

**Holder level:** a separate program running as the same user (level 2 of the four in the README). The key is never in the agent's environment, arguments, output, or erehold's record.

**Not claimed in v0:** protection from code that runs as you outside erehold. That code can read the keychain item through the macOS `security` tool, and it can read erehold's memory. The agent itself is not yet confined: it can reach the network directly, so a key it obtains some other way (pasted in, left in a file) is not protected. Running the agent inside a sandbox that can reach only the relay is the next version, and it raises the holder level to 3.

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

One live run against the real Anthropic API completes end to end, done by hand with a real key.
