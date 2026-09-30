# erehold v0.5: specification

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

## Modes

A mode is a short declared profile of what a session allows. It is read once when the session starts, stays fixed until the session closes, and is written, with its hash, into the record's opening line, so the record shows exactly what the run was allowed to do.

A mode is a JSON file with these fields, and no others:

- `"erehold-mode": 1`, required: the format of the file.
- `name`: a label shown in the record. It is not part of the hash.
- `within`: the name of a managed, user, or preset mode this mode must stay within. Required in effect for project modes, which otherwise stay within `lockdown`. Not part of the hash.
- `sandbox`: `true` to run the command in the sandbox, `false` to run without it. Missing means `true`, the stricter choice.
- `allowRead`: extra folders the sandboxed command may read.
- `allowWrite`: extra folders the sandboxed command may write.
- `pass`: extra environment variables let through to the command. The variables erehold sets itself (the provider keys and addresses) are never allowed.

Each list is an allowance. A missing list is the empty allowance, and relative folders are resolved against the working folder. The working folder itself is always readable and writable, and the always-unreadable secret files stay unreadable whatever a mode allows.

`erehold run --mode <name or file> -- <command>` runs under a mode, found by name or read from a path.

Where a mode file lives decides how far it is trusted. There are four locations, most trusted first:

- **managed:** `/Library/Application Support/erehold/modes`, counted only when an administrator owns the folder and nobody else can write to it. The same folder's parent may hold `ceiling.json`, a mode that every session's mode must stay within, whatever its source.
- **user:** `~/.erehold/modes`, your own modes. The sandboxed command can neither read nor write there.
- **preset:** the `modes` folder shipped with erehold.
- **project:** anywhere else, including a project's own `.erehold/modes` folder. A project file may have been written by the agent or by a dependency, so a project mode can only tighten: it must stay within a mode from a trusted location, the one it names in a `within` field, or `lockdown` if it names none. A project mode cannot name another project mode.

A name that exists in more than one location is refused, so a less trusted file can never stand in for a more trusted one of the same name. Trust follows where a file really is: a link in the user folder to a file elsewhere is trusted as that elsewhere. No mode may allow writing where erehold keeps modes or records (`~/.erehold`, the managed folder, the presets), since that would let a session change the rules for the next one. "Stays within" means: the sandbox stays on if the outer mode has it on, and every folder and variable the inner mode allows is one the outer mode allows, the working folder counting as allowed in every mode. The options `--allow-read`, `--allow-write`, `--pass`, and `--no-sandbox` build a mode instead, recorded as coming from options; using them together with `--mode` is refused, so a record never mixes a declared mode with changes made to it. One preset ships now: `lockdown`, the sandbox with nothing allowed beyond the working folder.

Refusing rather than guessing applies to modes too: an unknown field, a wrong type, or a variable erehold sets itself stops the session before anything starts. A declared mode that needs the sandbox does not start if the sandbox runtime is not installed; a mode built from options falls back to running without the sandbox, as before, and the record then says `sandbox: false`.

**Mode files a session changes.** With the sandbox on, the command can neither read nor write the user or managed mode folders. With it off, code running as you can change them, and erehold cannot prevent that. It records it instead. When a session opens, erehold writes a hash of every user and managed mode file, and of the ceiling, into the opening line; when it closes, it hashes them again and writes any difference into the closing line. A mode file changed during a session is then refused, and a ceiling removed during a session stops every session, until the person reviews it (`erehold mode <file>`) and accepts it (`erehold accept-mode <file>`), which writes an acceptance line to the ledger. Putting the file back as it was lifts the refusal without an acceptance. erehold also refuses to run from inside its own folder, the managed folder, or its presets, or from any folder that contains one of them, since the working folder is always writable.

**Known limit of acceptance.** An acceptance proves only that someone ran `erehold accept-mode`, and any code running as you can run it, or append an acceptance line to the ledger directly. So a program that changes a mode during a session could also accept its own change. Until acceptance requires the person's presence, it catches a change made carelessly or by a program that does not know to accept it, not one made by a program that does.

**Settings never come from the environment.** erehold reads no configuration from environment variables, so a repository's `.env` file or a shell hook cannot steer it or move its folders. The whole `EREHOLD_` namespace is reserved: such a variable in erehold's environment stops the session before anything starts, and no mode may pass one through.

**Folders are resolved when they are used.** Just before the command starts, every allowed folder and the working folder are taken to their real paths, a folder that does not exist is refused, and the check against erehold's own folders runs again on those real paths. The sandbox is given the real paths, so a link inside the working folder that is pointed elsewhere during the session does not move what the session may read or write. The record states the real paths the sandbox was given; the mode's hash stays the hash of the mode as declared.

The hash covers what a mode allows (the sandbox setting and the three allowances, normalized and sorted), not its name, so two modes that allow the same things have the same hash. `erehold mode <name or file>` shows a mode as erehold reads it, with that hash; `erehold verify` reports the mode a recorded session ran under. The hash is what another part of DFH can compare against to check that a session is running under the mode an action requires.

## What erehold claims, and what it does not

**Holder level, with the sandbox:** level 3 of the four in the README. The agent is behind a real boundary: it cannot reach anything but the relay, cannot read your home folder or common secret files, and cannot reach the keychain. A key it somehow obtained would have nowhere to go.

**Holder level, without the sandbox:** level 2, a separate program running as the same user. The key is never in the agent's environment, arguments, output, or erehold's record, but the agent can read files and reach the network directly.

**The record:** with the ledger locked, a rewrite of any session's record by code running as you is caught when that session is verified. Without the lock, the record catches edits and deletions of single lines but not a full rewrite, and each session says which applies. An administrator, or code that obtains administrator rights, can clear the lock; so can anyone at a macOS recovery console.

**Not claimed at either level:** protection from code that runs as you outside erehold. That code can read the keychain item through the macOS `security` tool, and it can read erehold's memory. The sandbox is Anthropic's research preview and rests on macOS `sandbox-exec`, which Apple marks as deprecated though it still enforces on macOS 27. Anything the command writes in the working folder runs later outside the sandbox if you run it.

## Design rules

- No outside packages. The core uses only Node's built-in modules, because the protecting part must be the hardest thing on the machine to poison.
- Refuse rather than guess: an unknown stand-in, an unknown provider path, or a missing key is refused, and the refusal is recorded.
- Write before acting: a request is recorded as forwarding before the real key leaves. If that line cannot be written (a full disk, a broken file), the request is refused and never sent, and the relay refuses everything after it until a new session starts. An action that cannot be recorded does not happen.
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
17. With the record unwritable, a request is refused and never reaches the provider, and erehold keeps running and keeps refusing rather than crashing.

Mode checks, in `test/run.mjs`:

18. The `lockdown` preset loads with the sandbox on and every allowance empty.
19. A mode without its format declaration, with an unknown field, with a wrong type, passing a variable erehold sets itself, or passing something that is not a variable name, is refused.
20. The hash is the same for modes that allow the same things in a different order or under a different name, and changes when an allowance changes.
21. A checked mode cannot be changed after it is read.
22. Options build a mode recorded as coming from options; `--mode` together with those options is refused; a mode file is recorded as coming from that file.
23. The record's opening line declares the mode's name, source, hash, working folder, network limit, and every allowance, and the record still verifies.
24. `erehold mode` shows the same hash a session records.

Location checks, in `test/run.mjs`, run against temporary folders standing in for the four locations:

25. A user mode loads with user trust; a name in two locations is refused.
26. A project mode that allows more than lockdown is refused; one within a user mode that allows the same folder loads and names its base; a project mode cannot turn the sandbox off inside a sandboxed base, or stay within another project mode.
27. A mode allowing writes where erehold keeps modes or records is refused; modes declared within each other in a loop are refused.
28. A link in the user folder to a file elsewhere gets project trust.
29. A managed folder anyone can write to is not trusted as managed; one only its owner can write is.
30. A mode that allows more than the managed ceiling is refused; one within it passes.

Checks for the three rules above, in `test/run.mjs`:

31. A mode may not pass an `EREHOLD_` variable, and `EREHOLD_` variables in erehold's own environment are found.
32. An allowed folder reached through a link resolves to the real folder; one that does not exist at launch is refused; running from inside erehold's folder, or a folder that contains it, is refused.
33. A mode file changed during a session is reported at close and written into the closing line, and the record still verifies.
34. That mode is refused until accepted; putting the file back lifts the refusal; after an acceptance line reaches the ledger, the changed mode loads.

And in `test/sandbox.mjs`, run for real inside `srt`:

35. A folder allowed through a link is readable as given, and pointing the link at another folder during the session does not make that folder readable.

One live run against the real Anthropic API completes end to end, done by hand with a real key.
