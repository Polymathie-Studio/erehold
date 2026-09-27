# EREHOLD

> "...our love would not bind you nor our needs hold you.
> Yet this we ask ere you leave us, that you speak to us and give us of your truth."
>
> Kahlil Gibran, *The Prophet* (1923)

**EREHOLD** (said "AIR-hold") is an approach to keeping secrets safe in terminals and in the AI agents that now run in them. *Ere* means *before*. A secret is held until the moment it has to leave, and released only there, at the threshold, where every crossing is asked about and recorded.

The principle in one line: **the untrusted party never holds the value.**

Concept note, 2026-09-27. Not yet a specification and not yet software.

---

## The problem

When you run a tool or an AI agent in your terminal, it runs as you. It can read what you can read: your environment variables, your dotfiles, your `.env` files, your cloud credentials, your SSH keys. An agent that can read a secret can also print it, paste it into its own context (which is sent to a model provider), write it into a transcript, commit it, or send it somewhere.

The usual defences work by detection: scan for things that look like keys, redact them from logs, strip them from environments. Detection has a miss rate. A scanner that catches most keys still lets some through, and a key that has already entered an agent's context has already left your machine.

Certainty comes only from construction: arranging things so the secret's value is never somewhere the agent can reach, because no path puts it there.

## One question sorts every secret

Rather than a list of secret types, one question decides how each secret is handled: **where must the secret's value exist for it to work?** There are three answers.

1. **Inside a signature or proof** (SSH keys, GPG keys, commit signing). The holder of the key signs on request, and the key itself never leaves the holder. This is how `ssh-agent` already works.
2. **Inside an outbound request** (API keys, package-registry tokens, git over HTTPS). The tool gets a stand-in, a placeholder that looks like a credential but isn't one. The real value is swapped in only as the request leaves the machine, and only toward the destinations that secret is bound to. The swap happens ere it leaves: never earlier, never anywhere else.
3. **Inside a local process that must hold the value itself** (a database client, a program that reads a key file). This is the ceiling, stated openly: a value that an untrusted process must hold cannot be kept from it. What EREHOLD can do is make it short-lived and narrowly scoped, so holding it is worth less and lasts less.

## One custody model across all three

Every case follows the same pattern: the agent holds a reference, it is granted a capability for a purpose, and every use is recorded. A secret is checked out to a holder for a purpose and checked back in when the session ends or the lease expires, whether or not the holder returns it. A secret that ever reaches a disclosing surface (the model's context, a transcript, a commit) is recorded as disclosed and carries an obligation to rotate it.

The record never contains a secret's value. It refers to secrets by reference, or by a keyed hash (HMAC), so the record can be checked without becoming a new place for secrets to leak.

## Where it can plug in today

Several tools already ask an outside program for credentials instead of storing them. An EREHOLD broker can sit behind those interfaces without changing the tools:

- **git credential helpers**: `get`, `store`, and `erase`, with support for expiring and ephemeral credentials.
- **Docker credential helpers**: `get`, `store`, `erase`, and `list`.
- **AWS `credential_process`**: returns temporary credentials with an expiry, refreshed automatically.
- **pip**, through the `keyring` library.
- **pnpm**, through `tokenHelper`. npm has no equivalent hook yet; one is proposed but not shipped.

The existing signing agents are the model for the first case, and their limits carry over. Anyone who can reach an `ssh-agent` socket can ask it to sign, even though they cannot copy the key. `gpg-agent` does its signing and decryption internally, but it also has an explicit export operation.

## What EREHOLD does not claim

A defensible claim is a narrow one. For the secrets it brokers, EREHOLD aims to guarantee that the value never enters the agent's context, its transcripts, its child processes' environments, or EREHOLD's own records, and that every use is recorded. It does not cover:

- secrets it never brokered: pasted into a prompt, left in a readable file, or returned by some other service;
- what an allowed destination does with a value legitimately sent to it;
- other programs running as the same user, unless the broker runs under a separate user, in a sandbox, or in a virtual machine;
- anything a model provider retains from content that did enter an agent's context;
- covert channels, such as encoding a value into traffic that is otherwise allowed.

## What would show this wrong

- A workflow in which a brokered secret's value reaches the agent's context, a transcript, or a child environment while EREHOLD is operating as described. That would falsify the construction claim.
- A common terminal secret that does not fit any of the three answers above. That would show the sorting question is incomplete.
- A record of a crossing from which the secret's value can be recovered without the hashing key. That would falsify the record claim.

## Prior art, credited

The swap-at-egress idea is not new, and this note builds on it:

- `ssh-agent` (now specified as RFC 9987): the holder signs, the key does not travel.
- The **Valet Key pattern** (Microsoft Azure Architecture Center): hand out a limited, expiring token instead of the real credential.
- **Claude Code's sandbox credential masking** and Anthropic's open-source **sandbox runtime**: the sandboxed command sees a placeholder, and a proxy substitutes the real value toward allowed hosts.
- **OpenClaw's secret sentinels**, **Cloudflare Sandbox outbound handlers**, and **OpenAI's hosted agent sandboxes**: placeholders inside the workload, real values supplied outside it.
- **HashiCorp Vault**: leases, response wrapping, and audit logs that record keyed hashes rather than values.

What EREHOLD adds is the combination: one question that sorts every terminal secret into three cases, one custody model and one record across all three, and the intent of an open, vendor-neutral protocol entered through the credential-helper interfaces that tools already call. A survey done while writing this note (September 2026) found several local secret brokers and no vendor-neutral protocol of this kind.

## Names

**EREHOLD** (uppercase) names the principle and, in time, the conformance designation. **erehold** (lowercase) names the software that implements it. The software does not exist yet.

## Author and licence

Regis Lloyd Chapman (Durgadas), 2026. Part of the Polymathie family of standards and tools.

This note is licensed under CC BY 4.0 (see `LICENSE-SPEC`). Software released here will be licensed under Apache-2.0 (see `LICENSE` and `NOTICE`).
