# EREHOLD

> "...our love would not bind you nor our needs hold you.
> Yet this we ask ere you leave us, that you speak to us and give us of your truth."
>
> Kahlil Gibran, *The Prophet* (1923)

**EREHOLD** (said "AIR-hold") is an approach to keeping secrets safe in terminals and in the AI agents that now run in them. *Ere* means *before*. A secret is held until the moment it has to leave, released only there, at the threshold, and every crossing is asked about and recorded.

The principle in one line: **code you have not verified never holds the value.**

Concept note, 2026-09-27. The approach below is still being worked out; the first working software, for AI provider keys only, is described in `SPEC.md`.

---

## Why now

On 24 March 2026, two poisoned releases of LiteLLM, a widely used library for calling AI models, were published to PyPI. The attackers had obtained the project's publishing token from its build pipeline through an earlier compromise of a security scanner. The poisoned code ran on every Python start and collected whatever it could reach: environment variables, SSH keys, cloud credentials, Kubernetes tokens, database passwords, and `.env` files. At least one victim was hit through a dependency of an agent plugin. The advice afterwards was to rotate everything, because nobody could say which secrets had been on the machine or used.

Sources: [LiteLLM security update](https://docs.litellm.ai/blog/security-update-march-2026); [Cloud Security Alliance research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-litellm-pypi-backdoor-ai-toolchain-supply/); [Sonatype analysis](https://www.sonatype.com/blog/compromised-litellm-pypi-package-delivers-multi-stage-credential-stealer).

The lesson is general. Code that runs as you can read what you can read. Agents run as you, install packages as you, and load plugins as you. Scanning and redaction find some of what leaks; they cannot guarantee that nothing does.

## The approach: many layers, each enforced somewhere different

A single lock fails in a single way. EREHOLD is built as defense in depth: several protections, each enforced by a different party or mechanism, arranged so that one failure does not take the others with it. A protection enforced only by one piece of software fails when that software does, however many names it has. So each protection is placed, wherever possible, outside the component it guards against.

The protections EREHOLD draws on are enforced in five different places:

- **the broker,** which holds secrets and hands the agent only stand-ins;
- **the boundary** between the agent and the broker: a separate operating-system user, a sandbox, a virtual machine, or secure hardware;
- **the destination or issuer,** through credentials bound to a key or to one exact request, and expiry set by whoever issued the credential;
- **an independent record,** kept where the broker cannot rewrite it;
- **the person,** through approvals that state exactly what they grant, asked only when they matter.

The exact set of protections, and a test that each one fails independently of the others, are the open work of this project.

## One question sorts every secret

Where must the secret's value exist for it to work? There are three answers, and they form a ladder.

1. **Inside a local program that must hold the value itself** (a database password, a program that reads a key file). This is the weakest place. A value that an unverified program must hold cannot be kept from it; it can only be made short-lived and narrowly scoped.
2. **Inside an outbound request** (API keys, registry tokens, git over HTTPS). The agent gets a stand-in, and the real value is swapped in only as the request leaves, only toward the destinations that secret is bound to.
3. **Inside a signature or proof** (SSH keys, signing keys, certificates). The holder signs on request and the key never travels. This is the strongest place.

EREHOLD's main move is to push each secret up the ladder. This already ships in places:

- a database login becomes a certificate or a short-lived token: [Teleport](https://goteleport.com/docs/connect-your-client/third-party/gui-clients/) connects database clients through a local tunnel with short-lived certificates and no database password; [AWS RDS IAM authentication](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html) uses tokens that last 15 minutes;
- a bearer token becomes a key-bound token: [RFC 9449 (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449) and [RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705) bind a token to a key its holder must prove, so a stolen copy is useless on its own;
- a standing password becomes a per-use credential: [Vault's database secrets engine](https://developer.hashicorp.com/vault/docs/secrets/databases) issues unique, leased credentials that are revoked when the lease ends.

## Where the holder lives decides how much is protected

The strength of every protection depends on how far the holder of the value is kept from the code you have not verified:

1. **In the same process as the agent.** Stand-ins keep values out of the agent's context and transcripts, but code in that process can read memory.
2. **In a separate process, as the same user** (a local broker, `ssh-agent`). The agent cannot copy the value but can ask the holder to use it, and a same-user attacker can often reach the holder.
3. **Behind a real boundary** (a separate user, a sandbox, a virtual machine). The agent reaches the holder only through the one door it is given.
4. **In secure hardware** (a security key, a secure enclave, a TPM). The value never exists in any software's memory. This fully covers the signature case, and only that case.

EREHOLD never claims a system is "secure." It claims a declared tier, so a user can see which attacks are defeated, which are only bounded, and which remain.

## Every crossing is recorded, without the value

A secret is checked out to a holder for a purpose and checked back in when the session ends or the grant expires, whether or not the holder returns it. Every use is recorded by reference or keyed hash, never by value, somewhere the broker cannot rewrite. A secret that ever reaches a place that discloses it (an agent's context, a transcript, a commit) is recorded as disclosed and carries an obligation to rotate it.

After an incident like LiteLLM's, that record is the difference between "rotate everything" and "rotate these four."

## What EREHOLD can reduce but not remove

- **A destination misusing what it is sent on purpose.** Key-bound tokens stop a stolen copy from being replayed elsewhere; what the rightful destination does with a real credential can only be bounded by scope, expiry, and the destination's own logs.
- **The person approving what they did not read.** Fewer, clearer, and physically confirmed asks make this rarer; they do not make it impossible.
- **Resources that accept neither short-lived tokens nor certificates.** For these, the value must be held; it can only be made short-lived and narrowly scoped.
- **Covert channels.** Lampson's 1973 "A Note on the Confinement Problem" observes that "there is not likely to be any rigorous way of identifying every channel in any system of even moderate complexity," and offers the practical answer: bound the capacity of the covert channels. For secrets EREHOLD brokers, the agent never holds the value, so there is nothing for it to leak; the remaining exposure is the data the agent is given to work with.

## What would show this wrong

- A workflow in which a brokered secret's value reaches the agent's context, a transcript, or a child environment while EREHOLD is operating at its declared tier. That would falsify the construction claim.
- A common terminal secret that fits none of the three places on the ladder. That would show the sorting question is incomplete.
- Two of EREHOLD's protections that fail together under one realistic attack while being counted as separate layers. That would falsify the defense-in-depth claim.
- A record of a crossing from which the secret's value can be recovered without the hashing key.

## Prior art, credited

Much of this already exists in pieces, and EREHOLD builds on it: `ssh-agent` (now RFC 9987), where the holder signs and the key does not travel; Microsoft's [Valet Key pattern](https://learn.microsoft.com/en-us/azure/architecture/patterns/valet-key); Claude Code's sandbox credential masking and Anthropic's open-source sandbox runtime, which give sandboxed commands a placeholder and substitute the real value at a proxy; OpenClaw's secret sentinels; Cloudflare Sandbox outbound handlers; OpenAI's hosted agent sandboxes; HashiCorp Vault's leases and keyed-hash audit logs; [HashiCorp Boundary's credential injection](https://developer.hashicorp.com/boundary/docs/concepts/credential-management) for SSH and RDP sessions; Teleport's certificate-based database access; and the OAuth sender-constraining standards above.

What EREHOLD adds is the combination: one question that sorts every terminal secret, a ladder for moving secrets to stronger places, holder tiers that make every claim explicit, protections enforced in different places so they fail independently, and one custody record across all of it. The goal is an open, vendor-neutral protocol that tools and agents can adopt without adopting any one vendor's stack.

## Names

**EREHOLD** (uppercase) names the principle and, in time, the conformance designation. **erehold** (lowercase) names the software that implements it. Version 0.1, which protects AI provider keys, is in this repository; `SPEC.md` says what it does, what it claims, and how it is tested.

## Author and licence

Regis Lloyd Chapman (Durgadas), 2026. Part of the Polymathie family of standards and tools.

This note is licensed under CC BY 4.0 (see `LICENSE-SPEC`). Software released here will be licensed under Apache-2.0 (see `LICENSE` and `NOTICE`).
