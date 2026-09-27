# Sources

The primary sources behind the EREHOLD concept note, grouped by what each supports. Checked on 2026-09-27.

## The motivating incident

- LiteLLM, "Security Update: Suspected Supply Chain Incident" (24 March 2026): https://docs.litellm.ai/blog/security-update-march-2026
- Cloud Security Alliance research note on the LiteLLM PyPI backdoor: https://labs.cloudsecurityalliance.org/research/csa-research-note-litellm-pypi-backdoor-ai-toolchain-supply/
- Sonatype, "Compromised litellm PyPI Package Delivers Multi-Stage Credential Stealer": https://www.sonatype.com/blog/compromised-litellm-pypi-package-delivers-multi-stage-credential-stealer
- The original report, BerriAI/litellm issue #24512: https://github.com/BerriAI/litellm/issues/24512

## Moving secrets to stronger places

- Teleport database access with short-lived certificates and a local authenticated tunnel: https://goteleport.com/docs/connect-your-client/third-party/gui-clients/
- AWS RDS IAM database authentication (tokens with a 15-minute lifetime): https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html
- HashiCorp Vault database secrets engine (dynamic, leased credentials): https://developer.hashicorp.com/vault/docs/secrets/databases
- HashiCorp Boundary credential injection (SSH and RDP targets): https://developer.hashicorp.com/boundary/docs/concepts/credential-management
- RFC 8705, OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens: https://datatracker.ietf.org/doc/html/rfc8705
- RFC 9449, OAuth 2.0 Demonstrating Proof of Possession (DPoP): https://datatracker.ietf.org/doc/html/rfc9449
- Microsoft Azure Architecture Center, Valet Key pattern: https://learn.microsoft.com/en-us/azure/architecture/patterns/valet-key

## Holding secrets apart from other code

- Apple, keychain access control lists (trusted applications for sensitive operations): https://developer.apple.com/documentation/security/secaccesscreate(_:_:_:)

## Covert channels

- Butler W. Lampson, "A Note on the Confinement Problem," Communications of the ACM 16(10), 1973: https://dl.acm.org/doi/10.1145/362375.362389

## The name

- Kahlil Gibran, *The Prophet* (Alfred A. Knopf, 1923), Project Gutenberg eBook #58585: https://www.gutenberg.org/ebooks/58585
