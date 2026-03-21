# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | Yes                |

## Reporting a Vulnerability

If you discover a security vulnerability in IronDivi, please report it responsibly. **Do not open a public GitHub issue.**

Email **[security@cri.xyz](mailto:security@cri.xyz)** with:

- A description of the vulnerability.
- Steps to reproduce or a proof of concept.
- The affected component(s) and version(s).
- Any potential impact assessment.

## Response Timeline

- **48 hours**: We will acknowledge receipt of your report.
- **7 days**: We will provide an initial assessment and severity classification.
- **90 days**: We aim to develop and release a fix within 90 days of the initial report. If a fix requires more time, we will communicate a revised timeline.

## Scope

The following categories of issues are in scope for security reports:

- **Consensus bugs**: Issues that could cause chain splits, invalid block acceptance, or rejection of valid blocks.
- **Key material exposure**: Vulnerabilities that could leak private keys, mnemonics, or wallet data.
- **Network denial of service**: Bugs that allow a remote attacker to crash or stall a node.
- **RPC authentication bypass**: Issues that allow unauthenticated access to protected RPC methods.
- **Double-spend vulnerabilities**: Any issue enabling the same UTXO to be spent more than once.
- **Memory safety issues**: Buffer overflows, use-after-free, or other memory corruption (even in unsafe blocks or FFI).

## Out of Scope

- Issues in third-party dependencies (report those upstream, but let us know so we can assess impact).
- Social engineering or phishing attacks.
- Denial of service via resource exhaustion that requires authenticated RPC access.

## Disclosure Policy

We follow coordinated disclosure. We ask that you:

1. Give us reasonable time to investigate and fix the issue before public disclosure.
2. Do not exploit the vulnerability beyond what is necessary to demonstrate it.
3. Do not access or modify other users' data.

We will credit reporters in the release notes (unless you prefer to remain anonymous).

## PGP Key

If you need to encrypt your report, request our PGP key by emailing [security@cri.xyz](mailto:security@cri.xyz) with the subject line "PGP Key Request".
