# Security Policy

## Supported versions

LiberaCrypt does not currently publish stable releases. Security fixes are developed against the current `main` branch. If you discover a problem in an older commit, please check whether it is reproducible on the current `main` branch when practical.

This policy will be updated with explicit supported release ranges once versioned releases are published.

## Reporting a vulnerability

**Do not report a suspected security vulnerability in a public GitHub issue, discussion, pull request, or public proof of concept before coordinated disclosure.**

Use GitHub's private vulnerability reporting for this repository:

- Open the repository's **Security** page and choose **Report a vulnerability**; or
- use the repository security advisory reporting form directly: <https://github.com/samdae5back/LiberaCrypt/security/advisories/new>.

If private vulnerability reporting is temporarily unavailable, open a public issue containing only a request for a private security contact. Do not include vulnerability details, exploit steps, proof-of-concept code, keys, credentials, or other sensitive material in that public issue.

## What to include

A useful report should include, when applicable:

- the affected commit, tag, component, algorithm, or API;
- affected operating systems, architectures, compilers, or build configurations;
- the security impact and attacker prerequisites;
- clear reproduction steps or a minimal proof of concept;
- expected and observed behavior;
- any suggested mitigation or fix; and
- whether the issue or similar details have already been disclosed elsewhere.

Do not include real credentials, production keys, private user data, or other unrelated secrets in a report.

## Security-relevant scope

Reports are especially useful for issues involving:

- cryptographic correctness or standards conformance;
- key, nonce, IV, tag, signature, or ciphertext validation;
- randomness, DRBG behavior, or entropy handling;
- memory safety, integer/range errors, or undefined behavior;
- timing or other side-channel behavior where the implementation makes a relevant security claim;
- authentication or verification bypasses;
- insecure failure handling or secret-data lifetime;
- build, export, packaging, or portability behavior that changes security properties; and
- bundled third-party code or provenance that creates a security risk.

## Disclosure process

Reports will be triaged privately. When a vulnerability is confirmed, the maintainer will coordinate a fix and disclosure with the reporter where practical. A GitHub Security Advisory and CVE may be published when appropriate.

Please allow time for investigation and cross-platform validation before public disclosure, especially when a fix affects cryptographic behavior or portability-sensitive code.

LiberaCrypt currently does not operate a paid bug-bounty program.
