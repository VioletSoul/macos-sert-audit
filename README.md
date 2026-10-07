# macOS Certificate Audit v2

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-macOS-lightgrey.svg)](https://www.apple.com/macos/)
[![Shell](https://img.shields.io/badge/shell-POSIX%20sh-blue.svg)](https://pubs.opengroup.org/onlinepubs/9699919799/)
[![Status](https://img.shields.io/badge/status-v2--stable-brightgreen.svg)](#status)
[![ShellCheck](https://img.shields.io/badge/ShellCheck-compatible-brightgreen.svg)](https://www.shellcheck.net/)

A read-only macOS certificate, keychain, trust configuration, and configuration-profile audit utility.

`macos-cert-audit-v2.sh` is designed to inspect the certificate state of a macOS system, identify objects that deserve attention, and provide enough context to investigate them without modifying the machine.

---

## Status

**v2**

The v2 architecture is based on a canonical certificate model rather than independent checks performed directly against individual keychain entries.

The tool is intentionally read-only.

---

## What it does

The audit examines certificates available through the main macOS certificate stores:

- Apple System Root Certificates
- System Keychain
- Current user's Login Keychain

For each certificate, v2 builds a normalized record containing its identity, cryptographic properties, validity, CA role, trust-related metadata, and other X.509 attributes.

The resulting data is then classified into inventory information and security/review findings.

The goal is not to label every unusual certificate as malicious.

Instead, the audit distinguishes between:

- normal certificate inventory;
- legacy or informational conditions;
- configuration that deserves review;
- potentially actionable objects;
- critical findings.

---

## Key features

### Canonical certificate model

Each certificate is represented by a normalized record and identified primarily by its SHA-256 fingerprint.

This allows the audit to reason about certificates as objects rather than treating every keychain occurrence as a separate incident.

### Certificate role classification

Certificates are classified as:

- Root CA
- Intermediate CA
- Leaf certificate

The classification is based on CA status and cryptographic self-signature rather than on the certificate's subject name alone.

### Self-issued vs. self-signed

v2 deliberately distinguishes two different concepts.

**Self-issued**

```text
Subject == Issuer
```

**Cryptographically self-signed**

The certificate's signature successfully verifies against its own public key.

A certificate can therefore be self-issued without being cryptographically self-signed.

This distinction is important for cross-signed and other non-trivial certificate structures.

A self-issued but non-self-signed certificate is **not automatically considered a security finding**.

### Cryptographic inspection

The audit examines:

- public-key algorithm;
- RSA key size;
- EC curve;
- certificate signature algorithm;
- SHA-1 usage;
- Basic Constraints;
- Key Usage;
- Extended Key Usage;
- Subject Alternative Name;
- Subject Key Identifier;
- Authority Key Identifier;
- certificate policies.

Supported EC curves such as P-256, P-384, and P-521 are not incorrectly classified as weak keys.

RSA key strength is evaluated separately.

### Expiration analysis

Expired certificates are classified according to their context.

For example:

- expired Apple certificates may simply be stale objects;
- an expired custom certificate in the System Keychain deserves investigation;
- an expired certificate in a user's Login Keychain is treated differently from a system-wide object.

An expired certificate is **not automatically evidence of compromise**.

### SHA-1 handling

SHA-1 is treated according to certificate role.

Legacy SHA-1 root certificates are reported as inventory information rather than generating one warning per root.

SHA-1 signatures on intermediate or leaf certificates are treated as review-worthy findings.

This avoids turning a modern macOS installation containing legacy trust anchors into dozens of misleading alerts.

### Custom / non-Apple CA detection

The audit identifies non-Apple CA certificates installed in:

- System Keychain
- Login Keychain

A custom CA is not automatically considered malicious.

For example, software such as HTTPS inspection, enterprise security products, VPN clients, or filtering applications may legitimately install their own CA.

The tool therefore reports the object and asks for verification rather than recommending blind removal.

### Trust configuration

The audit separately reports explicit trust configuration, including:

- user trust overrides;
- administrator trust overrides;
- system trust configuration.

Trust settings are not mixed into certificate inventory or treated as equivalent to a complete effective certificate-chain validation result.

### Configuration Profiles / MDM

Where supported by the installed macOS `profiles` tooling, the audit reports:

- MDM enrollment status;
- configuration profile identifiers.

Profile information is intentionally kept separate from certificate findings.

---

## Findings model

v2 separates **severity** from **actionability**.

A finding can be informational without requiring any action, while another object may require investigation even if it is not evidence of malicious activity.

Current severity levels are:

| Severity | Meaning |
|---|---|
| `CRITICAL` | Immediate security attention is warranted |
| `WARNING` | Requires review or investigation |
| `INFO` | Informational or potentially stale configuration |

Findings are also assigned categories such as:

- `SECURITY`
- `STALE`
- `LEGACY_CRYPTO`
- `CUSTOM`

Multiple findings for the same certificate are aggregated using its canonical SHA-256 fingerprint.

For example, an expired certificate with a SHA-1 signature is reported as one certificate with two finding codes rather than as two unrelated certificate objects.

---

## What is *not* automatically a finding

The audit intentionally avoids several common false positives.

### SHA-1 root certificates

Legacy SHA-1 root certificates are reported as inventory:

```text
Legacy SHA-1 roots    30
```

They do not automatically generate 30 security warnings.

### Self-issued certificates

A certificate with:

```text
Subject == Issuer
```

is not automatically suspicious.

### Self-issued but not self-signed certificates

This can occur with valid certificate structures such as cross-signing.

It is therefore retained as a structural inventory property rather than being treated as a vulnerability by itself.

### Expired certificates

An expired certificate can simply be an obsolete object left in a keychain.

The audit therefore distinguishes stale Apple objects from expired custom certificates that may warrant investigation.

### Non-Apple CA certificates

A custom CA can be completely legitimate.

The correct question is:

> Was this CA intentionally installed, and is it still required?

The tool reports the object so that question can be answered.

---

## Usage

Make the script executable:

```sh
chmod +x macos-cert-audit-v2.sh
```

Run the complete audit:

```sh
./macos-cert-audit-v2.sh --all
```

The script can also be executed directly through POSIX `sh`:

```sh
sh macos-cert-audit-v2.sh --all
```

### Available modes

```sh
./macos-cert-audit-v2.sh --all
./macos-cert-audit-v2.sh --inventory
./macos-cert-audit-v2.sh --trust
./macos-cert-audit-v2.sh --forensic
./macos-cert-audit-v2.sh --json
```

Help:

```sh
./macos-cert-audit-v2.sh --help
```

---

## `--all`

Runs the complete human-readable audit.

The report includes:

1. host and operating-system information;
2. executive assessment;
3. certificate inventory;
4. expiration statistics;
5. cryptographic statistics;
6. custom/non-Apple CA inventory;
7. trust configuration;
8. configuration profiles / MDM;
9. aggregated findings.

Example:

```text
macOS Certificate Audit v2
================================
  Host                           MacBook-Pro.local
  Model                          MacBook Pro
  macOS                          26.7
  Architecture                   arm64
  OpenSSL                        LibreSSL 3.3.6

Mode        : READ-ONLY
Architecture: canonical certificate model
```

The executive section provides a high-level summary before the individual findings.

---

## `--inventory`

Displays the certificate inventory and structural information without focusing primarily on findings.

This mode is useful when the objective is to understand what is installed rather than investigate a particular warning.

---

## `--trust`

Displays trust-related configuration separately from the certificate inventory.

This includes explicit user and administrator trust overrides where available.

---

## `--forensic`

Provides a more detailed certificate-oriented view intended for investigation.

This mode is useful when a certificate needs to be examined beyond the executive assessment.

---

## `--json`

Produces machine-readable output intended for further processing or integration with other tooling.

The JSON mode is useful for:

- automation;
- CI pipelines;
- local security tooling;
- archiving audit results;
- further analysis with `jq` or similar tools.

---

## Default certificate stores

The audit examines the following stores:

```text
/System/Library/Keychains/SystemRootCertificates.keychain
/Library/Keychains/System.keychain
~/Library/Keychains/login.keychain-db
```

The exact contents and accessibility of these stores depend on the macOS version, system configuration, user permissions, and installed software.

---

## Collected certificate data

The canonical certificate model includes information such as:

- certificate identity;
- keychain store;
- certificate path;
- subject;
- issuer;
- SHA-256 fingerprint;
- SHA-1 fingerprint;
- certificate role;
- CA status;
- Basic Constraints;
- path length;
- self-issued status;
- cryptographic self-signature status;
- expiration status;
- vendor classification;
- public-key algorithm;
- public-key strength;
- signature algorithm;
- Key Usage;
- Extended Key Usage;
- Subject Alternative Name;
- Subject Key Identifier;
- Authority Key Identifier;
- certificate policies;
- EC curve.

The exact output may vary depending on the certificate and the information exposed by macOS.

---

## Safety

The audit is **read-only**.

It does not:

- install certificates;
- remove certificates;
- modify keychains;
- change trust settings;
- modify configuration profiles;
- change MDM configuration;
- alter system security settings.

Temporary files may be created during processing.

They are removed automatically when the script exits.

The script does not require destructive privileges to perform its audit.

---

## Requirements

- macOS
- `/usr/bin/security`
- `/usr/bin/openssl`
- POSIX-compatible `sh`
- standard macOS command-line utilities such as `awk`, `sed`, `grep`, `sort`, and `printf`

The script is designed around the tooling provided by macOS rather than requiring a separate certificate-management framework.

---

## Interpreting the results

The output should be treated as an **audit and investigation aid**, not as an automated verdict.

For example, consider:

```text
[WARNING] /C=EN/O=AdGuard/CN=Adguard Personal CA
    Store:    System Keychain
    Role:     ROOT CA
    Codes:    CUSTOM_CA_SYSTEM
```

This means:

> A non-Apple root CA exists in the System Keychain.

It does **not** mean:

> The system is compromised.

The appropriate next step is to determine whether the CA was intentionally installed and which application or service owns it.

Likewise:

```text
[INFO] /CN=NorthPole
    Store:    Login Keychain
    Role:     LEAF
    Codes:    EXPIRED_LOGIN
```

means that an expired non-Apple certificate exists in the user's Login Keychain.

It does not prove that the certificate is currently being used.

> The repository also contains independent validation checks used to
> cross-check certificate inventory against native macOS security tools.

---

## Limitations

The audit intentionally does not attempt to replace a full PKI or endpoint-management system.

Known limitations include:

- An expired certificate is not necessarily active, trusted, malicious, or in use.
- The audit does not perform complete certificate-chain validation for every possible usage context.
- Explicit trust settings are not equivalent to a complete effective trust decision for every certificate and every application.
- Certificate presence does not prove certificate usage.
- Some certificates may be inaccessible depending on macOS permissions or system configuration.
- Configuration profile and MDM information depends on the capabilities and behavior of the installed macOS `profiles` tooling.
- Third-party applications may maintain their own certificate stores outside the keychains examined by this tool.
- A certificate that is legitimate in one environment may be inappropriate in another.

This project is intended as a technical inspection and troubleshooting utility, not as a replacement for:

- enterprise endpoint management;
- PKI management;
- certificate lifecycle management;
- SIEM/EDR;
- incident response;
- full certificate-chain validation.

---

## Design philosophy

The central design principle of v2 is:

> **Do not confuse unusual with malicious.**

macOS systems commonly contain:

- old certificates;
- legacy trust anchors;
- application-specific certificates;
- cross-signed certificates;
- expired objects;
- custom enterprise or filtering CAs;
- certificates that are structurally unusual but valid.

A useful audit tool should provide enough information to distinguish these cases rather than simply producing a long list of red warnings.

v2 therefore separates:

```text
Certificate inventory
        ↓
Structural classification
        ↓
Cryptographic analysis
        ↓
Trust / configuration analysis
        ↓
Finding generation
        ↓
Severity + actionability
        ↓
Aggregated report
```

This architecture also makes the output more useful for forensic investigation and future automation.

---

## Read-only by design

There is intentionally no remediation functionality in this project.

The tool reports what it finds.

It does not decide that a certificate should be deleted, a trust setting should be changed, or a profile should be removed.

This is particularly important for certificates because blindly removing a certificate can break:

- HTTPS inspection;
- VPN connectivity;
- enterprise authentication;
- application signing;
- development tooling;
- network filtering;
- corporate security software;
- other system services.

Investigate first. Modify second.

---

## Project scope

`macos-cert-audit-v2.sh` focuses specifically on certificate and related security configuration visibility on macOS.

It is intentionally a small, self-contained POSIX shell utility rather than a large agent or daemon.

The project does not require:

- Python;
- Homebrew;
- third-party certificate libraries;
- background services;
- installation packages;
- persistent system configuration.

---

## License

MIT License.

Copyright (c) 2026 Serj Martinoff