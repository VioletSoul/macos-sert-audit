# macos-sert-audit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-macOS-lightgrey.svg)](https://www.apple.com/macos/)
[![Shell](https://img.shields.io/badge/shell-POSIX%20sh-blue.svg)](https://pubs.opengroup.org/onlinepubs/9699919799/)
[![Status](https://img.shields.io/badge/status-work--in--progress-orange.svg)](#status)
[![ShellCheck](https://img.shields.io/badge/ShellCheck-compatible-brightgreen.svg)](https://www.shellcheck.net/)

Read-only macOS certificate, keychain, explicit trust settings, and basic MDM/profile audit tool.

## Status

Work in progress.

## Description

A lightweight POSIX shell utility for auditing certificates available through macOS keychains.

It collects X.509 certificate metadata, validity and expiration status, CA and self-issued status, key usage information, explicit trust settings, and basic configuration profile / MDM enrollment information.

The tool is designed for inspection and analysis. It does not modify the system.

## Requirements

- macOS
- `/usr/bin/security`
- `/usr/bin/openssl`
- POSIX-compatible `sh`

## Usage

```sh
chmod +x macos-cert-audit.sh
./macos-cert-audit.sh
```

Available modes:

```sh
./macos-cert-audit.sh --compact
./macos-cert-audit.sh --expired
./macos-cert-audit.sh --roots
./macos-cert-audit.sh --user
./macos-cert-audit.sh --interesting
./macos-cert-audit.sh --trust
./macos-cert-audit.sh --data
```

The default audit scans:

- Apple System Root Certificates store
- System keychain
- Current user's Login keychain

Exclude Apple’s System Root Certificates store when a faster, narrower scan is needed:

```sh
./macos-cert-audit.sh --no-system-roots
```

## Collected Data

For each certificate, the audit collects:

- Keychain store name
- Subject and issuer
- Serial number
- Validity period
- SHA-256 fingerprint
- CA status
- Self-issued status
- Key usage information
- Expiration status

`Self-issued` means that the certificate Subject and Issuer fields are identical. This indicator alone does not cryptographically prove that a certificate is self-signed.

The `--trust` mode displays explicit trust settings reported by macOS for user, admin, and system scopes where available.

The default report also includes basic configuration profile and MDM enrollment information when supported by the installed `profiles` command.

## Safety

The script operates in read-only mode.

It does not install, remove, modify, or change the trust state of certificates, keychains, configuration profiles, or MDM settings.

The script creates temporary files only for processing certificate data and removes them automatically when it exits.

## Limitations

- An expired certificate is not necessarily active, trusted, malicious, or in use by an application.
- The audit does not perform full certificate-chain validation for every certificate and possible usage context.
- Explicit trust settings are not equivalent to a complete effective trust decision for every certificate.
- Some keychains, profiles, or MDM details may be inaccessible depending on macOS version, user permissions, and device-management configuration.
- This project is intended as a technical inspection utility, not as a replacement for enterprise endpoint management, incident response, or certificate lifecycle management tools.

## License

MIT License.

Copyright (c) 2026 Serj Martinoff