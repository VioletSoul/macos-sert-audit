# macos-sert-audit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-macOS-lightgrey.svg)](https://www.apple.com/macos/)
[![Shell](https://img.shields.io/badge/shell-POSIX%20sh-blue.svg)](https://pubs.opengroup.org/onlinepubs/9699919799/)
[![Status](https://img.shields.io/badge/status-work--in--progress-orange.svg)](#status)
[![ShellCheck](https://img.shields.io/badge/ShellCheck-compatible-brightgreen.svg)](https://www.shellcheck.net/)

Read-only macOS certificate, keychain, and trust settings audit tool.

## Status

Work in progress.

## Description

A lightweight POSIX shell utility for auditing certificates available through macOS keychains and collecting X.509 metadata, certificate status, trust settings, and basic profile/MDM information.

The tool is designed for inspection and analysis. It does not modify the system.

## Requirements

- macOS
- `/usr/bin/security`
- OpenSSL
- POSIX-compatible `sh`

## Usage

```sh
chmod +x macos-cert-audit.sh
./macos-cert-audit.sh
```

Available modes:

```sh
./macos-cert-audit.sh --expired
./macos-cert-audit.sh --roots
./macos-cert-audit.sh --user
./macos-cert-audit.sh --interesting
./macos-cert-audit.sh --trust
./macos-cert-audit.sh --data
```

The default audit scans the System Root Certificates keychain, the System keychain, and the current user's Login keychain.

The system root store can be excluded with:

```sh
./macos-cert-audit.sh --no-system-roots
```

## Collected Data

The audit collects certificate subject and issuer, serial number, validity period, SHA-256 fingerprint, CA status, self-signed status, key usage information, and expiration status.

Trust settings are collected separately where available.

The report also includes basic macOS configuration profile and MDM enrollment information when supported by the installed `profiles` command.

## Safety

The script operates in read-only mode.

It does not install, remove, modify, or change the trust state of certificates, keychains, configuration profiles, or MDM settings.

## License

MIT License.

Copyright (c) 2026 Serj Martinoff