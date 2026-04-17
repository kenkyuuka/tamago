# Changelog

All notable changes to this project will be documented in this file.

## 1.0.1 — 2026-04-17

Packaging fix.

## 1.0.0 — 2026-04-14

Initial release.

### Features

- Unified CLI (`tamago`) with `extract`, `create`, and `identify` commands
- Auto-detection of archive formats by magic bytes
- Python API for reading and writing archives
- Plugin system for format handlers and XP3 encryption schemes

### Supported formats

- **XP3** ([KiriKiri](https://github.com/kenkyuuka/research-vault/blob/main/engines/KiriKiri.md)) — extract and create, with encryption support
- **DET** ([μ-GameOperationSystem](https://github.com/kenkyuuka/research-vault/blob/main/engines/%CE%BC-GameOperationSystem.md)) — extract and create, ATM and AT2 index formats
- **GSP** ([AGSD](https://github.com/kenkyuuka/research-vault/blob/main/engines/AGSD.md)) — extract and create
- **ARC** (AdvHD / WillPlus V2) — extract and create, with script decryption and LZSS decompression

### XP3 encryption

- Automatic encryption detection (TPM hash lookup, XP3 structure hash, probing)
- Built-in schemes: hash-xor, fixed-xor, null, poringsoft, cxcrypt, pinpoint
- Known-game database (`encryption_library.toml`)

### Images

- TLG image decoding (TLG5, TLG6) with optional Pillow integration
