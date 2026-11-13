# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Added

- DxLib DXA archives, versions 1 to 4: extract, including LZ-compressed members and nested directories, and create version 4 with an optional password and `--compress`. The key is recovered from the archive itself, so password-protected archives extract without their password. Encrypted DXA archives have no fixed signature, so tamago recognises them by recovering the key and parsing the index, whatever the file extension.
- Fudegaki Soft "MD" archives (`md_gra.med`, `md_bgm.med`, `md_scr.med`...): extract and create. Script archives are decrypted with a per-game keyword that tamago recovers from the archive's `_VIEW` script and reports, so it can be passed back with `--keyword` when recreating the archive. The scripts' running counters are recomputed on create. `--no-decrypt` extracts scripts as stored.

## 1.3.0 — 2026-11-03

### Added

- Ren'Py RPA archives: extract RPA-1.0, RPA-2.0 and RPA-3.0, and create RPA-3.0. Archive indexes are pickles, so tamago loads them with a restricted unpickler that cannot run code from the archive, and refuses to extract members whose names would land outside the output directory.

### Fixed

- Extraction refuses archives whose member names would land outside the output directory, such as `../escaped.txt`, before writing anything. Previously a crafted ARC, DET, GSP, VF or XP3 archive could write files anywhere the user could write. Names containing `..` that stay inside the output directory still extract.
- XP3: `extract_all` treats `\` in member names as a directory separator, like the other formats.

## 1.2.0 — 2026-11-01

### Added

- Ship a `py.typed` marker so type checkers use tamago's inline annotations.
- XP3: `auto_detect()` takes a `quiet` argument to stop it printing the `encryption_library.toml` snippet to stderr when the probe stage finds a match.

### Fixed

- XP3: `XP3File.write` closes the source file after reading it. Previously every call left a file handle open and raised a `ResourceWarning`.

## 1.1.1 — 2026-10-29

### Fixed

- XP3: decrypt segments after inflating them, and encrypt before compressing, as the engine does. Previously, compressed files that were also encrypted came out garbled, and archives tamago created with encryption could not be read by the game.
- XP3: decrypt archives whose file table leaves every per-file encrypted flag clear, as the engine does. Previously these extracted without error but with garbled contents (affects HashCrypt games from Ammolite, Apadash, Appetite and others).

## 1.1.0 — 2026-04-19

### Added

- LiveMaker VF archive support (embedded, standalone, and multi-part configurations).
- LiveMaker: convert Gale images (classic and GaleX200) to PNG on extract (`--no-convert-gal` to opt out).
- XP3: decode KiriKiri "simple crypt" text files on extract (`--no-decode-text` to opt out).

### Changed

- XP3: `XP3File` accepts `compresslevel` to control zlib compression on write.
- Tests: nonfree suite ~85% faster, full suite ~72% faster.

## 1.0.1 — 2026-04-17

### Fixed

- Packaging fix.

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
