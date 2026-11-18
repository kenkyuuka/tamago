# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

## 1.6.0 — 2026-11-18

### Added

- ANIM packs (`voice/*_wave.pck`, `cg/psbpack.dat`): extract and create. Packs have no signature, so tamago recognises them by checking that the index describes the file exactly. EOG audio is unwrapped to plain Ogg on extract (`--no-convert-eog` to opt out), and `.ogg` files are wrapped back as `.eog` on create (`--no-wrap-ogg` to opt out). Members are written sorted by name, ignoring case, as in the games' own packs.
- `tamago anim decrypt` and `tamago anim encrypt` for ANIM's enciphered single files (`*_sce.dat`, `*_define.dat`, `*_system.dat`, `cg/*.gax`), one file or a whole directory at a time. The engine accepts any key, so `encrypt` uses zeros unless given `--key`.
- YU-RIS YPF archives (versions 461–500): extract and create. Reading needs no per-game settings: the name key is recovered from the names, and each name's scrambled length is confirmed against the stored name hash, so archives using unusual length tables open too. Creating needs the version, name key and length table the game expects; `--like ARCHIVE` copies them from one of the game's own archives, or give `--version`, `--name-key` and `--length-table`. Archives from version 478 on use MurmurHash2 and 64-bit offsets, which tamago writes (a C accelerator speeds up hashing when it can be built). Versions 476 and 477, which other tools misread, are supported.
- YU-RIS YCG images: `--convert-ycg` on extract writes them as PNG, `--encode-ycg` on create converts PNGs back, and `tamago yuris decode-ycg` / `encode-ycg` convert files or directories. Only zlib-compressed YCGs are supported; the rarer "YSSnp" method has not been seen in a game.
- `tamago yuris decrypt` and `encrypt` for YU-RIS's compiled scripts (`ysbin/yst*.ybn`). The per-game key is recovered from the scripts themselves, or can be given with `--key`. In a directory, other files are copied unchanged so the result can be packed again.
- BlackRainbow ADVDX archives (`image/*.dat`, `voice/*.pak`, `script.dat`, `*_spt.dat`...): extract and create. Archives have no signature, so tamago recognises them by their slot table. The engine finds members by slot number, so extraction writes a manifest (`_advdx_manifest.json`) recording each member's slot and stored name, the header's game ID and any trailing bytes. Unnamed members are extracted under their slot number (`017.bmd`). Rebuilding from the manifest reproduces the original archive byte for byte, except where an overlong name had overwritten its size field: tamago writes the correct size there. Without a manifest, `--kind`, `--game-id` and `--slots` set the header.
- BlackRainbow `_BMD` images: `--convert-bmd` on extract writes them as PNG, and create encodes PNGs in image archives back to `_BMD`. `tamago blackrainbow decode-bmd` / `encode-bmd` convert files or directories.
- E-mote PSB files (versions 2–4), as found in ANIM's `psbpack.dat`: `tamago psb extract` decompiles one to JSON, its resource chunks and its texture atlases as PNG (RGBA8, A8L8, A8, L8, RGBA4444, RL, DXT1, DXT5), and `tamago psb create` compiles it back, byte for byte as E-mote's own files, encryption included. The key is recovered from version 3 and 4 headers, and ANIM's key is built in for version 2; `--key` gives another. `tamago psb decrypt` writes a plain copy, and `tamago psb info` describes a file. The `tamago.formats.psb` library reads and writes value trees directly.

## 1.5.0 — 2026-11-13

### Added

- MED: convert PRS images to PNG and WADY music to WAV on extract (`--no-convert-prs` and `--no-convert-wady` to opt out). Members are recognised by their contents, and `.png` or `.wav` is appended to the member name. Conversion is one-way: extract with the opt-out flags to recreate an archive. WADY files in the rarer "v2" coding, not seen in any game so far, are extracted unconverted with a warning.

### Fixed

- README: removed the instructions for an `images` extra that does not exist. Image conversion works with a plain `pip install tamagoarc`.

## 1.4.0 — 2026-11-13

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
