#!/usr/bin/env python3
"""Survey installed KiriKiri games for XP3 files and encryption status.

Scans a directory tree for XP3 archives, identifies encryption TPMs,
hashes them, and cross-references against the encryption_library.toml
to report known vs unknown encryption schemes.

When --update is passed, delegates to identify_encryption (with --no-frida)
for each game directory with unknown or incomplete library entries.

Usage:
    python scripts/survey_installed_games.py [SCAN_DIR]
    python scripts/survey_installed_games.py [SCAN_DIR] --update
"""

import argparse
import logging
import os
import sys
import tomllib
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from tamago.formats.xp3 import XP3File
from tamago.formats.xp3.detect import (
    UTILITY_TPMS,
    XP3_MAGIC,
    build_tpm_index,
    hash_file,
    hash_xp3_structure,
    load_library,
)
from identify_encryption import verify_unencrypted


def _build_tpm_key_index(library):
    """Build mapping from TPM hash -> game key (without the full entry)."""
    index = {}
    for game_key, entry in library.get("games", {}).items():
        for h in entry.get("tpm_hashes", []):
            index[h] = game_key
    return index


def _build_xp3_hash_set(library):
    """Build the set of all XP3 hashes already in the library."""
    known = set()
    for entry in library.get("games", {}).values():
        for h in entry.get("xp3_hashes", []):
            known.add(h)
    return known


def check_xp3_encrypted_flags(xp3_path):
    """Open an XP3 and check whether any files have the encrypted flag set.

    Returns (total_files, encrypted_count) or None on error.
    """
    try:
        with XP3File(xp3_path) as xp3:
            encrypted_count = sum(1 for info in xp3.files if info.encrypted)
            return len(xp3.files), encrypted_count
    except Exception:
        return None


def find_xp3_games(scan_dir):
    """Find all directories containing valid XP3 files.

    Returns dict mapping game_dir -> list of xp3 file paths.
    """
    games = defaultdict(list)
    for root, dirs, files in os.walk(scan_dir):
        for f in files:
            if f.lower().endswith(".xp3"):
                path = os.path.join(root, f)
                try:
                    with open(path, "rb") as fh:
                        if fh.read(11) == XP3_MAGIC:
                            games[root].append(path)
                except OSError:
                    pass
    for k in games:
        games[k].sort()
    return dict(sorted(games.items()))


def find_encryption_tpms(game_dir):
    """Find encryption-related TPM files in a game directory.

    Returns (encryption_tpms, utility_tpms) as lists of paths.
    """
    enc_tpms = []
    util_tpms = []
    for root, dirs, files in os.walk(game_dir):
        for f in files:
            if f.lower().endswith(".tpm"):
                path = os.path.join(root, f)
                if f.lower() in UTILITY_TPMS:
                    util_tpms.append(path)
                else:
                    enc_tpms.append(path)
    return sorted(enc_tpms), sorted(util_tpms)


def get_publisher_and_game(path, scan_dir):
    """Extract publisher and game name from path relative to scan_dir."""
    rel = os.path.relpath(path, scan_dir)
    parts = rel.split(os.sep)
    publisher = parts[0] if len(parts) >= 1 else "Unknown"
    game = parts[1] if len(parts) >= 2 else parts[0]
    return publisher, game


def get_scan_dir(args):
    """Get scan directory from CLI args or local.toml."""
    if args.scan_dir:
        return os.path.abspath(args.scan_dir)

    project_root = Path(__file__).resolve().parent.parent
    conf_path = project_root / "local.toml"
    if conf_path.exists():
        with open(conf_path, "rb") as f:
            config = tomllib.load(f)
        scan_dir = config.get("paths", {}).get("survey_scan_dir")
        if scan_dir:
            return os.path.abspath(scan_dir)

    print("Usage: python scripts/survey_installed_games.py [SCAN_DIR]", file=sys.stderr)
    print("Or set paths.survey_scan_dir in local.toml", file=sys.stderr)
    sys.exit(1)


def collect_missing_xp3_hashes(tpm_groups, tpm_index, known_xp3_hashes, games):
    """Find XP3 structure hashes that should be in the library but aren't.

    For each game directory with a known TPM hash, compute XP3 structure
    hashes for all non-patch XP3 files. Return a dict mapping
    game_key -> list of (xp3_hash, xp3_basename, game_label) for new hashes.
    """
    missing = defaultdict(list)  # game_key -> [(hash, basename, label)]

    for tpm_hash, entries in tpm_groups.items():
        game_key = tpm_index.get(tpm_hash)
        if game_key is None:
            continue

        for publisher, game, tpm_path, game_dir in entries:
            xp3_files = games.get(game_dir, [])
            label = f"{publisher} - {game}"

            for xp3_path in xp3_files:
                basename = os.path.basename(xp3_path)
                if basename.startswith("patch"):
                    continue
                try:
                    h = hash_xp3_structure(xp3_path)
                except Exception as e:
                    print(f"  WARNING: could not hash {label}/{basename}: {e}", file=sys.stderr)
                    continue
                if h not in known_xp3_hashes:
                    missing[game_key].append((h, basename, label))

    return dict(missing)


def _collect_update_dirs(tpm_groups, tpm_index, missing, no_tpm_encrypted=None):
    """Collect unique game directories that need updating.

    Returns a list of game_dir paths — games with unknown TPM hashes,
    games with known TPMs but missing XP3 hashes, and no-TPM games
    with genuinely encrypted files.
    """
    dirs = set()

    # Unknown TPM hash groups
    for tpm_hash, entries in tpm_groups.items():
        if tpm_hash not in tpm_index:
            for _pub, _game, _tpm, game_dir in entries:
                dirs.add(game_dir)

    # Known games with missing XP3 hashes
    for game_key, hash_entries in missing.items():
        for _h, _basename, label in hash_entries:
            # Recover game_dir from tpm_groups
            for tpm_hash, tpm_entries in tpm_groups.items():
                if tpm_index.get(tpm_hash) == game_key:
                    for _pub, _game, _tpm, game_dir in tpm_entries:
                        dirs.add(game_dir)

    # No-TPM games with genuinely encrypted files
    if no_tpm_encrypted:
        for _pub, _game, _xp3_name, _result, gdir in no_tpm_encrypted:
            dirs.add(gdir)

    return sorted(dirs)


def main():
    parser = argparse.ArgumentParser(description="Survey installed KiriKiri games for XP3 encryption status.")
    parser.add_argument("scan_dir", nargs="?", default=None, help="Directory to scan")
    parser.add_argument("--update", action="store_true", help="Run identify_encryption for games needing updates")
    parser.add_argument("--dry-run", action="store_true", help="With --update, pass --dry-run to identify_encryption")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Show full details (known groups, no-TPM games, etc.)"
    )
    args = parser.parse_args()

    scan_dir = get_scan_dir(args)

    if not os.path.isdir(scan_dir):
        print(f"Error: {scan_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    library = load_library()
    tpm_index = _build_tpm_key_index(library)
    known_xp3_hashes = _build_xp3_hash_set(library)

    print(f"Scanning: {scan_dir}")
    print(f"Known TPM hashes in library: {len(tpm_index)}")
    print(f"Known XP3 hashes in library: {len(known_xp3_hashes)}")
    print()

    # Find all games
    games = find_xp3_games(scan_dir)

    # Suppress XP3File warnings about encrypted files during scanning
    logging.getLogger("xp3file").setLevel(logging.ERROR)

    # Collect TPM hash groups
    tpm_groups = defaultdict(list)  # hash -> [(publisher, game, tpm_path, game_dir)]
    no_tpm_games = []  # [(publisher, game, xp3_names, game_dir, enc_flags)]

    for game_dir, xp3_files in games.items():
        publisher, game = get_publisher_and_game(game_dir, scan_dir)
        enc_tpms, util_tpms = find_encryption_tpms(game_dir)

        if enc_tpms:
            for tpm in enc_tpms:
                h = hash_file(tpm)
                tpm_groups[h].append((publisher, game, tpm, game_dir))
        else:
            xp3_names = [os.path.basename(x) for x in xp3_files]
            enc_flags = {}
            for xp3 in xp3_files:
                enc_flags[os.path.basename(xp3)] = check_xp3_encrypted_flags(xp3)
            no_tpm_games.append((publisher, game, xp3_names, game_dir, enc_flags))

    # --- Classify data for reporting ---

    # Separate known vs unknown TPM groups
    unknown_tpm_groups = {}
    known_tpm_groups = {}
    for h, entries in tpm_groups.items():
        if h in tpm_index:
            known_tpm_groups[h] = entries
        else:
            unknown_tpm_groups[h] = entries

    # Classify no-TPM games — only warn about games that are genuinely encrypted
    no_tpm_surprise_encrypted = []
    for pub, game, xp3_names, gdir, enc_flags in no_tpm_games:
        has_encrypted_flag = any(r is not None and r[1] > 0 for r in enc_flags.values())
        if not has_encrypted_flag:
            continue
        # Check if files are actually encrypted by reading raw magic bytes
        xp3_paths = games.get(gdir, [])
        confirmed, checked, failed = verify_unencrypted(xp3_paths)
        if confirmed:
            continue  # Magic bytes intact — encryption flag is cosmetic
        for xp3_name, result in enc_flags.items():
            if result is not None and result[1] > 0:
                no_tpm_surprise_encrypted.append((pub, game, xp3_name, result, gdir))

    missing = collect_missing_xp3_hashes(tpm_groups, tpm_index, known_xp3_hashes, games)
    total_missing = sum(len(v) for v in missing.values())

    verbose = args.verbose

    # --- Verbose: full TPM group listing ---

    if verbose:
        print("=" * 80)
        print("TPM HASH GROUPS (encrypted games)")
        print("=" * 80)

        for i, (h, entries) in enumerate(sorted(tpm_groups.items(), key=lambda x: -len(x[1])), 1):
            game_key = tpm_index.get(h)
            status = f"KNOWN: {game_key}" if game_key else "UNKNOWN"
            print(f"\nGroup {i}: {h}")
            print(f"  Status: {status}")
            print(f"  Games ({len(entries)}):")
            for pub, game, tpm, gdir in entries:
                tpm_name = os.path.basename(tpm)
                print(f"    [{pub}] {game} (TPM: {tpm_name})")
                if not game_key:
                    print(f"      {gdir}")

        print()
        print("=" * 80)
        print("NO-TPM GAMES")
        print("=" * 80)

        by_publisher = defaultdict(list)
        for pub, game, xp3_names, gdir, enc_flags in no_tpm_games:
            by_publisher[pub].append((game, xp3_names, gdir, enc_flags))

        for pub in sorted(by_publisher.keys()):
            entries = by_publisher[pub]
            print(f"\n  {pub} ({len(entries)} games):")
            for game, xp3_names, gdir, enc_flags in entries:
                total_enc = 0
                total_files = 0
                errors = 0
                for xp3_name in xp3_names:
                    result = enc_flags.get(xp3_name)
                    if result is None:
                        errors += 1
                    else:
                        total_files += result[0]
                        total_enc += result[1]
                if total_enc > 0:
                    status = f"ENCRYPTED ({total_enc}/{total_files} files flagged!)"
                elif errors > 0:
                    status = f"unencrypted ({total_files} files checked, {errors} XP3s failed to open)"
                else:
                    status = f"unencrypted ({total_files} files checked)"
                print(f"    {game}")
                print(f"      XP3: {', '.join(xp3_names)}")
                print(f"      Flags: {status}")

    # --- Always: warnings about no-TPM encrypted games ---

    if no_tpm_surprise_encrypted:
        print()
        print("*** WARNING: No-TPM games with encrypted flags set ***")
        for pub, game, xp3_name, (total, enc), gdir in no_tpm_surprise_encrypted:
            print(f"  [{pub}] {game} / {xp3_name}: {enc}/{total} files encrypted")
            print(f"    {gdir}")

    # --- Always: unknown TPM groups ---

    if unknown_tpm_groups:
        print()
        print("=" * 80)
        print("UNKNOWN ENCRYPTION")
        print("=" * 80)

        for i, (h, entries) in enumerate(sorted(unknown_tpm_groups.items(), key=lambda x: -len(x[1])), 1):
            print(f"\n  TPM hash: {h}")
            print(f"  Games ({len(entries)}):")
            for pub, game, tpm, gdir in entries:
                tpm_name = os.path.basename(tpm)
                print(f"    [{pub}] {game} (TPM: {tpm_name})")
                print(f"      {gdir}")

    # --- Always: missing XP3 hashes ---

    if missing:
        print()
        print("=" * 80)
        print("MISSING XP3 HASHES")
        print("=" * 80)
        for game_key, entries in sorted(missing.items()):
            by_label = defaultdict(list)
            for h, basename, label in entries:
                by_label[label].append(basename)
            print(f"\n  {game_key}:")
            for label, basenames in sorted(by_label.items()):
                print(f"    {label}: {', '.join(sorted(basenames))}")

    # --- Always: summary ---
    print()
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    total_games = len(games)
    enc_games = sum(len(v) for v in tpm_groups.values())
    print(f"  Total game directories with XP3 files: {total_games}")
    print(f"  Games with encryption TPM: {enc_games}")
    print(f"  Games without encryption TPM: {len(no_tpm_games)}")
    if no_tpm_surprise_encrypted:
        print(f"  *** No-TPM games with encrypted flags: {len(no_tpm_surprise_encrypted)} ***")
    print(f"  Unique TPM hashes: {len(tpm_groups)}")
    print(f"  Known TPM hashes: {len(known_tpm_groups)}")
    print(f"  Unknown TPM hashes: {len(unknown_tpm_groups)}")
    if total_missing:
        print(f"  Missing XP3 hashes: {total_missing} (across {len(missing)} library entries)")

    # --- Update via identify_encryption ---

    if args.update:
        update_dirs = _collect_update_dirs(tpm_groups, tpm_index, missing, no_tpm_surprise_encrypted)
        if not update_dirs:
            print("\n  Nothing to update.")
            return

        from identify_encryption import identify_encryption

        print()
        print("=" * 80)
        print(f"RUNNING IDENTIFY_ENCRYPTION (no Frida) on {len(update_dirs)} game(s)")
        print("=" * 80)

        for game_dir in update_dirs:
            print(f"\n{'─' * 60}")
            exit_code, report = identify_encryption(
                game_dir=game_dir,
                use_frida=False,
                dry_run=args.dry_run,
                output_dir=os.path.join(os.getcwd(), 'survey_results', os.path.basename(game_dir)),
            )
            status = {0: "OK", 1: "unencrypted", 2: "failed"}
            print(f"  Result: {status.get(exit_code, f'exit {exit_code}')}")
    elif missing or any(h not in tpm_index for h in tpm_groups) or no_tpm_surprise_encrypted:
        unknown_count = sum(1 for h in tpm_groups if h not in tpm_index)
        parts = []
        if unknown_count:
            parts.append(f"{unknown_count} unknown TPM group(s)")
        if total_missing:
            parts.append(f"{total_missing} missing XP3 hash(es)")
        if no_tpm_surprise_encrypted:
            # Count unique game directories
            enc_dirs = len({gdir for _p, _g, _x, _r, gdir in no_tpm_surprise_encrypted})
            parts.append(f"{enc_dirs} no-TPM encrypted game(s)")
        print(f"\n  Run with --update to process {' and '.join(parts)} via identify_encryption.")


if __name__ == "__main__":
    main()
