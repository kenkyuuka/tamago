#!/usr/bin/env python3
"""Survey installed games for engine identification.

Scans a directory tree for folders containing Windows executables, runs
engine identification on each, extracts PE version info from every
executable, and groups games by version fingerprint.

No assumptions are made about the directory structure — any folder at
any depth that directly contains executable files (.exe, .dll, .scr)
is treated as a potential game folder.

Usage:
    python scripts/survey_engines.py [SCAN_DIR]
    python scripts/survey_engines.py [SCAN_DIR] -v
"""

import argparse
import os
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

from karakuri.identify import _get_pe_version_strings, identify_engine, load_engine_library

# Extensions that qualify a directory as a game (must have at least one .exe).
_GAME_EXE_EXTENSION = ".exe"

# Executables that are generic runtimes, installers, or utilities — not game
# launchers.  A directory containing *only* these does not qualify as a game
# directory, but they do not prevent qualification if a non-ignored exe is
# also present.
_IGNORED_EXES = {
    "directx_Jun2010_redist.exe",
    "DXSETUP.exe",
    "dxwebsetup.exe",
    "python.exe",
    "pythonw.exe",
    "setup.exe",
    "uninstall.exe",
    "unins000.exe",
    "zsync.exe",
    "zsyncmake.exe",
}

# All PE executable extensions scanned for version info within a game directory.
_PE_EXTENSIONS = {".exe", ".dll", ".scr"}

# PE version info fields used to build the grouping fingerprint.
# These identify the engine and its build; other fields (LegalCopyright,
# FileDescription) tend to vary per game and are less useful for grouping.
_FINGERPRINT_FIELDS = (
    "ProductName",
    "ProductVersion",
    "FileVersion",
    "InternalName",
    "OriginalFilename",
    "CompanyName",
)


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

    print("Usage: python scripts/survey_engines.py [SCAN_DIR]", file=sys.stderr)
    print("Or set paths.survey_scan_dir in local.toml", file=sys.stderr)
    sys.exit(1)


def find_game_dirs(scan_dir):
    """Find the deepest directories that contain ``.exe`` files.

    Only ``.exe`` files count — directories with only ``.dll`` or ``.scr``
    are not considered games.  When a directory containing an ``.exe`` has
    a descendant that also contains one, only the descendant is kept.  This
    prevents installer/launcher directories from appearing as separate games
    when the actual game executable lives in a subdirectory.

    Returns a sorted list of absolute path strings.
    """
    # Collect every directory that directly contains a non-ignored .exe.
    exe_dirs = set()
    for root, _dirs, files in os.walk(scan_dir):
        if any(f.lower().endswith(_GAME_EXE_EXTENSION) and f.lower() not in _IGNORED_EXES for f in files):
            exe_dirs.add(root)

    # Prune ancestors: if dir A is a proper ancestor of dir B, and both
    # are in exe_dirs, remove A.  We only keep the deepest directories.
    pruned = set(exe_dirs)
    for d in exe_dirs:
        # Walk each proper ancestor up to (but not including) scan_dir.
        parent = os.path.dirname(d)
        while parent != d and len(parent) >= len(scan_dir):
            pruned.discard(parent)
            parent = os.path.dirname(parent)

    return sorted(pruned)


def _relative_label(game_dir, scan_dir):
    """Return a human-readable label for a game directory."""
    return os.path.relpath(game_dir, scan_dir)


def _collect_exe_version_info(game_dir, *, include_dlls=False):
    """Extract PE version info from executables directly in *game_dir*.

    By default only ``.exe`` files are scanned.  Set *include_dlls* to
    also scan ``.dll`` and ``.scr`` files.

    Returns a list of (exe_name, version_strings_dict) for executables
    that have version info, plus a list of exe names without version info.
    """
    extensions = _PE_EXTENSIONS if include_dlls else {_GAME_EXE_EXTENSION}
    with_info = []
    without_info = []
    try:
        for p in sorted(Path(game_dir).iterdir()):
            if p.is_file() and p.suffix.lower() in extensions:
                strings = _get_pe_version_strings(p)
                if strings:
                    with_info.append((p.name, strings))
                else:
                    without_info.append(p.name)
    except OSError:
        pass
    return with_info, without_info


def _version_fingerprint(version_strings):
    """Build a hashable fingerprint from a PE version info dict."""
    pairs = []
    for field in _FINGERPRINT_FIELDS:
        value = version_strings.get(field, "").strip()
        if value:
            pairs.append((field, value))
    return tuple(pairs)


def _format_fingerprint(fingerprint):
    """Format a fingerprint tuple as a compact string for display."""
    return ", ".join(f"{field}={value!r}" for field, value in fingerprint)


def _format_version_strings(strings):
    """Format all version string fields for display."""
    lines = []
    for field in sorted(strings.keys()):
        lines.append(f"{field}: {strings[field]}")
    return lines


def main():
    parser = argparse.ArgumentParser(
        description="Survey installed games for engine identification and PE version info."
    )
    parser.add_argument("scan_dir", nargs="?", default=None, help="Directory to scan")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show full details including engine evidence")
    parser.add_argument(
        "--unknown-only",
        action="store_true",
        help="Hide directories with 100%% confidence matches (known builds or sufficient rules)",
    )
    args = parser.parse_args()

    scan_dir = get_scan_dir(args)

    if not os.path.isdir(scan_dir):
        print(f"Error: {scan_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    print(f"Scanning: {scan_dir}")
    print()

    game_dirs = find_game_dirs(scan_dir)
    if not game_dirs:
        print("No directories containing executables found.")
        return

    print(f"Found {len(game_dirs)} directories with executables.")
    print()

    # --- Collect data ---

    # Engine identification per game dir
    engine_results = {}  # game_dir -> list[EngineMatch]
    for game_dir in game_dirs:
        engine_results[game_dir] = identify_engine(game_dir)

    # Classify directories up front so we can skip work for fully identified ones
    identified = [(d, r) for d, r in engine_results.items() if r]
    unidentified = [d for d, r in engine_results.items() if not r]
    known_dirs = {d for d, r in engine_results.items() if r and r[0].confidence == 1.0}

    # PE version info — skip fully identified directories (known builds /
    # sufficient matches) since we won't report on them anyway.
    pe_data = {}  # game_dir -> (with_info, without_info)
    for game_dir in game_dirs:
        if game_dir in known_dirs:
            continue
        pe_data[game_dir] = _collect_exe_version_info(game_dir, include_dlls=args.verbose)

    by_engine = defaultdict(list)
    for game_dir, results in identified:
        top = results[0]
        by_engine[top.name].append((game_dir, top.confidence, top.evidence, top.version))

    if not args.unknown_only:
        print("=" * 80)
        print("IDENTIFIED ENGINES")
        print("=" * 80)

        for engine_name in sorted(by_engine.keys()):
            entries = by_engine[engine_name]
            print(f"\n  {engine_name} ({len(entries)} directories):")
            for game_dir, confidence, evidence, version in sorted(entries):
                label = _relative_label(game_dir, scan_dir)
                pct = f"{confidence:.0%}"
                ver = f" v{version}" if version else ""
                known_tag = " [KNOWN]" if game_dir in known_dirs else ""
                print(f"    {label} ({pct}{ver}){known_tag}")
                if args.verbose:
                    print(f"      Evidence: {'; '.join(evidence)}")

    if unidentified:
        print()
        print("=" * 80)
        print("UNIDENTIFIED")
        print("=" * 80)
        for game_dir in sorted(unidentified):
            print(f"  {_relative_label(game_dir, scan_dir)}")

    # --- PE version info per game ---

    # When --unknown-only, skip directories with 100% confidence (known builds
    # or sufficient rule matches) — partial matches are still shown.
    if args.unknown_only:
        show_dirs = [d for d in game_dirs if d not in known_dirs]
    else:
        show_dirs = game_dirs

    print()
    print("=" * 80)
    print("PE VERSION INFO BY DIRECTORY")
    if args.unknown_only:
        print(f"  (showing {len(show_dirs)} directories, {len(known_dirs)} fully identified omitted)")
    print("=" * 80)

    for game_dir in show_dirs:
        label = _relative_label(game_dir, scan_dir)
        with_info, without_info = pe_data[game_dir]

        if not with_info and not without_info:
            continue

        print(f"\n  {label}/")

        for exe_name, strings in with_info:
            print(f"    {exe_name}:")
            for line in _format_version_strings(strings):
                print(f"      {line}")

        if without_info:
            for exe_name in without_info:
                print(f"    {exe_name}: (no version info)")

    # --- PE version fingerprint groups ---

    groups = defaultdict(list)  # fingerprint -> [(game_dir, exe_name, strings)]
    no_version_dirs = []  # game_dirs with no version info at all

    for game_dir in show_dirs:
        with_info, without_info = pe_data[game_dir]
        if not with_info:
            no_version_dirs.append(game_dir)
            continue
        for exe_name, strings in with_info:
            fp = _version_fingerprint(strings)
            if fp:
                groups[fp].append((game_dir, exe_name, strings))

    sorted_groups = sorted(groups.items(), key=lambda x: (-len(x[1]), x[0]))

    print()
    print("=" * 80)
    print("PE VERSION FINGERPRINT GROUPS")
    print("=" * 80)

    for i, (fingerprint, entries) in enumerate(sorted_groups, 1):
        unique_dirs = len({d for d, _e, _s in entries})
        print(f"\n  Group {i} ({unique_dirs} directories, {len(entries)} executables):")
        print(f"    {_format_fingerprint(fingerprint)}")

        by_dir = defaultdict(list)
        for game_dir, exe_name, strings in entries:
            by_dir[game_dir].append(exe_name)
        for game_dir in sorted(by_dir.keys()):
            label = _relative_label(game_dir, scan_dir)
            exe_list = ", ".join(sorted(by_dir[game_dir]))
            print(f"      {label} ({exe_list})")

    if no_version_dirs:
        print(f"\n  No PE version info ({len(no_version_dirs)} directories):")
        for game_dir in sorted(no_version_dirs):
            print(f"    {_relative_label(game_dir, scan_dir)}")

    # --- Summary ---

    print()
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    scanned_exes = sum(len(w) + len(wo) for w, wo in pe_data.values())
    scanned_with_info = sum(len(w) for w, _wo in pe_data.values())
    print(f"  Directories with executables: {len(game_dirs)}")
    print(f"  Directories fully identified (skipped PE scan): {len(known_dirs)}")
    print(f"  Executables scanned for version info: {scanned_exes}")
    print(f"  Executables with version info: {scanned_with_info}")
    print(f"  Engine identified: {len(identified)} ({len(known_dirs)} known)")
    print(f"  Engine unidentified: {len(unidentified)}")
    for engine_name in sorted(by_engine.keys()):
        print(f"    {engine_name}: {len(by_engine[engine_name])}")
    print(f"  PE version fingerprint groups: {len(groups)}")
    print(f"  Directories without PE version info: {len(no_version_dirs)}")


if __name__ == "__main__":
    main()
