#!/usr/bin/env python3
"""Extract game trial ZIPs that contain XP3 archives.

Scans a source directory for ZIP files, checks whether each contains any
.xp3 files, and if so extracts the full ZIP into a parallel directory tree.
Skips ZIPs whose target directory already exists.

Default paths for source and dest can be set via paths.trial_source and
paths.trial_dest in local.toml at the repository root.

Usage:
    python scripts/extract_trial_zips.py
    python scripts/extract_trial_zips.py /path/to/game/trial/zips/
    python scripts/extract_trial_zips.py /path/to/game/trial/zips/ --dest /base/path/for/extracted/files/
    python scripts/extract_trial_zips.py /path/to/game/trial/zips/ --dry-run
"""

import argparse
import os
import sys
import tomllib
import zipfile
from pathlib import Path

# Encodings to try (in order) when the ZIP's UTF-8 flag is not set.
_CANDIDATE_ENCODINGS = ["cp932", "euc_jp", "cp949", "big5"]


def _detect_zip_encoding(zf: zipfile.ZipFile) -> str | None:
    """Detect filename encoding for ZIPs without the UTF-8 flag.

    Returns the encoding name if non-ASCII filenames are detected and can be
    decoded from one of the candidate encodings, or None if everything is
    ASCII / already UTF-8.
    """
    for info in zf.infolist():
        if info.flag_bits & 0x800:
            # UTF-8 flag is set — no fixup needed.
            return None

        # Python decoded the raw bytes as cp437.  Re-encode to recover the
        # original byte sequence, then try candidate encodings.
        try:
            raw = info.filename.encode("cp437")
        except UnicodeEncodeError:
            continue

        if all(b < 0x80 for b in raw):
            continue  # pure ASCII — nothing to detect from this entry

        for enc in _CANDIDATE_ENCODINGS:
            try:
                raw.decode(enc)
                return enc
            except (UnicodeDecodeError, UnicodeEncodeError):
                continue

    return None


def _fix_top_level_encoding(target: Path, zf: zipfile.ZipFile, encoding: str, *, dry_run: bool = False) -> None:
    """Rename top-level directories inside *target* from cp437 mojibake to *encoding*."""
    renamed: set[str] = set()
    for info in zf.infolist():
        if info.flag_bits & 0x800:
            continue
        top = info.filename.split("/")[0]
        if not top or top in renamed:
            continue
        try:
            raw = top.encode("cp437")
        except UnicodeEncodeError:
            continue
        if all(b < 0x80 for b in raw):
            continue
        try:
            correct = raw.decode(encoding)
        except (UnicodeDecodeError, UnicodeEncodeError):
            continue
        if correct == top:
            continue

        src = target / top
        dst = target / correct
        if src.exists() and not dst.exists():
            if dry_run:
                print(f"  Would rename: {top!r} -> {correct!r}")
            else:
                src.rename(dst)
                print(f"  Renamed: {top!r} -> {correct!r}")
        renamed.add(top)


def has_xp3(zf: zipfile.ZipFile) -> bool:
    return any(name.lower().endswith(".xp3") for name in zf.namelist())


def find_zips(source: Path):
    for root, _dirs, files in os.walk(source):
        for name in sorted(files):
            if name.lower().endswith(".zip"):
                yield Path(root) / name


def load_local_config():
    """Load local.toml from repository root, returning the parsed dict or {}."""
    conf_path = Path(__file__).resolve().parents[3] / "local.toml"
    if not conf_path.is_file():
        return {}
    with open(conf_path, "rb") as f:
        return tomllib.load(f)


def main():
    config = load_local_config()
    default_source = config.get("paths", {}).get("trial_source")
    default_dest = config.get("paths", {}).get("trial_dest")

    parser = argparse.ArgumentParser(description="Extract game trial ZIPs containing XP3 archives.")
    parser.add_argument(
        "source",
        type=Path,
        nargs="?" if default_source else None,
        default=Path(default_source) if default_source else None,
        help="Root directory to scan for ZIP files (default: paths.trial_source from local.toml)",
    )
    parser.add_argument(
        "--dest",
        type=Path,
        default=Path(default_dest) if default_dest else None,
        help="Destination root (default: paths.trial_dest from local.toml, or <source>-extracted/)",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print what would be done without extracting")
    args = parser.parse_args()

    source = args.source.resolve()
    if not source.is_dir():
        print(f"Error: {source} is not a directory", file=sys.stderr)
        sys.exit(1)

    dest = args.dest.resolve() if args.dest else source.parent / (source.name + "-extracted")

    skipped_exists = 0
    skipped_no_xp3 = 0
    skipped_bad_zip = 0
    extracted = 0

    for zip_path in find_zips(source):
        rel = zip_path.relative_to(source)
        target = dest / rel
        if target.exists():
            skipped_exists += 1
            continue

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                if not has_xp3(zf):
                    skipped_no_xp3 += 1
                    continue

                encoding = _detect_zip_encoding(zf)

                if args.dry_run:
                    xp3_names = [n for n in zf.namelist() if n.lower().endswith(".xp3")]
                    enc_note = f", encoding={encoding}" if encoding else ""
                    print(f"Would extract: {rel}  ({len(xp3_names)} XP3 files{enc_note}) -> {target}")
                    if encoding:
                        _fix_top_level_encoding(target, zf, encoding, dry_run=True)
                    extracted += 1
                    continue

                print(f"Extracting: {rel} -> {target}")
                target.mkdir(parents=True, exist_ok=True)
                zf.extractall(target)
                if encoding:
                    _fix_top_level_encoding(target, zf, encoding)
                extracted += 1
        except zipfile.BadZipFile:
            print(f"Warning: bad zip file: {rel}", file=sys.stderr)
            skipped_bad_zip += 1

    print()
    print(f"Extracted: {extracted}")
    print(f"Skipped (already exists): {skipped_exists}")
    print(f"Skipped (no XP3 files): {skipped_no_xp3}")
    if skipped_bad_zip:
        print(f"Skipped (bad zip): {skipped_bad_zip}")


if __name__ == "__main__":
    main()
