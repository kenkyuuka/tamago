#!/usr/bin/env python3
"""Extract all TLG images from XP3 archives into a deduplicated sample library.

Scans a directory tree for XP3 archives, opens each one (with auto-detected
encryption where possible), and extracts every file whose name ends in .tlg.
Files are saved by content hash to a flat destination directory, ensuring no
duplicates or collisions even when the same image appears in multiple archives
or under different names.

The destination directory is append-only: running the script again with
different source directories adds new images without disturbing existing ones.
Source directories are never modified.

A manifest file (manifest.tsv) in the destination directory records the
provenance of each extracted file: hash, original archive, and original name.
New entries are appended on each run.

Usage:
    python scripts/extract_tlg_samples.py /path/to/games/ /path/to/tlg_library/
    python scripts/extract_tlg_samples.py /path/to/games/ /path/to/tlg_library/ --dry-run
    python scripts/extract_tlg_samples.py /path/to/games/ /path/to/tlg_library/ -v
"""

import argparse
import hashlib
import logging
import os
import sys
from pathlib import Path

from tamago.formats.xp3 import XP3File
from tamago.formats.xp3.detect import auto_detect
from tamago.formats.xp3.models import XP3_MAGIC
from tamago.formats.xp3.tlg import TLG0_MAGIC, TLG5_MAGIC, TLG6_MAGIC

TLG_MAGICS = (TLG0_MAGIC, TLG5_MAGIC, TLG6_MAGIC)

logger = logging.getLogger(__name__)


def find_xp3_files(scan_dir: Path):
    """Yield paths to all XP3 files under *scan_dir*."""
    for root, _dirs, files in os.walk(scan_dir):
        for name in sorted(files):
            if not name.lower().endswith(".xp3"):
                continue
            path = Path(root) / name
            # Quick magic check to skip non-XP3 files with .xp3 extension
            try:
                with open(path, "rb") as f:
                    if f.read(11) == XP3_MAGIC:
                        yield path
            except OSError:
                continue


def open_xp3_with_auto_detect(xp3_path: Path) -> XP3File | None:
    """Open an XP3 file, attempting auto-detection of encryption.

    Returns an XP3File on success, or None if the file cannot be opened.
    """
    # auto_detect prints diagnostic info to stdout/stderr; suppress it.
    import contextlib

    try:
        with open(os.devnull, "w") as devnull, contextlib.redirect_stdout(devnull), contextlib.redirect_stderr(devnull):
            encryption = auto_detect(str(xp3_path))
    except Exception:
        encryption = None

    try:
        return XP3File(str(xp3_path), encryption=encryption)
    except Exception as e:
        logger.warning("Could not open %s: %s", xp3_path, e)
        return None


def extract_tlg_members(xp3: XP3File, xp3_path: Path, dest: Path, manifest_fd, *, dry_run: bool = False):
    """Extract all .tlg members from an open XP3 file.

    Files are saved as <sha256>.tlg in *dest*.  Provenance is appended to
    *manifest_fd* as tab-separated lines.

    Returns (new_count, skip_count, error_count).
    """
    new_count = 0
    skip_count = 0
    error_count = 0

    for member in xp3.files:
        if not member.file_name.lower().endswith(".tlg"):
            continue

        try:
            with xp3.open(member) as f:
                data = f.read()
        except Exception as e:
            logger.debug("  Error reading %s from %s: %s", member.file_name, xp3_path, e)
            error_count += 1
            continue

        if not any(data[:11] == m for m in TLG_MAGICS):
            logger.debug("  Skipping %s from %s: invalid magic bytes", member.file_name, xp3_path)
            error_count += 1
            continue

        content_hash = hashlib.sha256(data).hexdigest()
        out_path = dest / f"{content_hash}.tlg"

        # Record provenance regardless of whether the file is new
        manifest_fd.write(f"{content_hash}\t{xp3_path}\t{member.file_name}\n")

        if out_path.exists():
            skip_count += 1
            continue

        if dry_run:
            logger.info("  Would extract: %s (%d bytes) -> %s", member.file_name, len(data), out_path.name)
            new_count += 1
            continue

        out_path.write_bytes(data)
        logger.debug("  Extracted: %s -> %s", member.file_name, out_path.name)
        new_count += 1

    return new_count, skip_count, error_count


def main():
    parser = argparse.ArgumentParser(
        description="Extract all TLG images from XP3 archives into a deduplicated library.",
    )
    parser.add_argument("source", type=Path, help="Root directory to scan for XP3 files")
    parser.add_argument("dest", type=Path, help="Destination directory for extracted TLG files")
    parser.add_argument("--dry-run", action="store_true", help="Report what would be extracted without writing files")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show individual file extractions")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(message)s",
    )
    # Suppress noisy output from the XP3 library and detection pipeline.
    logging.getLogger("tamago").setLevel(logging.ERROR)

    source = args.source.resolve()
    if not source.is_dir():
        print(f"Error: {source} is not a directory", file=sys.stderr)
        sys.exit(1)

    dest = args.dest.resolve()
    if not args.dry_run:
        dest.mkdir(parents=True, exist_ok=True)

    manifest_path = dest / "manifest.tsv"
    manifest_mode = "a"  # append — safe for repeated runs

    total_archives = 0
    total_new = 0
    total_skipped = 0
    total_errors = 0
    total_archive_errors = 0

    # Open manifest for appending (or /dev/null for dry-run)
    if args.dry_run:
        import io

        manifest_fd = io.StringIO()
    else:
        manifest_fd = open(manifest_path, manifest_mode)

    try:
        for xp3_path in find_xp3_files(source):
            rel = xp3_path.relative_to(source)
            xp3 = open_xp3_with_auto_detect(xp3_path)
            if xp3 is None:
                total_archive_errors += 1
                continue

            with xp3:
                tlg_count = sum(1 for m in xp3.files if m.file_name.lower().endswith(".tlg"))
                if tlg_count == 0:
                    continue

                total_archives += 1
                logger.info("%s (%d TLG files)", rel, tlg_count)

                new, skipped, errors = extract_tlg_members(xp3, xp3_path, dest, manifest_fd, dry_run=args.dry_run)
                total_new += new
                total_skipped += skipped
                total_errors += errors
    finally:
        if not args.dry_run:
            manifest_fd.close()

    print()
    print(f"Archives scanned: {total_archives}")
    print(f"TLG files extracted: {total_new}")
    print(f"TLG files skipped (already in library): {total_skipped}")
    if total_errors:
        print(f"TLG files with read errors: {total_errors}")
    if total_archive_errors:
        print(f"Archives that could not be opened: {total_archive_errors}")


if __name__ == "__main__":
    main()
