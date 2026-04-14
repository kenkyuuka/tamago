#!/usr/bin/env python3
"""Curate a TLG sample library by keeping only 5 samples per unique variation.

Scans a directory of TLG files (as produced by extract_tlg_samples.py),
fingerprints each file by its structural properties, and copies up to 5
samples per unique combination to a destination directory.

Properties fingerprinted:

  Format-level:
  - Outer format: TLG0 (wrapped) vs raw TLG5/TLG6
  - Inner format: TLG5 vs TLG6
  - Channel count: 3 (BGR) or 4 (BGRA)
  - TLG5 block_height
  - TLG6 header flags: data_flag, color_type, ext_golomb_table
  - TLG0 trailing chunk names and tag key-value pairs

  Code-path-relevant:
  - TLG5: has_raw_blocks (at least one uncompressed block)
  - TLG5: single_strip (height <= block_height)
  - TLG6: has_partial_block (width % 8 != 0)
  - TLG6: filter predictor types used (median vs average)
  - TLG6: color transform indices used

Usage:
    python scripts/curate_tlg_samples.py /path/to/tlg_library/ /path/to/curated/
    python scripts/curate_tlg_samples.py /path/to/tlg_library/ /path/to/curated/ --dry-run
"""

import argparse
import logging
import shutil
import struct
import sys
from collections import defaultdict
from pathlib import Path

from tamago.formats.xp3.tlg import (
    TLG0_MAGIC,
    TLG5_MAGIC,
    TLG6_MAGIC,
    _RING_SIZE,
    _init_filter_type_ring,
    _lzss_decompress,
)

logger = logging.getLogger(__name__)

SAMPLES_PER_VARIATION = 5
_BLOCK_WIDTH = 8


def _scan_tlg5_blocks(data: bytes) -> dict:
    """Scan TLG5 data stream for raw vs LZSS blocks.

    Returns dict with has_raw_blocks and single_strip, or error.
    Data is after the 11-byte magic.
    """
    if len(data) < 13:
        return {"error": "truncated_tlg5"}

    channel_count = data[0]
    height = struct.unpack_from("<I", data, 5)[0]
    block_height = struct.unpack_from("<I", data, 9)[0]

    if channel_count not in (3, 4) or block_height == 0:
        return {"error": "invalid_tlg5_header"}

    block_count = (height + block_height - 1) // block_height
    pos = 13 + block_count * 4  # skip block size table

    has_raw = False
    for _strip in range(block_count):
        for _channel in range(channel_count):
            if pos + 5 > len(data):
                return {"has_raw_blocks": has_raw, "single_strip": block_count == 1}
            is_raw = data[pos] != 0
            if is_raw:
                has_raw = True
            chunk_size = struct.unpack_from("<I", data, pos + 1)[0]
            pos += 5 + chunk_size

    return {"has_raw_blocks": has_raw, "single_strip": block_count == 1}


def _extract_tlg6_filter_info(data: bytes) -> dict:
    """Extract filter type information from TLG6 data.

    Decompresses the filter type LZSS stream and collects which predictor
    types and color transform indices are used.

    Data is after the 11-byte magic.
    """
    if len(data) < 16:
        return {"error": "truncated_tlg6"}

    width = struct.unpack_from("<I", data, 4)[0]
    height = struct.unpack_from("<I", data, 8)[0]

    x_block_count = (width + _BLOCK_WIDTH - 1) // _BLOCK_WIDTH
    y_block_count = (height + _BLOCK_WIDTH - 1) // _BLOCK_WIDTH
    has_partial = (width % _BLOCK_WIDTH) != 0

    pos = 16
    if pos + 4 > len(data):
        return {"has_partial_block": has_partial, "error": "truncated_tlg6_filter"}

    filter_compressed_size = struct.unpack_from("<I", data, pos)[0]
    pos += 4
    filter_data = data[pos : pos + filter_compressed_size]

    total_filters = x_block_count * y_block_count
    filter_output = bytearray(total_filters)
    filter_ring = _init_filter_type_ring()
    _lzss_decompress(filter_data, filter_output, filter_ring)

    predictors = set()
    transforms = set()
    for fb in filter_output:
        predictors.add("average" if (fb & 1) else "median")
        transforms.add(fb >> 1)

    return {
        "has_partial_block": has_partial,
        "predictors": tuple(sorted(predictors)),
        "transform_indices": tuple(sorted(transforms)),
    }


def fingerprint_tlg5(data: bytes) -> dict:
    """Extract structural properties from TLG5 data (after the 11-byte magic)."""
    if len(data) < 13:
        return {"error": "truncated_tlg5"}
    channel_count = data[0]
    block_height = struct.unpack_from("<I", data, 9)[0]

    props = {
        "inner_format": "TLG5",
        "channels": channel_count,
        "block_height": block_height,
    }

    scan = _scan_tlg5_blocks(data)
    if "error" not in scan:
        props["has_raw_blocks"] = scan["has_raw_blocks"]
        props["single_strip"] = scan["single_strip"]

    return props


def fingerprint_tlg6(data: bytes) -> dict:
    """Extract structural properties from TLG6 data (after the 11-byte magic)."""
    if len(data) < 16:
        return {"error": "truncated_tlg6"}
    channel_count = data[0]
    data_flag = data[1]
    color_type = data[2]
    ext_golomb_table = data[3]

    props = {
        "inner_format": "TLG6",
        "channels": channel_count,
        "data_flag": data_flag,
        "color_type": color_type,
        "ext_golomb_table": ext_golomb_table,
    }

    filter_info = _extract_tlg6_filter_info(data)
    if "error" not in filter_info:
        props["has_partial_block"] = filter_info["has_partial_block"]
        props["predictors"] = filter_info["predictors"]
        props["transform_indices"] = filter_info["transform_indices"]

    return props


def parse_tags_chunk(chunk_data: bytes) -> dict[str, str]:
    """Parse a TLG0 ``tags`` chunk into key-value pairs.

    The format is comma-separated ``length:name=length:value`` in UTF-8.
    """
    tags = {}
    try:
        text = chunk_data.decode("utf-8")
    except UnicodeDecodeError:
        return tags
    for item in text.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            name_part, value_part = item.split("=", 1)
            # Each side is "length:content"
            _, name = name_part.split(":", 1)
            _, value = value_part.split(":", 1)
            tags[name] = value
        except ValueError:
            continue
    return tags


def read_tlg0_chunks(data: bytes) -> tuple[list[str], dict[str, str]]:
    """Read trailing chunks from TLG0 container data (after the 11-byte magic).

    Returns (sorted chunk names, merged tag key-value pairs).
    """
    if len(data) < 4:
        return [], {}
    inner_length = struct.unpack_from("<I", data, 0)[0]
    pos = 4 + inner_length
    chunk_names = []
    all_tags = {}
    while pos + 8 <= len(data):
        chunk_name = data[pos : pos + 4]
        chunk_size = struct.unpack_from("<I", data, pos + 4)[0]
        chunk_data = data[pos + 8 : pos + 8 + chunk_size]
        try:
            name_str = chunk_name.decode("ascii")
        except UnicodeDecodeError:
            name_str = chunk_name.hex()
        chunk_names.append(name_str)
        if name_str == "tags":
            all_tags.update(parse_tags_chunk(chunk_data))
        pos += 8 + chunk_size
    return sorted(chunk_names), all_tags


def fingerprint(data: bytes) -> tuple | None:
    """Fingerprint a TLG file, returning a hashable key or None on failure."""
    if len(data) < 11:
        return None

    magic = data[:11]
    payload = data[11:]

    if magic == TLG0_MAGIC:
        outer = "TLG0"
        chunk_names, tags = read_tlg0_chunks(payload)
        # Parse the inner image
        if len(payload) < 4:
            return None
        inner_length = struct.unpack_from("<I", payload, 0)[0]
        inner_data = payload[4 : 4 + inner_length]
        if len(inner_data) < 11:
            return None
        inner_magic = inner_data[:11]
        inner_payload = inner_data[11:]
        if inner_magic == TLG5_MAGIC:
            props = fingerprint_tlg5(inner_payload)
        elif inner_magic == TLG6_MAGIC:
            props = fingerprint_tlg6(inner_payload)
        else:
            return None
        props["outer_format"] = outer
        props["chunks"] = tuple(chunk_names)
        props["tag_keys"] = tuple(sorted(tags.keys()))
        props["tag_values"] = tuple(sorted(tags.items()))
    elif magic == TLG5_MAGIC:
        props = fingerprint_tlg5(payload)
        props["outer_format"] = "raw"
    elif magic == TLG6_MAGIC:
        props = fingerprint_tlg6(payload)
        props["outer_format"] = "raw"
    else:
        return None

    if "error" in props:
        return None

    # Build a stable hashable key from sorted properties
    return tuple(sorted(props.items()))


def format_label(props: dict) -> str:
    """Build a human-readable label from fingerprint properties."""
    parts = []
    parts.append(f"outer={props.get('outer_format', '?')}")
    parts.append(f"inner={props.get('inner_format', '?')}")
    parts.append(f"ch={props.get('channels', '?')}")

    if props.get("inner_format") == "TLG5":
        parts.append(f"block_h={props.get('block_height', '?')}")
        if "single_strip" in props:
            parts.append(f"single_strip={props['single_strip']}")
        if "has_raw_blocks" in props:
            parts.append(f"has_raw={props['has_raw_blocks']}")

    if props.get("inner_format") == "TLG6":
        for f in ("data_flag", "color_type", "ext_golomb_table"):
            if f in props:
                parts.append(f"{f}={props[f]}")
        if "has_partial_block" in props:
            parts.append(f"partial_block={props['has_partial_block']}")
        if "predictors" in props:
            parts.append(f"predictors={list(props['predictors'])}")
        if "transform_indices" in props:
            parts.append(f"transforms={list(props['transform_indices'])}")

    if "chunks" in props and props["chunks"]:
        parts.append(f"chunks={list(props['chunks'])}")
    if "tag_keys" in props and props["tag_keys"]:
        parts.append(f"tag_keys={list(props['tag_keys'])}")
    if "tag_values" in props and props["tag_values"]:
        tag_dict = dict(props["tag_values"])
        parts.append(f"tags={tag_dict}")

    return "  ".join(parts)


def main():
    parser = argparse.ArgumentParser(
        description="Curate TLG samples: keep 5 per unique structural variation.",
    )
    parser.add_argument("source", type=Path, help="Directory of TLG samples")
    parser.add_argument("dest", type=Path, help="Destination directory for curated samples")
    parser.add_argument("--dry-run", action="store_true", help="Report what would be kept without copying")
    parser.add_argument("-n", "--count", type=int, default=SAMPLES_PER_VARIATION, help="Samples to keep per variation")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(message)s",
    )

    source = args.source.resolve()
    if not source.is_dir():
        print(f"Error: {source} is not a directory", file=sys.stderr)
        sys.exit(1)

    dest = args.dest.resolve()

    # Collect all .tlg files
    tlg_files = sorted(source.glob("*.tlg"))
    if not tlg_files:
        print("No .tlg files found in source directory.")
        sys.exit(0)

    # Group files by fingerprint
    buckets: dict[tuple, list[Path]] = defaultdict(list)
    skipped = 0

    for path in tlg_files:
        data = path.read_bytes()
        key = fingerprint(data)
        if key is None:
            logger.debug("Skipping %s: could not fingerprint", path.name)
            skipped += 1
            continue
        buckets[key].append(path)

    # Report
    print(f"Scanned {len(tlg_files)} files, {len(buckets)} unique variations, {skipped} skipped")
    print()

    total_kept = 0
    for key in sorted(buckets.keys()):
        props = dict(key)
        files = buckets[key]
        keep = files[: args.count]
        total_kept += len(keep)

        label = format_label(props)
        print(f"  {label}: {len(files)} files, keeping {len(keep)}")

    print()
    print(f"Total files to keep: {total_kept}")

    if args.dry_run:
        print("(dry run — no files copied)")
        return

    # Load source manifest for provenance info (hash -> first seen source/name)
    source_manifest = {}
    source_manifest_path = source / "manifest.tsv"
    if source_manifest_path.exists():
        with open(source_manifest_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split("\t", 2)
                if len(parts) == 3 and parts[0] not in source_manifest:
                    source_manifest[parts[0]] = (parts[1], parts[2])

    # Collect kept files with their variation labels
    kept_files: list[tuple[Path, str]] = []
    for key in sorted(buckets.keys()):
        props = dict(key)
        label = format_label(props)
        for path in buckets[key][: args.count]:
            kept_files.append((path, label))

    dest.mkdir(parents=True, exist_ok=True)
    copied = 0
    manifest_path = dest / "manifest.tsv"
    with open(manifest_path, "w") as mf:
        mf.write("filename\tvariation\tsource_archive\toriginal_name\n")
        for path, label in kept_files:
            shutil.copy2(path, dest / path.name)
            copied += 1
            # Look up provenance by hash (filename is <hash>.tlg)
            content_hash = path.stem
            source_archive, original_name = source_manifest.get(content_hash, ("", ""))
            mf.write(f"{path.name}\t{label}\t{source_archive}\t{original_name}\n")

    print(f"Copied {copied} files to {dest}")
    print(f"Manifest written to {manifest_path}")


if __name__ == "__main__":
    main()
