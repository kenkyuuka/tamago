#!/usr/bin/env python3
"""Survey a collection of TLG files for format features and unknowns.

Parses each TLG file's header to gather statistics on format variants,
channel counts, dimensions, compression methods, and values of header
fields documented as "unknown" or "not observed in the wild".

Designed to run against a library of hash-named TLG files produced by
extract_tlg_samples.py, but works on any directory of .tlg files.

Usage:
    python scripts/survey_tlg_samples.py /path/to/tlg_library/
    python scripts/survey_tlg_samples.py /path/to/tlg_library/ -v
"""

import argparse
import os
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

TLG0_MAGIC = b"TLG0.0\x00sds\x1a"
TLG5_MAGIC = b"TLG5.0\x00raw\x1a"
TLG6_MAGIC = b"TLG6.0\x00raw\x1a"


def _read_u32(data: bytes, offset: int) -> int:
    return struct.unpack_from('<I', data, offset)[0]


def survey_tlg0(data: bytes, filename: str, results: dict):
    """Survey a TLG0 container, then recurse into its inner image."""
    results['tlg0_count'] += 1

    if len(data) < 4:
        results['errors'].append((filename, 'TLG0 truncated'))
        return

    inner_length = _read_u32(data, 0)
    inner_end = 4 + inner_length

    # Check for trailing metadata chunks after the inner image
    trailing_length = len(data) - inner_end
    if trailing_length > 0:
        results['tlg0_with_trailing'] += 1
        # Parse trailing chunks
        pos = inner_end
        while pos + 8 <= len(data):
            chunk_name = data[pos : pos + 4]
            chunk_size = _read_u32(data, pos + 4)
            chunk_data = data[pos + 8 : pos + 8 + chunk_size]
            results['tlg0_chunk_names'][chunk_name] += 1

            # If it's a "tags" chunk, parse the tag keys
            if chunk_name == b'tags' and chunk_data:
                _parse_tags(chunk_data, results)

            pos += 8 + chunk_size
    else:
        results['tlg0_without_trailing'] += 1

    # Recurse into inner image
    inner_data = data[4:inner_end]
    if len(inner_data) >= 11:
        _survey_inner(inner_data, filename, results)


def _parse_tags(tag_data: bytes, results: dict):
    """Parse the TLG0 'tags' chunk to extract tag key names.

    Tag format: length:name=length:value, repeated.
    Example: 4:LEFT=2:20,3:TOP=3:120,
    """
    try:
        text = tag_data.decode('utf-8', errors='replace')
    except Exception:
        return

    pos = 0
    while pos < len(text):
        # Read key length
        colon = text.find(':', pos)
        if colon < 0:
            break
        try:
            key_len = int(text[pos:colon])
        except ValueError:
            break
        key_start = colon + 1
        key = text[key_start : key_start + key_len]
        results['tlg0_tag_keys'][key] += 1

        # Skip past =length:value,
        eq = text.find('=', key_start + key_len)
        if eq < 0:
            break
        colon2 = text.find(':', eq + 1)
        if colon2 < 0:
            break
        try:
            val_len = int(text[eq + 1 : colon2])
        except ValueError:
            break
        val_start = colon2 + 1
        value = text[val_start : val_start + val_len]

        # Record specific values for interesting tags
        results['tlg0_tag_values'][(key, value)] += 1

        pos = val_start + val_len
        if pos < len(text) and text[pos] == ',':
            pos += 1


def survey_tlg5(data: bytes, filename: str, results: dict):
    """Survey a TLG5 image header."""
    results['tlg5_count'] += 1

    if len(data) < 13:
        results['errors'].append((filename, 'TLG5 header truncated'))
        return

    channels = data[0]
    width = _read_u32(data, 1)
    height = _read_u32(data, 5)
    block_height = _read_u32(data, 9)

    results['tlg5_channels'][channels] += 1
    results['tlg5_block_heights'][block_height] += 1
    results['dimensions'][(width, height)] += 1

    if channels not in (3, 4):
        results['unusual'].append((filename, f'TLG5 channels={channels}'))

    # Check whether any blocks use LZSS compression vs raw
    block_count = (height + block_height - 1) // block_height
    pos = 13 + block_count * 4  # skip block size table

    compressed_blocks = 0
    raw_blocks = 0
    for _block in range(block_count):
        for _ch in range(channels):
            if pos >= len(data):
                break
            mark = data[pos]
            pos += 1
            if pos + 4 > len(data):
                break
            chunk_size = _read_u32(data, pos)
            pos += 4 + chunk_size
            if mark == 0:
                compressed_blocks += 1
            else:
                raw_blocks += 1

    results['tlg5_compressed_blocks'] += compressed_blocks
    results['tlg5_raw_blocks'] += raw_blocks


def survey_tlg6(data: bytes, filename: str, results: dict):
    """Survey a TLG6 image header and bit pool metadata."""
    results['tlg6_count'] += 1

    if len(data) < 16:
        results['errors'].append((filename, 'TLG6 header truncated'))
        return

    channels = data[0]
    data_flag = data[1]
    color_type = data[2]
    ext_golomb = data[3]
    width = _read_u32(data, 4)
    height = _read_u32(data, 8)
    max_bit_length = _read_u32(data, 12)

    results['tlg6_channels'][channels] += 1
    results['tlg6_data_flag'][data_flag] += 1
    results['tlg6_color_type'][color_type] += 1
    results['tlg6_ext_golomb'][ext_golomb] += 1
    results['tlg6_max_bit_length'][max_bit_length] += 1
    results['dimensions'][(width, height)] += 1

    # Flag any nonzero "unknown" header fields
    if data_flag != 0:
        results['unusual'].append((filename, f'TLG6 data_flag={data_flag}'))
    if color_type != 0:
        results['unusual'].append((filename, f'TLG6 color_type={color_type}'))
    if ext_golomb != 0:
        results['unusual'].append((filename, f'TLG6 ext_golomb={ext_golomb}'))
    if channels not in (3, 4):
        results['unusual'].append((filename, f'TLG6 channels={channels}'))

    # Scan bit pool headers to check compression methods
    pos = 16
    # Skip filter types
    if pos + 4 > len(data):
        return
    ft_size = _read_u32(data, pos)
    pos += 4 + ft_size

    # Read filter types to survey which transforms/predictors are used
    x_block_count = (width + 7) // 8
    y_block_count = (height + 7) // 8

    # Survey bit pool headers
    for _block_row in range(y_block_count):
        group_height = min(8, height - _block_row * 8)
        for _ch in range(channels):
            if pos + 4 > len(data):
                return
            header_word = _read_u32(data, pos)
            pos += 4
            method = (header_word >> 30) & 3
            bit_count = header_word & 0x3FFFFFFF
            byte_count = (bit_count + 7) // 8
            pos += byte_count

            results['tlg6_methods'][method] += 1
            if method != 0:
                results['unusual'].append(
                    (filename, f'TLG6 compression method={method} (block_row={_block_row}, ch={_ch})')
                )


def _survey_inner(data: bytes, filename: str, results: dict):
    """Dispatch to the appropriate surveyor based on magic bytes."""
    magic = data[:11]
    payload = data[11:]

    if magic == TLG5_MAGIC:
        survey_tlg5(payload, filename, results)
    elif magic == TLG6_MAGIC:
        survey_tlg6(payload, filename, results)
    elif magic == TLG0_MAGIC:
        survey_tlg0(payload, filename, results)
    else:
        results['unknown_magic'].append((filename, magic[:20]))


def survey_file(path: Path, results: dict):
    """Survey a single TLG file."""
    results['total_files'] += 1
    filename = path.name

    try:
        data = path.read_bytes()
    except OSError as e:
        results['errors'].append((filename, str(e)))
        return

    if len(data) < 11:
        results['errors'].append((filename, 'too short'))
        return

    _survey_inner(data, filename, results)


def make_results() -> dict:
    """Create a fresh results dictionary."""
    return {
        'total_files': 0,
        'tlg0_count': 0,
        'tlg5_count': 0,
        'tlg6_count': 0,
        'tlg0_with_trailing': 0,
        'tlg0_without_trailing': 0,
        'tlg0_chunk_names': Counter(),
        'tlg0_tag_keys': Counter(),
        'tlg0_tag_values': Counter(),
        'tlg5_channels': Counter(),
        'tlg5_block_heights': Counter(),
        'tlg5_compressed_blocks': 0,
        'tlg5_raw_blocks': 0,
        'tlg6_channels': Counter(),
        'tlg6_data_flag': Counter(),
        'tlg6_color_type': Counter(),
        'tlg6_ext_golomb': Counter(),
        'tlg6_max_bit_length': Counter(),
        'tlg6_methods': Counter(),
        'dimensions': Counter(),
        'unusual': [],
        'unknown_magic': [],
        'errors': [],
    }


def print_counter(name: str, counter: Counter, limit: int = 20):
    """Print a counter as a sorted table."""
    if not counter:
        print(f"  (none)")
        return
    for value, count in counter.most_common(limit):
        print(f"  {value!s:>30s}  {count:>7d}")
    if len(counter) > limit:
        print(f"  ... and {len(counter) - limit} more distinct values")


def main():
    parser = argparse.ArgumentParser(description="Survey TLG files for format features and unknowns.")
    parser.add_argument("source", type=Path, help="Directory containing .tlg files")
    parser.add_argument("-v", "--verbose", action="store_true", help="List every unusual finding")
    args = parser.parse_args()

    source = args.source.resolve()
    if not source.is_dir():
        print(f"Error: {source} is not a directory", file=sys.stderr)
        sys.exit(1)

    results = make_results()

    # Collect all .tlg files
    tlg_files = sorted(source.glob("*.tlg"))
    if not tlg_files:
        print(f"No .tlg files found in {source}")
        sys.exit(0)

    print(f"Surveying {len(tlg_files)} TLG files in {source} ...")
    for i, path in enumerate(tlg_files):
        survey_file(path, results)
        if (i + 1) % 5000 == 0:
            print(f"  ... {i + 1}/{len(tlg_files)}")

    # --- Print report ---
    print()
    print("=" * 72)
    print("TLG SAMPLE SURVEY REPORT")
    print("=" * 72)

    print(f"\nTotal files: {results['total_files']}")
    print(f"  TLG0 containers:  {results['tlg0_count']}")
    print(f"  TLG5 images:      {results['tlg5_count']}")
    print(f"  TLG6 images:      {results['tlg6_count']}")

    # --- TLG0 ---
    if results['tlg0_count']:
        print(f"\n--- TLG0 Container ---")
        print(f"  With trailing chunks:     {results['tlg0_with_trailing']}")
        print(f"  Without trailing chunks:  {results['tlg0_without_trailing']}")

        if results['tlg0_chunk_names']:
            print(f"\n  Chunk types found:")
            for name, count in results['tlg0_chunk_names'].most_common():
                print(f"    {name!r:>10s}  {count:>7d}")

        if results['tlg0_tag_keys']:
            print(f"\n  Tag keys found in 'tags' chunks:")
            print_counter("tag keys", results['tlg0_tag_keys'])

        if results['tlg0_tag_values'] and args.verbose:
            print(f"\n  Tag key=value pairs (top 30):")
            for (key, value), count in results['tlg0_tag_values'].most_common(30):
                print(f"    {key}={value}  ({count})")

    # --- TLG5 ---
    if results['tlg5_count']:
        print(f"\n--- TLG5 ---")
        print(f"  Channel counts:")
        print_counter("channels", results['tlg5_channels'])
        print(f"  Block heights:")
        print_counter("block_height", results['tlg5_block_heights'])
        print(f"  LZSS compressed blocks:  {results['tlg5_compressed_blocks']}")
        print(f"  Raw (uncompressed) blocks: {results['tlg5_raw_blocks']}")

    # --- TLG6 ---
    if results['tlg6_count']:
        print(f"\n--- TLG6 ---")
        print(f"  Channel counts:")
        print_counter("channels", results['tlg6_channels'])

        print(f"\n  data_flag values (expected: always 0):")
        print_counter("data_flag", results['tlg6_data_flag'])

        print(f"\n  color_type values (expected: always 0):")
        print_counter("color_type", results['tlg6_color_type'])

        print(f"\n  ext_golomb_table values (expected: always 0):")
        print_counter("ext_golomb", results['tlg6_ext_golomb'])

        print(f"\n  Compression methods in bit pools (expected: always 0 = Golomb):")
        print_counter("method", results['tlg6_methods'])

        print(f"\n  max_bit_length distribution (top 20):")
        print_counter("max_bit_length", results['tlg6_max_bit_length'])

    # --- Dimensions ---
    if results['dimensions']:
        print(f"\n--- Dimensions (top 20) ---")
        print_counter("(width, height)", results['dimensions'])

    # --- Unusual findings ---
    if results['unusual']:
        print(f"\n--- UNUSUAL FINDINGS ({len(results['unusual'])}) ---")
        if args.verbose:
            for filename, desc in results['unusual']:
                print(f"  {filename}: {desc}")
        else:
            # Summarize by description
            desc_counter = Counter(desc for _, desc in results['unusual'])
            for desc, count in desc_counter.most_common():
                print(f"  {desc}: {count} files")
            print("  (use -v to see individual files)")

    # --- Unknown magic ---
    if results['unknown_magic']:
        print(f"\n--- UNKNOWN MAGIC BYTES ({len(results['unknown_magic'])}) ---")
        for filename, magic in results['unknown_magic'][:10]:
            print(f"  {filename}: {magic!r}")
        if len(results['unknown_magic']) > 10:
            print(f"  ... and {len(results['unknown_magic']) - 10} more")

    # --- Errors ---
    if results['errors']:
        print(f"\n--- ERRORS ({len(results['errors'])}) ---")
        if args.verbose:
            for filename, desc in results['errors']:
                print(f"  {filename}: {desc}")
        else:
            print(f"  (use -v to see details)")

    # --- Summary of unknowns ---
    print(f"\n{'=' * 72}")
    print("SUMMARY: Status of documented unknowns")
    print(f"{'=' * 72}")

    if results['tlg6_count']:
        df = results['tlg6_data_flag']
        ct = results['tlg6_color_type']
        eg = results['tlg6_ext_golomb']
        meth = results['tlg6_methods']

        non_zero_df = sum(v for k, v in df.items() if k != 0)
        non_zero_ct = sum(v for k, v in ct.items() if k != 0)
        non_zero_eg = sum(v for k, v in eg.items() if k != 0)
        non_golomb = sum(v for k, v in meth.items() if k != 0)

        print(f"\n  TLG6 data_flag != 0:       {'YES (%d files)' % non_zero_df if non_zero_df else 'not observed'}")
        print(f"  TLG6 color_type != 0:      {'YES (%d files)' % non_zero_ct if non_zero_ct else 'not observed'}")
        print(f"  TLG6 ext_golomb != 0:      {'YES (%d files)' % non_zero_eg if non_zero_eg else 'not observed'}")
        print(f"  Non-Golomb methods:        {'YES (%d pools)' % non_golomb if non_golomb else 'not observed'}")

    greyscale = results['tlg6_channels'].get(1, 0) + results['tlg5_channels'].get(1, 0)
    print(f"  Greyscale (1-channel):     {'YES (%d files)' % greyscale if greyscale else 'not observed'}")

    tlg0_chunks = set(results['tlg0_chunk_names'].keys())
    non_tags = tlg0_chunks - {b'tags'}
    print(f"  TLG0 chunk types:          {', '.join(repr(c) for c in sorted(tlg0_chunks)) if tlg0_chunks else 'none'}")
    if non_tags:
        print(f"    Non-'tags' chunks found: {', '.join(repr(c) for c in sorted(non_tags))}")
    else:
        print(f"    Non-'tags' chunks:       not observed")

    tag_keys = set(results['tlg0_tag_keys'].keys())
    known_keys = {'LEFT', 'TOP', 'TYPE'}
    novel_keys = tag_keys - known_keys
    print(f"  TLG0 tag keys:             {', '.join(sorted(tag_keys)) if tag_keys else 'none'}")
    if novel_keys:
        print(f"    Novel tag keys:          {', '.join(sorted(novel_keys))}")


if __name__ == "__main__":
    main()
