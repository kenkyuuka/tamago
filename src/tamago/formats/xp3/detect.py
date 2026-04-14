"""Auto-detection of XP3 encryption schemes.

Detection proceeds in three stages:
1. TPM discovery: look for *.tpm files alongside the XP3, hash them, look up
   in the encryption library.
2. XP3 structure hash: hash the header + raw file table of the XP3 file
   itself and look that up.
3. Probe: try each known encryption scheme against a file with a recognizable
   magic number and see which one produces valid output.
"""

import hashlib
import importlib.resources
import logging
import struct
import sys
import zlib
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib

from .encryption import get_encryption_schemes
from .encryption.hash_xor import HashXorEncryption
from .models import XP3_MAGIC

logger = logging.getLogger(__name__)

RESERVED_KEYS = frozenset({'title', 'encryption', 'tpm_hashes', 'xp3_hashes'})

# Utility TPM filenames that are not encryption-related
UTILITY_TPMS = frozenset(
    {
        "csvparser.tpm",
        "extrans.tpm",
        "fstat.tpm",
        "layereximage.tpm",
        "windowex.tpm",
        "wumsadp.tpm",
        "wuvorbis.tpm",
        "menu.tpm",
        "wutcwf.tpm",
        "kratimer.tpm",
        "krflash.tpm",
        "krmovie.tpm",
        "ksupport.tpm",
        "wumsmpeg.tpm",
    }
)

MAGIC_SIGNATURES = {
    '.png': b'\x89PNG',
    '.bmp': b'BM',
    '.wav': b'RIFF',
    '.ogg': b'OggS',
    '.jpg': b'\xff\xd8\xff',
    '.jpeg': b'\xff\xd8\xff',
}


def load_library():
    """Load the encryption library TOML file.

    Returns the parsed dict.
    """
    lib_file = importlib.resources.files('tamago.formats.xp3').joinpath('encryption_library.toml')
    return tomllib.loads(lib_file.read_text(encoding='utf-8'))


def _hash_bytes(data):
    """SHA-256 hex digest of bytes."""
    return hashlib.sha256(data).hexdigest()


def hash_file(path):
    """SHA-256 hex digest of an entire file."""
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def hash_xp3_structure(path):
    """Hash the header + raw file table of an XP3 file.

    Reads the header and the raw (compressed) file table bytes, skipping
    the bulk data segments. Returns a SHA-256 hex digest.
    """
    with open(path, 'rb') as f:
        # Read magic (11 bytes) + initial offset (8 bytes)
        header = f.read(19)
        if header[:11] != XP3_MAGIC:
            raise ValueError("Not an XP3 file")
        info_offset = struct.unpack('<Q', header[11:19])[0]

        # Seek to initial offset to check for continuation block
        f.seek(info_offset)
        indexbyte = f.read(1)
        if indexbyte == b'\x80':
            f.seek(8, 1)
            info_offset = struct.unpack('<Q', f.read(8))[0]
            f.seek(info_offset)
            indexbyte = f.read(1)

        # Read file table: sizes + compressed data
        sizes = f.read(16)
        compressed_size = struct.unpack('<Q', sizes[:8])[0]
        table_data = f.read(compressed_size)

        h = hashlib.sha256()
        h.update(header)
        h.update(indexbyte)
        h.update(sizes)
        h.update(table_data)
        return h.hexdigest()


def instantiate_encryption(entry, xp3_path=None):
    """Instantiate an encryption class from a library entry dict.

    The 'encryption' field names the entry point. All other non-reserved
    fields are passed as keyword arguments to the constructor.

    For schemes that require a TPM file (e.g. cxcrypt), ``xp3_path`` is used
    to locate ``*.tpm`` files in the same directory as the XP3 archive. If
    the entry contains a ``tpm_filename`` field, that specific file is used;
    otherwise all encryption TPMs are searched for a valid control block.
    """
    schemes = get_encryption_schemes()
    scheme_name = entry['encryption']
    if scheme_name not in schemes:
        logger.warning("Unknown encryption scheme %r", scheme_name)
        return None
    cls = schemes[scheme_name].load()
    kwargs = {k: v for k, v in entry.items() if k not in RESERVED_KEYS}

    # Resolve TPM file path for schemes that need it (e.g. cxcrypt)
    if 'tpm_file' not in kwargs and xp3_path is not None and scheme_name == 'cxcrypt':
        tpm_path = _find_tpm_for_cxcrypt(xp3_path, kwargs.get('tpm_filename'))
        if tpm_path:
            kwargs['tpm_file'] = str(tpm_path)
        kwargs.pop('tpm_filename', None)

    try:
        return cls(**kwargs)
    except (TypeError, ValueError) as e:
        logger.warning("Failed to instantiate %r with %r: %s", scheme_name, kwargs, e)
        return None


def _find_tpm_for_cxcrypt(xp3_path, tpm_filename=None):
    """Find an encryption TPM file near an XP3 archive.

    Args:
        xp3_path: Path to the XP3 file.
        tpm_filename: Specific TPM filename to look for, or None to search.

    Returns the Path to the TPM file, or None.
    """
    parent = Path(xp3_path).parent
    if tpm_filename:
        candidate = parent / tpm_filename
        if candidate.is_file():
            return candidate
        # Also check plugin/ subdirectory
        candidate = parent / "plugin" / tpm_filename
        if candidate.is_file():
            return candidate
        return None

    # Search for any encryption TPM (not a utility TPM)
    for tpm_path in sorted(parent.glob('*.tpm')):
        if tpm_path.name.lower() not in UTILITY_TPMS:
            return tpm_path
    # Also check plugin/ subdirectory
    plugin_dir = parent / "plugin"
    if plugin_dir.is_dir():
        for tpm_path in sorted(plugin_dir.glob('*.tpm')):
            if tpm_path.name.lower() not in UTILITY_TPMS:
                return tpm_path
    return None


def build_tpm_index(library):
    """Build a mapping from TPM hash -> (game_key, entry)."""
    index = {}
    for key, entry in library.get('games', {}).items():
        for h in entry.get('tpm_hashes', []):
            index[h] = (key, entry)
    return index


def build_xp3_index(library):
    """Build a mapping from XP3 structure hash -> (game_key, entry)."""
    index = {}
    for key, entry in library.get('games', {}).items():
        for h in entry.get('xp3_hashes', []):
            index[h] = (key, entry)
    return index


def detect_by_tpm(xp3_path, library=None):
    """Detect encryption by hashing *.tpm files alongside the XP3.

    Returns (game_key, encryption_instance) or None.
    """
    if library is None:
        library = load_library()
    tpm_index = build_tpm_index(library)
    if not tpm_index:
        return None

    parent = Path(xp3_path).parent
    for tpm_path in sorted(parent.glob('*.tpm')):
        h = hash_file(tpm_path)
        if h in tpm_index:
            game_key, entry = tpm_index[h]
            enc = instantiate_encryption(entry, xp3_path=xp3_path)
            if enc:
                title = entry.get('title', game_key)
                logger.info("Detected game %r via TPM %s", title, tpm_path.name)
                return game_key, enc
    return None


def detect_by_xp3_hash(xp3_path, library=None):
    """Detect encryption by hashing the XP3 file structure.

    Returns (game_key, encryption_instance) or None.
    """
    if library is None:
        library = load_library()
    xp3_index = build_xp3_index(library)
    if not xp3_index:
        return None

    h = hash_xp3_structure(xp3_path)
    if h in xp3_index:
        game_key, entry = xp3_index[h]
        enc = instantiate_encryption(entry, xp3_path=xp3_path)
        if enc:
            title = entry.get('title', game_key)
            logger.info("Detected game %r via XP3 structure hash", title)
            return game_key, enc
    return None


def read_segment_raw(xp3_path, segment):
    """Read raw segment bytes from an XP3 file."""
    with open(xp3_path, 'rb') as f:
        f.seek(segment.offset)
        return f.read(segment.compressed_size)


def read_file_list(xp3_path):
    """Read the file list from an XP3 without decryption.

    Returns a list of XP3Info objects.
    """
    from .xp3file import XP3File

    xp3 = XP3File(xp3_path, mode='r')
    files = xp3.files
    xp3.close()
    return files


def try_decrypt_segment(encryption, data, info, segment):
    """Try to decrypt (and decompress) a segment, returning bytes or None."""
    try:
        result = encryption.decrypt(data, info, segment)
        if segment.compressed:
            result = zlib.decompress(result)
        return result
    except Exception:
        return None


def detect_by_probe(xp3_path, library=None, force=False, quiet=False):
    """Detect encryption by trying known schemes against files with magic numbers.

    Args:
        xp3_path: Path to the XP3 file.
        library: Parsed library dict, or None to load the default.
        force: If False (default), skip probing when no files have the
            encrypted flag set. If True, probe regardless.
        quiet: If True, suppress the TOML snippet printed to stderr.

    Returns (encryption_instance, params_dict) or None.
    If successful and not quiet, prints a TOML snippet to stderr.
    """
    if library is None:
        library = load_library()

    files = read_file_list(xp3_path)

    if not force and not any(info.encrypted for info in files):
        logger.info("No files have the encrypted flag set; skipping probe")
        return None

    # Find candidate files with known magic signatures.
    # When not forcing, restrict to files with the encrypted flag to avoid
    # false positives (e.g. NullEncryption matching on an unencrypted file).
    candidates = []
    for info in files:
        if not force and not info.encrypted:
            continue
        for ext, magic in MAGIC_SIGNATURES.items():
            if info.file_name.lower().endswith(ext) and info.segments and info.segments[0].compressed_size > 0:
                candidates.append((info, magic))
                break
    if not candidates:
        logger.warning("No files with recognizable magic numbers found for probing")
        return None

    # Pick the candidate with the smallest first segment for speed
    candidates.sort(key=lambda c: c[0].segments[0].compressed_size)
    info, expected_magic = candidates[0]
    segment = info.segments[0]
    raw_data = read_segment_raw(xp3_path, segment)

    # Try each registered entry point (skip parameterized ones that can't default-construct)
    schemes = get_encryption_schemes()
    for name, ep in schemes.items():
        cls = ep.load()
        try:
            enc = cls()
        except (TypeError, ValueError):
            continue
        result = try_decrypt_segment(enc, raw_data, info, segment)
        if result and result[: len(expected_magic)] == expected_magic:
            logger.info("Probe matched encryption scheme %r", name)
            if not quiet:
                _print_probe_snippet(xp3_path, name, {})
            return enc, {'encryption': name}

    # Try HashXorEncryption with shifts 0-31
    for shift in range(32):
        enc = HashXorEncryption(shift=shift)
        # Skip if key byte would be 0 (no-op)
        key_byte = (info.key >> shift) & 0xFF
        if key_byte == 0:
            continue
        result = try_decrypt_segment(enc, raw_data, info, segment)
        if result and result[: len(expected_magic)] == expected_magic:
            logger.info("Probe matched hash-xor with shift=%d", shift)
            params = {'encryption': 'hash-xor', 'shift': shift}
            if not quiet:
                _print_probe_snippet(xp3_path, 'hash-xor', {'shift': shift})
            return enc, params

    # Try CxEncryption with TPM files found nearby
    result = _probe_cxcrypt(xp3_path, raw_data, info, segment, expected_magic, quiet)
    if result:
        return result

    logger.info("Probe did not match any known encryption scheme")
    return None


def _probe_cxcrypt(xp3_path, raw_data, info, segment, expected_magic, quiet):
    """Try CxEncryption with TPM files found near the XP3.

    Extracts the control block from each non-utility TPM and tries all
    permutations of prolog/odd/even branch orders that appear in the GARbro
    scheme database. If a match is found, returns (enc, params_dict).
    """
    from .encryption.cxcrypt import CxEncryption, extract_control_block

    parent = Path(xp3_path).parent
    tpm_paths = [p for p in sorted(parent.glob('*.tpm')) if p.name.lower() not in UTILITY_TPMS]
    if not tpm_paths:
        # Also check plugin/ subdirectory
        plugin_dir = parent / "plugin"
        if plugin_dir.is_dir():
            tpm_paths = [p for p in sorted(plugin_dir.glob('*.tpm')) if p.name.lower() not in UTILITY_TPMS]
    if not tpm_paths:
        return None

    for tpm_path in tpm_paths:
        with open(tpm_path, 'rb') as f:
            tpm_data = f.read()
        control_block = extract_control_block(tpm_data)
        if control_block is None:
            continue

        # Try common CxEncryption parameter combinations.
        # Mask and offset are typically in range 0-0x3FF.
        # We try the most common values seen in GARbro's scheme database.
        for mask, offset in _CXCRYPT_COMMON_MASKS:
            for prolog, odd, even in _CXCRYPT_COMMON_ORDERS:
                try:
                    enc = CxEncryption(
                        control_block=control_block,
                        mask=mask,
                        offset=offset,
                        prolog_order=prolog,
                        odd_branch_order=odd,
                        even_branch_order=even,
                    )
                except (TypeError, ValueError):
                    continue
                result = try_decrypt_segment(enc, raw_data, info, segment)
                if result and result[: len(expected_magic)] == expected_magic:
                    logger.info(
                        "Probe matched cxcrypt with mask=0x%x, offset=0x%x via TPM %s",
                        mask,
                        offset,
                        tpm_path.name,
                    )
                    params = {
                        'encryption': 'cxcrypt',
                        'mask': mask,
                        'offset': offset,
                        'prolog_order': prolog,
                        'odd_branch_order': odd,
                        'even_branch_order': even,
                        'tpm_filename': tpm_path.name,
                    }
                    if not quiet:
                        _print_probe_snippet(
                            xp3_path, 'cxcrypt', {k: v for k, v in params.items() if k != 'encryption'}
                        )
                    return enc, params
    return None


# Common mask/offset pairs seen in CxEncryption games (from GARbro scheme database)
_CXCRYPT_COMMON_MASKS = [
    (0x1C9, 0x1F3),
    (0x20, 0x2),
    (0x100, 0x100),
    (0x200, 0x100),
    (0x0FF, 0x0FF),
]

# Common branch order permutations from GARbro's Formats.dat
_CXCRYPT_COMMON_ORDERS = [
    ([0, 1, 2], [0, 1, 2, 3, 4, 5], [0, 1, 2, 3, 4, 5, 6, 7]),
    ([2, 0, 1], [1, 2, 0, 4, 3, 5], [5, 4, 1, 0, 3, 2, 6, 7]),
    ([1, 2, 0], [1, 3, 2, 0, 4, 5], [1, 6, 4, 0, 3, 7, 5, 2]),
    ([1, 0, 2], [1, 4, 0, 3, 2, 5], [5, 4, 1, 0, 7, 6, 2, 3]),
    ([0, 2, 1], [3, 5, 2, 1, 4, 0], [7, 1, 0, 6, 3, 2, 4, 5]),
    ([2, 0, 1], [5, 0, 1, 4, 3, 2], [2, 4, 3, 0, 1, 5, 6, 7]),
    ([1, 2, 0], [2, 0, 5, 1, 3, 4], [1, 4, 2, 3, 0, 7, 6, 5]),
    ([0, 2, 1], [2, 1, 5, 4, 3, 0], [0, 4, 5, 7, 3, 1, 6, 2]),
    ([1, 2, 0], [4, 1, 3, 5, 2, 0], [5, 2, 0, 6, 4, 1, 7, 3]),
    ([0, 2, 1], [3, 4, 0, 1, 2, 5], [4, 1, 0, 3, 6, 2, 7, 5]),
    ([2, 1, 0], [3, 2, 0, 5, 4, 1], [5, 4, 7, 0, 6, 2, 3, 1]),
    ([1, 0, 2], [2, 1, 4, 5, 0, 3], [4, 6, 1, 5, 2, 7, 0, 3]),
]


def _print_probe_snippet(xp3_path, encryption_name, extra_params):
    """Print a TOML snippet for a newly discovered game."""
    xp3_hash = hash_xp3_structure(xp3_path)
    parent = Path(xp3_path).parent

    tpm_lines = []
    for tpm_path in sorted(parent.glob('*.tpm')):
        h = hash_file(tpm_path)
        tpm_lines.append(f'    "{h}", # {tpm_path.name}')

    xp3_lines = [f'    "{xp3_hash}", # {Path(xp3_path).name}']

    lines = [
        '',
        '# Add the following to encryption_library.toml:',
        '[games.CHANGEME]',
        'title = "CHANGEME"',
        f'encryption = "{encryption_name}"',
    ]
    for k, v in extra_params.items():
        if k in ('mask', 'offset') and isinstance(v, int):
            lines.append(f'{k} = 0x{v:X}')
        elif isinstance(v, str):
            lines.append(f'{k} = "{v}"')
        else:
            lines.append(f'{k} = {v!r}')
    lines.append('tpm_hashes = [')
    lines.extend(tpm_lines)
    lines.append(']')
    lines.append('xp3_hashes = [')
    lines.extend(xp3_lines)
    lines.append(']')
    lines.append('')

    snippet = '\n'.join(lines)
    print(snippet, file=sys.stderr)


def auto_detect(xp3_path, force_probe=False):
    """Auto-detect the encryption scheme for an XP3 file.

    Tries detection in order: TPM hash, XP3 structure hash, probe.

    Args:
        xp3_path: Path to the XP3 file.
        force_probe: If True, the probe stage will try decryption even when
            no files have the encrypted flag set.

    Returns an XP3Encryption instance, or None if no encryption was detected.
    """
    # Stage 1: TPM
    result = detect_by_tpm(xp3_path)
    if result:
        return result[1]

    # Stage 2: XP3 structure hash
    result = detect_by_xp3_hash(xp3_path)
    if result:
        return result[1]

    # Stage 3: Probe
    result = detect_by_probe(xp3_path, force=force_probe)
    if result:
        return result[0]

    return None


# Backward compatibility aliases
_instantiate_encryption = instantiate_encryption
_read_file_list = read_file_list
_read_segment_raw = read_segment_raw
_try_decrypt_segment = try_decrypt_segment
