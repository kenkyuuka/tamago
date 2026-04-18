"""Simple crypt — KiriKiri text-file obfuscation and framing.

A thin layer applied by KiriKiri's ``tTJSTextReadStream`` /
``tTJSTextWriteStream`` to script and data files (typically ``.ks``,
``.tjs``, ``.csv``).  Lives above the XP3 archive layer: extracting a
file from an XP3 yields these bytes verbatim; this module decodes them.

Four file formats are recognised by the KiriKiri reader:

- ``FF FE …`` — plain UTF-16LE with BOM.  Returned unchanged.
- ``FE FE 00 FF FE …`` — mode 0 "buggy XOR".  Deprecated, read-only.
- ``FE FE 01 FF FE …`` — mode 1 "simple crypt", the canonical bit-swap.
- ``FE FE 02 FF FE …`` — mode 2, zlib-compressed text.
- anything else — treated by KiriKiri as ANSI/MBCS (Shift-JIS on Japanese
  systems) and read raw.  :func:`decode` returns such buffers unchanged
  so the caller can decode them with the appropriate codec.
"""

import struct
import zlib

MAGIC = b"\xfe\xfe"
BOM = b"\xff\xfe"

MODE_BUGGY_XOR = 0
MODE_SIMPLE_CRYPT = 1
MODE_COMPRESSED = 2

_HEADER_SIZE = 3
_PAYLOAD_START = _HEADER_SIZE + len(BOM)  # BOM is stored unencrypted
_MODE2_SIZE_TRAILER = 16  # two uint64 LE (compressed, uncompressed)
_KNOWN_MODES = frozenset({MODE_BUGGY_XOR, MODE_SIMPLE_CRYPT, MODE_COMPRESSED})
_WRITABLE_MODES = frozenset({MODE_SIMPLE_CRYPT, MODE_COMPRESSED})


def is_encrypted(data: bytes) -> bool:
    """Return True if ``data`` begins with the simple-crypt magic (``FE FE``)."""
    return len(data) >= 2 and data[:2] == MAGIC


def get_mode(data: bytes) -> int | None:
    """Return the crypt mode byte, or None if ``data`` is not encrypted.

    Raises ``ValueError`` if ``data`` begins with the magic but is too short
    to contain a mode byte.
    """
    if not is_encrypted(data):
        return None
    if len(data) < _HEADER_SIZE:
        raise ValueError("simple_crypt: truncated header (expected mode byte)")
    return data[2]


def _swap_bits(payload: bytes) -> bytes:
    if len(payload) % 2:
        raise ValueError("simple_crypt: payload length must be even (UTF-16LE words)")
    n = len(payload) // 2
    words = struct.unpack(f"<{n}H", payload)
    swapped = tuple(((w & 0xAAAA) >> 1) | ((w & 0x5555) << 1) for w in words)
    return struct.pack(f"<{n}H", *swapped)


def _buggy_xor(payload: bytes) -> bytes:
    """Apply mode-0 buggy XOR, identical for encode and decode.

    For each UTF-16 code unit ``ch``: if ``ch >= 0x20`` XOR with
    ``((ch & 0xFE) << 8) ^ 1``, else leave as-is.  The predicate is
    evaluated on different sides of the XOR for encoder vs. decoder,
    so some values do not round-trip — this mirrors the KiriKiri bug.
    """
    if len(payload) % 2:
        raise ValueError("simple_crypt: payload length must be even (UTF-16LE words)")
    n = len(payload) // 2
    words = struct.unpack(f"<{n}H", payload)
    out = [(ch ^ (((ch & 0xFE) << 8) ^ 1)) if ch >= 0x20 else ch for ch in words]
    return struct.pack(f"<{n}H", *out)


def _decompress_mode2(payload: bytes) -> bytes:
    """Decompress a mode-2 payload.

    Layout after the ``FE FE 02 FF FE`` header is:
        uint64 LE compressed_size
        uint64 LE uncompressed_size
        zlib stream
    """
    if len(payload) < _MODE2_SIZE_TRAILER:
        raise ValueError("simple_crypt: truncated mode-2 size trailer")
    compressed_size, uncompressed_size = struct.unpack("<QQ", payload[:_MODE2_SIZE_TRAILER])
    stream = payload[_MODE2_SIZE_TRAILER:]
    if compressed_size and len(stream) < compressed_size:
        raise ValueError(
            f"simple_crypt: mode-2 stream truncated (have {len(stream)}, " f"header claims {compressed_size})"
        )
    inflated = zlib.decompress(stream[:compressed_size] if compressed_size else stream)
    if uncompressed_size and len(inflated) != uncompressed_size:
        raise ValueError(
            f"simple_crypt: mode-2 size mismatch (inflated {len(inflated)}, " f"header claims {uncompressed_size})"
        )
    return inflated


def _compress_mode2(text: bytes) -> bytes:
    compressed = zlib.compress(text)
    return struct.pack("<QQ", len(compressed), len(text)) + compressed


def decode(data: bytes) -> bytes:
    """Decode a KiriKiri text file.

    Mimics the KiriKiri reader's branch logic:

    - Plain UTF-16LE (``FF FE …``) — returned unchanged.
    - Simple-crypt (``FE FE 00/01/02 FF FE …``) — the mode is applied to
      the ciphertext and the result is prefixed with the unencrypted BOM,
      yielding plain UTF-16LE bytes.
    - Anything else — treated as ANSI/MBCS and returned unchanged so the
      caller can decode it with the appropriate narrow codec.

    Raises ``ValueError`` for malformed simple-crypt buffers (truncated
    header, missing BOM, unknown mode, odd payload length, corrupt zlib
    stream).
    """
    if len(data) >= 2 and data[:2] == BOM:
        return data
    if not is_encrypted(data):
        # ANSI/MBCS: KiriKiri reads raw and does narrow-to-wide conversion.
        # We hand the bytes back unchanged; the caller chooses the codec.
        return data

    mode = get_mode(data)
    if mode not in _KNOWN_MODES:
        raise ValueError(f"simple_crypt: unsupported mode {mode}")
    if len(data) < _PAYLOAD_START or data[_HEADER_SIZE:_PAYLOAD_START] != BOM:
        raise ValueError("simple_crypt: expected UTF-16LE BOM after header")

    payload = data[_PAYLOAD_START:]
    if mode == MODE_SIMPLE_CRYPT:
        return BOM + _swap_bits(payload)
    if mode == MODE_BUGGY_XOR:
        return BOM + _buggy_xor(payload)
    # MODE_COMPRESSED
    return BOM + _decompress_mode2(payload)


def encode(data: bytes, mode: int = MODE_SIMPLE_CRYPT) -> bytes:
    """Encode plain UTF-16LE bytes into a KiriKiri text file.

    ``data`` must begin with the UTF-16LE BOM (``FF FE``) and have an even
    total length.  The BOM is preserved verbatim in the output (KiriKiri
    writes it separately from the ciphered payload); only the text after
    the BOM is transformed.

    Supported modes: ``MODE_SIMPLE_CRYPT`` (1, bit-swap) and
    ``MODE_COMPRESSED`` (2, zlib).  Mode 0 is deprecated and buggy and is
    never produced — KiriKiri itself only writes modes 1 and 2.
    """
    if mode not in _WRITABLE_MODES:
        raise ValueError(f"simple_crypt: unsupported mode {mode}")
    if data[:2] != BOM:
        raise ValueError("simple_crypt: input must start with UTF-16LE BOM (FF FE)")
    body = data[2:]
    header = MAGIC + bytes([mode]) + BOM
    if mode == MODE_SIMPLE_CRYPT:
        return header + _swap_bits(body)
    return header + _compress_mode2(body)
