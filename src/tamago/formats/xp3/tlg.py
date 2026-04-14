"""TLG image format decoder.

Decodes TLG (KiriKiri engine) images to PIL Image objects.  Supports three
variants:

- **TLG0**: a container wrapping a raw TLG5 or TLG6 image with optional
  metadata tags.
- **TLG5**: per-channel LZSS compression with cross-channel delta filtering.
  Designed for fast decoding.
- **TLG6**: adaptive Golomb coding with block-based spatial prediction and
  selectable color decorrelation transforms.  Higher compression ratio.
"""

from __future__ import annotations

import array
import io
import os
import struct
from pathlib import Path

try:
    from PIL import Image
except ImportError:
    Image = None  # type: ignore[assignment,misc]

try:
    from tamago.formats.xp3 import _tlg_accel
except ImportError:
    _tlg_accel = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

TLG0_MAGIC = b"TLG0.0\x00sds\x1a"
TLG5_MAGIC = b"TLG5.0\x00raw\x1a"
TLG6_MAGIC = b"TLG6.0\x00raw\x1a"


# ---------------------------------------------------------------------------
# Section 1: LZSS decompression (shared by TLG5 and TLG6)
# ---------------------------------------------------------------------------

_RING_SIZE = 4096
_RING_MASK = _RING_SIZE - 1

# Maximum encoded match length: base 3 + 4-bit field (max 15) + extension byte (max 255) = 273
_MATCH_BASE_LENGTH = 3
_MATCH_EXTENDED_THRESHOLD = 18  # base + 15; triggers an extension byte


def _lzss_decompress(
    source: bytes,
    output: bytearray,
    ring: bytearray,
    ring_pos: int = 0,
) -> int:
    """Decompress LZSS data into *output*, updating *ring* in place.

    The LZSS variant used by TLG has a 4096-byte ring buffer and flag-byte
    driven literal/back-reference selection.  Each flag byte controls 8
    operations (one per bit, LSB first).

    Back-references are encoded as two bytes: a 12-bit ring position (low
    bits) and a 4-bit match length (high nybble of second byte).  If the
    decoded length equals 18 (the maximum for 4 bits + base 3), a third byte
    extends the length.

    Args:
        source: Compressed input bytes.
        output: Pre-allocated output buffer.  Only ``len(output)`` bytes
            will be written.
        ring: 4096-byte ring buffer, modified in place.
        ring_pos: Starting write position within the ring buffer.

    Returns:
        The updated ring buffer write position, so callers that decompress
        multiple blocks with a shared ring (TLG5) can carry state forward.
    """
    src_len = len(source)
    dst_len = len(output)
    src_idx = 0
    dst_idx = 0

    while src_idx < src_len and dst_idx < dst_len:
        # Read a flag byte — each bit controls one of the next 8 operations.
        flag_byte = source[src_idx]
        src_idx += 1

        for bit in range(8):
            if dst_idx >= dst_len or src_idx >= src_len:
                return ring_pos

            if (flag_byte >> bit) & 1:
                # --- Back-reference ---
                if src_idx + 1 >= src_len:
                    return ring_pos
                lo = source[src_idx]
                hi = source[src_idx + 1]
                src_idx += 2

                match_pos = lo | ((hi & 0x0F) << 8)
                match_len = (hi >> 4) + _MATCH_BASE_LENGTH

                if match_len == _MATCH_EXTENDED_THRESHOLD:
                    if src_idx >= src_len:
                        return ring_pos
                    match_len += source[src_idx]
                    src_idx += 1

                # Clamp to remaining output space
                match_len = min(match_len, dst_len - dst_idx)

                # Fast path: if neither the ring read nor write wraps, use slice ops
                match_end = match_pos + match_len
                ring_end = ring_pos + match_len
                if match_end <= _RING_SIZE and ring_end <= _RING_SIZE:
                    chunk = ring[match_pos:match_end]
                    output[dst_idx : dst_idx + match_len] = chunk
                    ring[ring_pos:ring_end] = chunk
                    dst_idx += match_len
                    ring_pos = ring_end & _RING_MASK
                else:
                    for j in range(match_len):
                        byte = ring[(match_pos + j) & _RING_MASK]
                        output[dst_idx] = byte
                        ring[ring_pos] = byte
                        dst_idx += 1
                        ring_pos = (ring_pos + 1) & _RING_MASK
            else:
                # --- Literal byte ---
                byte = source[src_idx]
                src_idx += 1
                output[dst_idx] = byte
                ring[ring_pos] = byte
                dst_idx += 1
                ring_pos = (ring_pos + 1) & _RING_MASK

    return ring_pos


# ---------------------------------------------------------------------------
# Section 2: Packed-byte arithmetic
#
# Several TLG operations work on four independent bytes packed into a single
# 32-bit integer (one per BGRA channel).  Standard integer addition would
# let carries leak between byte lanes, so we need special primitives.
# ---------------------------------------------------------------------------


def _packed_add(a: int, b: int) -> int:
    """Add four bytes packed in 32-bit integers, independently per lane.

    Each byte lane is computed as ``(a_byte + b_byte) mod 256``, with no
    carry propagation between lanes.

    The trick: a normal 32-bit add produces the right result in every lane
    *except* where a carry crossed a byte boundary.  We detect those carries
    and subtract them out.
    """
    # Bits that would carry into the next byte lane:
    carry = (((a & b) << 1) + ((a ^ b) & 0xFEFEFEFE)) & 0x01010100
    return (a + b - carry) & 0xFFFFFFFF


def _packed_greater_than(a: int, b: int) -> int:
    """Per-byte comparison: returns 0xFF in lanes where a > b, else 0x00.

    Works by computing (a - b - 1) in each byte lane and checking the sign
    bit.  The sign bit is then spread to fill each byte lane.
    """
    complement = ~b & 0xFFFFFFFF
    # High bit is set in lanes where a > b (since a + ~b = a - b - 1):
    high_bits = ((a & complement) + (((a ^ complement) >> 1) & 0x7F7F7F7F)) & 0x80808080
    # Spread each high bit to fill its byte lane (0x80 -> 0xFF):
    return ((high_bits >> 7) + 0x7F7F7F7F) ^ 0x7F7F7F7F


# ---------------------------------------------------------------------------
# Section 3: TLG5 decoder
# ---------------------------------------------------------------------------


def _correlate_channels(pixels: bytearray, width: int, height: int, channel_count: int):
    """Apply the TLG5 color correlation filter in place.

    After LZSS decompression, TLG5 channel data is delta-encoded.  This
    function reverses the three-stage correlation filter to recover final
    pixel values:

    1. **Cross-channel decorrelation**: B += G, R += G.  The green channel
       carries the most luminance, so expressing B and R as offsets from G
       reduces their entropy.
    2. **Horizontal accumulation**: a running sum across each scanline
       (resets per scanline).
    3. **Vertical delta**: each pixel adds the corresponding pixel from the
       previous scanline.

    The pixel buffer is in RGBA byte order (R at offset 0, G at 1, B at 2,
    A at 3) with 4 bytes per pixel regardless of *channel_count*.
    """
    stride = width * 4
    for y in range(height):
        row_start = y * stride
        # Horizontal accumulators, reset each scanline
        horiz_r = horiz_g = horiz_b = horiz_a = 0

        for x in range(width):
            px = row_start + x * 4
            delta_r = pixels[px]
            delta_g = pixels[px + 1]
            delta_b = pixels[px + 2]
            delta_a = pixels[px + 3]

            # Step 1: cross-channel decorrelation
            delta_b = (delta_b + delta_g) & 0xFF
            delta_r = (delta_r + delta_g) & 0xFF

            # Step 2: horizontal accumulation
            horiz_r = (horiz_r + delta_r) & 0xFF
            horiz_g = (horiz_g + delta_g) & 0xFF
            horiz_b = (horiz_b + delta_b) & 0xFF
            horiz_a = (horiz_a + delta_a) & 0xFF

            # Step 3: vertical delta (add pixel from previous scanline)
            if y > 0:
                above = row_start - stride + x * 4
                final_r = (horiz_r + pixels[above]) & 0xFF
                final_g = (horiz_g + pixels[above + 1]) & 0xFF
                final_b = (horiz_b + pixels[above + 2]) & 0xFF
                final_a = (horiz_a + pixels[above + 3]) & 0xFF
            else:
                final_r, final_g, final_b, final_a = horiz_r, horiz_g, horiz_b, horiz_a

            if channel_count == 3:
                final_a = 0xFF

            pixels[px] = final_r
            pixels[px + 1] = final_g
            pixels[px + 2] = final_b
            pixels[px + 3] = final_a


def _decode_tlg5(data: bytes) -> Image.Image:
    """Decode a TLG5 image from the data following the 11-byte magic."""
    # --- Parse header ---
    channel_count = data[0]
    width = struct.unpack_from('<I', data, 1)[0]
    height = struct.unpack_from('<I', data, 5)[0]
    block_height = struct.unpack_from('<I', data, 9)[0]

    if channel_count not in (3, 4):
        raise ValueError(f"Unsupported TLG5 channel count: {channel_count}")

    # Skip the block size table (redundant; per-channel sizes suffice).
    block_count = (height + block_height - 1) // block_height
    pos = 13 + block_count * 4

    # --- Decompress all strips ---
    # Output buffer: RGBA byte order, 4 bytes per pixel.
    # Channels are decompressed into separate planes then interleaved.
    pixels = bytearray(width * height * 4)

    # A single LZSS ring buffer is shared across all channels and strips.
    ring = bytearray(_RING_SIZE)
    ring_pos = 0

    scanline_y = 0
    for _strip in range(block_count):
        strip_rows = min(block_height, height - scanline_y)
        strip_pixels = strip_rows * width

        for channel in range(channel_count):
            if pos >= len(data):
                raise ValueError("Unexpected end of TLG5 data")

            is_raw = data[pos] != 0
            pos += 1
            chunk_size = struct.unpack_from('<I', data, pos)[0]
            pos += 4
            chunk_data = data[pos : pos + chunk_size]
            pos += chunk_size

            # Decompress channel into a flat buffer.
            channel_buf = bytearray(strip_pixels)
            if is_raw:
                channel_buf[: len(chunk_data)] = chunk_data
            else:
                ring_pos = _lzss_decompress(chunk_data, channel_buf, ring, ring_pos)

            # Spread channel bytes into the interleaved RGBA pixel buffer.
            # Channel order in TLG5 is B=0, G=1, R=2, A=3.
            # We store as R=0, G=1, B=2, A=3 (RGBA) so:
            #   TLG channel 0 (B) -> byte offset 2
            #   TLG channel 1 (G) -> byte offset 1
            #   TLG channel 2 (R) -> byte offset 0
            #   TLG channel 3 (A) -> byte offset 3
            byte_offset = (2, 1, 0, 3)[channel]
            base = scanline_y * width * 4

            pixels[base + byte_offset : base + strip_pixels * 4 + byte_offset : 4] = channel_buf[:strip_pixels]

        scanline_y += strip_rows

    # --- Apply correlation filter ---
    _correlate_channels(pixels, width, height, channel_count)

    return Image.frombytes("RGBA", (width, height), bytes(pixels))


# ---------------------------------------------------------------------------
# Section 4: TLG6 lookup tables
# ---------------------------------------------------------------------------

# Golomb coding parameters
_GOLOMB_PERIOD = 4  # adaptive context resets every this many symbols
_UNARY_TABLE_BITS = 12
_UNARY_TABLE_SIZE = 1 << _UNARY_TABLE_BITS

# Block dimensions for TLG6
_BLOCK_WIDTH = 8
_BLOCK_HEIGHT = 8

# Lazily initialized lookup tables (module-level singletons).
_unary_table: list[int] | None = None
_golomb_length_table: list[list[int]] | None = None


def _ensure_tables():
    """Build the Golomb lookup tables on first use."""
    global _unary_table, _golomb_length_table
    if _unary_table is not None:
        return

    # --- Unary code table ---
    # Maps a 12-bit value to the 1-indexed position of its lowest set bit.
    # Entry 0 means "no bit set in this window" — the decoder must advance.
    _unary_table = [0] * _UNARY_TABLE_SIZE
    for i in range(1, _UNARY_TABLE_SIZE):
        bit_position = 0
        while not (i & (1 << bit_position)):
            bit_position += 1
        _unary_table[i] = bit_position + 1  # 1-indexed

    # --- Golomb bit-length table ---
    # For each (context, period) pair, gives the number of suffix bits
    # to read when decoding a nonzero Golomb value.
    #
    # The table is derived from four threshold profiles.  Each profile
    # specifies how many symbols use each bit-length (0 through 8).
    thresholds = [
        [3, 7, 15, 27, 63, 108, 223, 448, 130],
        [3, 5, 13, 24, 51, 95, 192, 384, 257],
        [2, 5, 12, 21, 39, 86, 155, 320, 384],
        [2, 3, 9, 18, 33, 61, 129, 258, 511],
    ]
    table_size = _GOLOMB_PERIOD * 2 * 128  # 1024 entries per profile
    _golomb_length_table = [[0] * _GOLOMB_PERIOD for _ in range(table_size)]
    for profile in range(_GOLOMB_PERIOD):
        entry = 0
        for bit_length, count in enumerate(thresholds[profile]):
            for _ in range(count):
                _golomb_length_table[entry][profile] = bit_length
                entry += 1


# ---------------------------------------------------------------------------
# Section 5: TLG6 Golomb decoder
# ---------------------------------------------------------------------------


class _BitReader:
    """Read individual bits from a byte buffer, LSB first.

    The Golomb decoder reads variable-length codes from a packed bitstream.
    This class encapsulates the byte-offset and bit-offset bookkeeping.
    """

    __slots__ = ('_buffer', '_byte_idx', '_bit_idx')

    def __init__(self, data: bytes):
        # Pad with 4 zero bytes so 32-bit reads near the end don't fault.
        self._buffer = bytearray(data) + b'\x00\x00\x00\x00'
        self._byte_idx = 0
        self._bit_idx = 0

    def _peek32(self) -> int:
        """Read a 32-bit little-endian value at the current byte offset."""
        return struct.unpack_from('<I', self._buffer, self._byte_idx)[0]

    def _advance(self, bits: int):
        """Advance the read position by *bits* bits."""
        self._bit_idx += bits
        self._byte_idx += self._bit_idx >> 3
        self._bit_idx &= 7

    def read_bit(self) -> int:
        """Read a single bit."""
        value = (self._buffer[self._byte_idx] >> self._bit_idx) & 1
        self._advance(1)
        return value

    def read_bits(self, count: int) -> int:
        """Read *count* bits as an unsigned integer."""
        if count == 0:
            return 0
        word = self._peek32() >> self._bit_idx
        value = word & ((1 << count) - 1)
        self._advance(count)
        return value

    def read_unary(self) -> int:
        """Read a unary code: count zero bits up to (and including) the terminating 1-bit.

        Returns the number of zero bits before the terminating 1.  Uses a
        12-bit lookup table for speed.
        """
        zero_count = 0
        while True:
            window = (self._peek32() >> self._bit_idx) & (_UNARY_TABLE_SIZE - 1)
            lowest_set = _unary_table[window]
            if lowest_set:
                zero_count += lowest_set - 1
                self._advance(lowest_set)
                return zero_count
            # No set bit in the 12-bit window — all zeros.
            zero_count += _UNARY_TABLE_BITS
            self._advance(_UNARY_TABLE_BITS)

    def read_unary_with_fallback(self) -> tuple[int, int]:
        """Read a unary code, with a fallback for very long runs.

        If the 32-bit word at the current position is entirely zero (which
        can happen for very large values), the decoder falls back to reading
        the zero count from the next byte directly.

        Returns:
            (zero_count, raw_bits_consumed_by_terminator) — the second value
            is used by the caller to extract suffix bits from the same word.
        """
        word = self._peek32() >> self._bit_idx
        if word:
            # Normal case: find the lowest set bit.
            zero_count = 0
            while True:
                lowest_set = _unary_table[word & (_UNARY_TABLE_SIZE - 1)]
                if lowest_set:
                    zero_count += lowest_set - 1
                    self._advance(lowest_set)
                    return zero_count, lowest_set
                zero_count += _UNARY_TABLE_BITS
                self._advance(_UNARY_TABLE_BITS)
                word = self._peek32() >> self._bit_idx
        else:
            # Fallback: skip 5 bytes, read the zero count from byte 5.
            self._byte_idx += 5
            zero_count = self._buffer[self._byte_idx - 1]
            self._bit_idx = 0
            return zero_count, 0


def _decode_golomb_channel(
    pixel_buffer: bytearray,
    channel_offset: int,
    pixel_count: int,
    bit_pool: bytes,
):
    """Decode one channel of Golomb-coded pixel deltas into *pixel_buffer*.

    The Golomb coder produces alternating runs of zero and nonzero values.
    Decoded values are written at stride-4 positions in *pixel_buffer*
    (starting at *channel_offset*), because the buffer is interleaved BGRA.

    Values are zig-zag encoded: bit 0 is the sign, remaining bits are the
    magnitude.  So encoded value 0 → +1, 1 → -1, 2 → +2, 3 → -2, etc.
    Zero-valued pixels are handled separately by zero runs (not zig-zag coded).
    """
    reader = _BitReader(bit_pool)
    output_limit = pixel_count * 4
    output_idx = channel_offset

    # First bit determines whether we start with a zero run or nonzero run.
    is_zero_run = reader.read_bit() == 0

    # Adaptive Golomb parameters
    adaptation_sum = 0
    period_counter = _GOLOMB_PERIOD - 1

    while output_idx < output_limit:
        # --- Read run length (exponential-Golomb) ---
        unary_value = reader.read_unary()
        mantissa_bits = unary_value  # number of extra bits to read
        run_length = (1 << mantissa_bits) + reader.read_bits(mantissa_bits)

        if is_zero_run:
            # --- Zero run: emit run_length zeros via slice assignment ---
            end = min(output_idx + run_length * 4, output_limit)
            count = (end - output_idx + 3) // 4
            pixel_buffer[output_idx:end:4] = b'\x00' * count
            output_idx = output_idx + count * 4
        else:
            # --- Nonzero run: decode run_length Golomb-coded values ---
            for _ in range(run_length):
                if output_idx >= output_limit:
                    break

                # Read the value's unary prefix (with fallback for large values)
                prefix_zeros, _terminator_bits = reader.read_unary_with_fallback()

                # Read the Golomb suffix bits
                suffix_bits = _golomb_length_table[adaptation_sum][period_counter]
                suffix = reader.read_bits(suffix_bits)

                # Combine prefix and suffix into the encoded magnitude
                encoded = (prefix_zeros << suffix_bits) + suffix

                # Zig-zag decode: bit 0 is sign (0 = negative, 1 = positive),
                # remaining bits are the magnitude minus one (since zero is
                # handled by zero runs, the smallest nonzero magnitude is 1).
                sign_bit = encoded & 1
                magnitude = encoded >> 1
                sign_mask = sign_bit - 1  # 0 → -1 (negative), 1 → 0 (positive)
                decoded = ((magnitude ^ sign_mask) + sign_mask + 1) & 0xFF
                pixel_buffer[output_idx] = decoded
                output_idx += 4

                # Update adaptive context
                adaptation_sum += magnitude
                period_counter -= 1
                if period_counter < 0:
                    adaptation_sum >>= 1
                    period_counter = _GOLOMB_PERIOD - 1

                # Advance past the terminator bits (for the suffix extraction)
                # This is only needed when using read_unary_with_fallback,
                # because the suffix was read from the same word as the
                # terminator.  The _advance calls in read_bits already handle
                # the suffix advancement; we just need to account for the
                # terminator position within the word.
                # (Already handled by _BitReader.read_unary_with_fallback
                # and read_bits — no extra advancement needed here.)

        is_zero_run = not is_zero_run


# ---------------------------------------------------------------------------
# Section 6: TLG6 color transforms
#
# TLG6 applies one of 16 invertible color transforms per 8-pixel block.
# Each transform is a linear combination of the (R, G, B) deltas with
# small integer coefficients (0, 1, or 2), computed modulo 256.
#
# The table below gives the coefficients as ((cRr,cRg,cRb), (cGr,cGg,cGb),
# (cBr,cBg,cBb)) where output_R = cRr*dR + cRg*dG + cRb*dB, etc.
# ---------------------------------------------------------------------------

_COLOR_TRANSFORMS = [
    # idx  R' coefficients    G' coefficients    B' coefficients    Description
    ((1, 0, 0), (0, 1, 0), (0, 0, 1)),  #  0: identity
    ((1, 1, 0), (0, 1, 0), (0, 1, 1)),  #  1: green decorrelation
    ((1, 1, 1), (0, 1, 1), (0, 0, 1)),  #  2: additive chain
    ((1, 0, 0), (1, 1, 0), (1, 1, 1)),  #  3: red-first chain
    ((2, 1, 1), (1, 1, 1), (1, 0, 1)),  #  4: double-red emphasis
    ((1, 0, 0), (1, 1, 1), (1, 0, 1)),  #  5: full sum in G
    ((1, 0, 0), (0, 1, 0), (0, 1, 1)),  #  6: blue from green
    ((1, 0, 0), (0, 1, 1), (0, 0, 1)),  #  7: green from blue
    ((1, 1, 0), (0, 1, 0), (0, 0, 1)),  #  8: red from green
    ((1, 0, 1), (1, 1, 1), (1, 1, 2)),  #  9: double-blue emphasis
    ((1, 0, 0), (1, 1, 0), (1, 0, 1)),  # 10: red spread
    ((1, 0, 1), (0, 1, 1), (0, 0, 1)),  # 11: blue additive
    ((1, 0, 1), (1, 1, 1), (0, 0, 1)),  # 12: blue-red in G
    ((1, 1, 1), (1, 2, 1), (0, 1, 1)),  # 13: double-green emphasis
    ((2, 1, 1), (1, 1, 0), (1, 1, 1)),  # 14: double-red variant
    ((1, 0, 2), (0, 1, 2), (0, 0, 1)),  # 15: double-blue spread
]


def _apply_color_transform(transform_index: int, delta_r: int, delta_g: int, delta_b: int) -> tuple[int, int, int]:
    """Apply a TLG6 color transform to channel deltas."""
    r_coeff, g_coeff, b_coeff = _COLOR_TRANSFORMS[transform_index]
    out_r = (r_coeff[0] * delta_r + r_coeff[1] * delta_g + r_coeff[2] * delta_b) & 0xFF
    out_g = (g_coeff[0] * delta_r + g_coeff[1] * delta_g + g_coeff[2] * delta_b) & 0xFF
    out_b = (b_coeff[0] * delta_r + b_coeff[1] * delta_g + b_coeff[2] * delta_b) & 0xFF
    return out_r, out_g, out_b


# ---------------------------------------------------------------------------
# Section 7: TLG6 spatial predictors
# ---------------------------------------------------------------------------


def _predict_median(left: int, above: int, upper_left: int, delta: int) -> int:
    """MED (median) spatial predictor.

    Computes a componentwise median-like value from three neighbors (left,
    above, upper-left) and adds the delta.  All four BGRA channels are
    processed simultaneously as packed bytes in a 32-bit integer.

    The median prediction for each byte lane is:
        if left >= max(above, upper_left): min(above, upper_left)
        if left <= min(above, upper_left): max(above, upper_left)
        otherwise:                         above + upper_left - left
    """
    # Sort left and above into (min, max) per byte lane
    gt_mask = _packed_greater_than(left, above)
    swap_bits = (left ^ above) & gt_mask
    smaller = swap_bits ^ left  # min(left, above) per lane
    larger = swap_bits ^ above  # max(left, above) per lane

    # Compare sorted values against upper_left
    use_smaller = _packed_greater_than(smaller, upper_left)  # smaller > upper_left
    use_larger = _packed_greater_than(upper_left, larger)  # upper_left > larger
    use_computed = ~(use_smaller | use_larger) & 0xFFFFFFFF  # neither extreme

    # Select: if upper_left is outside [smaller, larger], clip to the nearer bound;
    # otherwise use the linear predictor (larger - upper_left + smaller).
    prediction = (
        (use_larger & smaller)
        | (use_smaller & larger)
        | ((larger & use_computed) - (upper_left & use_computed) + (smaller & use_computed)) & 0xFFFFFFFF
    )

    return _packed_add(prediction, delta)


def _predict_average(left: int, above: int, _upper_left: int, delta: int) -> int:
    """AVG (average) spatial predictor.

    Computes the per-byte average of the left and above pixels, rounding up,
    then adds the delta.  The upper_left pixel is ignored.

    Per byte lane: ceil((left + above) / 2) = (left & above) + ((left ^ above + 1) >> 1)
    """
    # floor((a+b)/2) = (a & b) + ((a ^ b) >> 1), but we want rounding average:
    xor = left ^ above
    average = (left & above) + ((xor & 0xFEFEFEFE) >> 1) + (xor & 0x01010101)
    return _packed_add(average, delta)


# ---------------------------------------------------------------------------
# Section 8: TLG6 line decoder
# ---------------------------------------------------------------------------


def _decode_scanline(
    above_line: array.array,
    current_line: array.array,
    image_width: int,
    first_block: int,
    last_block: int,
    filter_types: bytearray,
    block_row_stride: int,
    delta_buffer: bytearray,
    initial_pixel: int,
    interleave_offset: int,
    row_direction: int,
    channel_count: int,
):
    """Decode one scanline of TLG6 pixel data from the delta buffer.

    Processes the image in 8-pixel-wide blocks from *first_block* to
    *last_block* (exclusive).  Each block has its own color transform and
    spatial predictor, selected by *filter_types*.

    The delta buffer is interleaved BGRA, organized in column-major blocks
    with a zigzag row order.  Even-indexed blocks read left-to-right; odd
    blocks read right-to-left.

    Args:
        above_line: Pixel values from the previous scanline (packed uint32).
        current_line: Output buffer for this scanline (packed uint32).
        image_width: Total image width in pixels.
        first_block: Starting block index (inclusive).
        last_block: Ending block index (exclusive).
        filter_types: Per-block filter byte array (predictor + transform).
        block_row_stride: Number of pixels per block column in this block
            group (= block_group_height * BLOCK_WIDTH).
        delta_buffer: Interleaved BGRA delta values from Golomb decoding.
        initial_pixel: Seed pixel for the left/upper-left context (0 or
            0xFF000000 for opaque).
        interleave_offset: Row interleaving offset within the block group.
        row_direction: 0 for even scanlines (left-to-right within each
            block), 1 for odd scanlines (right-to-left within each block).
        channel_count: 3 or 4.
    """
    above_idx = 0
    output_idx = 0
    delta_idx = 0

    if first_block > 0:
        above_idx = first_block * _BLOCK_WIDTH
        output_idx = first_block * _BLOCK_WIDTH
        upper_left_pixel = above_line[above_idx - 1]
        left_pixel = current_line[output_idx - 1]
    else:
        left_pixel = initial_pixel
        upper_left_pixel = initial_pixel

    delta_idx = block_row_stride * first_block * 4
    step = 1 if (row_direction & 1) else -1

    for block_col in range(first_block, last_block):
        block_width = min(image_width - block_col * _BLOCK_WIDTH, _BLOCK_WIDTH)

        # Adjust delta buffer position for block read direction
        if step == -1:
            delta_idx += (block_width - 1) * 4
        if block_col & 1:
            delta_idx += interleave_offset * block_width * 4

        # Look up this block's filter parameters
        filter_byte = filter_types[block_col]
        use_average = filter_byte & 1
        transform_index = filter_byte >> 1
        predict = _predict_average if use_average else _predict_median

        # Decode each pixel in the block
        for _px in range(block_width):
            # Extract BGRA deltas from the interleaved buffer
            delta_a = delta_buffer[delta_idx + 3]
            delta_r = delta_buffer[delta_idx + 2]
            delta_g = delta_buffer[delta_idx + 1]
            delta_b = delta_buffer[delta_idx]

            # Apply color transform
            delta_r, delta_g, delta_b = _apply_color_transform(transform_index, delta_r, delta_g, delta_b)

            # Pack as 0xAARRGGBB (BGRA in memory on little-endian)
            packed_delta = (delta_b << 16) | (delta_g << 8) | delta_r | (delta_a << 24)

            # Apply spatial prediction
            above_pixel = above_line[above_idx]
            left_pixel = predict(left_pixel, above_pixel, upper_left_pixel, packed_delta)

            if channel_count == 3:
                left_pixel |= 0xFF000000

            upper_left_pixel = above_pixel
            current_line[output_idx] = left_pixel

            output_idx += 1
            above_idx += 1
            delta_idx += step * 4

        # Advance delta buffer past this block's data
        delta_idx += (block_row_stride + (-block_width if step == 1 else 1)) * 4
        if block_col & 1:
            delta_idx -= interleave_offset * block_width * 4


# ---------------------------------------------------------------------------
# Section 9: TLG6 top-level decoder
# ---------------------------------------------------------------------------


def _init_filter_type_ring() -> bytearray:
    """Build the specially initialized ring buffer for filter type LZSS.

    The pattern fills 4096 bytes: for each (i, j) with i in 0..31 and
    j in 0..15, write 4 copies of i followed by 4 copies of j.
    """
    ring = bytearray(_RING_SIZE)
    pos = 0
    for i in range(32):
        for j in range(16):
            ring[pos : pos + 4] = bytes([i]) * 4
            ring[pos + 4 : pos + 8] = bytes([j]) * 4
            pos += 8
    return ring


def _decode_tlg6(data: bytes) -> Image.Image:
    """Decode a TLG6 image from the data following the 11-byte magic."""
    _ensure_tables()

    # --- Parse header ---
    channel_count = data[0]
    # data[1..3]: data_flag, color_type, ext_golomb_table (always 0)
    width = struct.unpack_from('<I', data, 4)[0]
    height = struct.unpack_from('<I', data, 8)[0]
    # data[12..15]: max_bit_length (unused by decoder)
    pos = 16

    x_block_count = (width + _BLOCK_WIDTH - 1) // _BLOCK_WIDTH
    y_block_count = (height + _BLOCK_HEIGHT - 1) // _BLOCK_HEIGHT
    full_block_cols = width // _BLOCK_WIDTH  # number of full 8-wide block columns
    remainder_width = width - full_block_cols * _BLOCK_WIDTH

    # --- Decompress filter types ---
    filter_compressed_size = struct.unpack_from('<I', data, pos)[0]
    pos += 4
    filter_data = data[pos : pos + filter_compressed_size]
    pos += filter_compressed_size

    filter_output = bytearray(x_block_count * y_block_count)
    filter_ring = _init_filter_type_ring()
    _lzss_decompress(filter_data, filter_output, filter_ring, 0)
    filter_types = filter_output

    # --- Decode block groups ---
    pixels = array.array("I")
    zero_line = array.array("I", [0] * width)
    previous_line = zero_line
    opaque_seed = 0xFF000000 if channel_count == 3 else 0

    for block_row in range(y_block_count):
        group_y = block_row * _BLOCK_HEIGHT
        group_y_end = min(group_y + _BLOCK_HEIGHT, height)
        group_height = group_y_end - group_y
        group_pixel_count = group_height * width

        # Read per-channel Golomb-coded bit pools
        delta_buffer = bytearray(4 * group_pixel_count)
        for channel in range(channel_count):
            header_word = struct.unpack_from('<I', data, pos)[0]
            pos += 4
            method = (header_word >> 30) & 3
            bit_count = header_word & 0x3FFFFFFF
            byte_count = (bit_count + 7) // 8
            bit_pool = data[pos : pos + byte_count]
            pos += byte_count

            if method != 0:
                raise ValueError(f"Unsupported TLG6 compression method: {method}")

            _decode_golomb_channel(delta_buffer, channel, group_pixel_count, bit_pool)

        # Get filter types for this block row
        row_filter_types = filter_types[block_row * x_block_count :]
        block_row_stride = group_height * _BLOCK_WIDTH

        # Decode each scanline in the group
        for scanline_y in range(group_y, group_y_end):
            current_line = array.array("I", b'\x00' * (width * 4))
            row_direction = (scanline_y & 1) ^ 1
            row_within_group = scanline_y - group_y
            interleave_offset = (group_y_end - scanline_y - 1) - row_within_group

            # Decode full 8-wide blocks
            if full_block_cols > 0:
                first_pixel_row_offset = min(width, _BLOCK_WIDTH) * row_within_group
                _decode_scanline(
                    previous_line,
                    current_line,
                    width,
                    0,
                    full_block_cols,
                    row_filter_types,
                    block_row_stride,
                    delta_buffer[first_pixel_row_offset * 4 :],
                    opaque_seed,
                    interleave_offset,
                    row_direction,
                    channel_count,
                )

            # Decode the partial rightmost block (if width is not a multiple of 8)
            if full_block_cols != x_block_count:
                partial_width = min(remainder_width, _BLOCK_WIDTH)
                partial_row_offset = partial_width * row_within_group
                _decode_scanline(
                    previous_line,
                    current_line,
                    width,
                    full_block_cols,
                    x_block_count,
                    row_filter_types,
                    block_row_stride,
                    delta_buffer[partial_row_offset * 4 :],
                    opaque_seed,
                    interleave_offset,
                    row_direction,
                    channel_count,
                )

            pixels.extend(current_line)
            previous_line = current_line

    # --- Convert packed pixels to PIL Image ---
    # Pixels are packed as 0xAABBGGRR — on little-endian, the byte order
    # is [R, G, B, A], which is already RGBA.
    return Image.frombytes("RGBA", (width, height), pixels.tobytes())


# ---------------------------------------------------------------------------
# Section 10: TLG0 container
# ---------------------------------------------------------------------------


def _decode_tlg0(data: bytes) -> Image.Image:
    """Decode a TLG0 container from the data following the 11-byte magic.

    Extracts the inner TLG5/TLG6 image and dispatches to the appropriate
    decoder.  Trailing metadata chunks are ignored.
    """
    inner_length = struct.unpack_from('<I', data, 0)[0]
    inner_data = data[4 : 4 + inner_length]
    return _dispatch(inner_data)


# ---------------------------------------------------------------------------
# Section 11: Dispatch and public API
# ---------------------------------------------------------------------------


def _dispatch(data: bytes) -> Image.Image:
    """Identify the TLG variant by its magic bytes and decode."""
    if len(data) < 11:
        raise ValueError("Data too short to be a TLG image")

    magic = data[:11]
    payload = data[11:]

    if magic == TLG5_MAGIC:
        return _decode_tlg5(payload)
    if magic == TLG6_MAGIC:
        return _decode_tlg6(payload)
    if magic == TLG0_MAGIC:
        return _decode_tlg0(payload)

    raise ValueError(f"Unknown TLG magic: {magic!r}")


def open_tlg(image: str | Path | io.BufferedIOBase) -> Image.Image:
    """Open a TLG image and return a PIL Image.

    Args:
        image: Path to a TLG file (str or Path), or a file-like object
            opened in binary mode.

    Returns:
        A PIL Image in RGBA mode.

    Raises:
        ValueError: If the file is not a valid TLG image.
        ImportError: If Pillow is not installed.
    """
    if Image is None:
        raise ImportError("Pillow is required for TLG image conversion. " "Install it with: pip install tamago[images]")

    if isinstance(image, (str, os.PathLike)):
        with open(image, 'rb') as f:
            data = f.read()
    else:
        data = image.read()

    return _dispatch(data)


# ---------------------------------------------------------------------------
# Section 12: C accelerator binding
#
# When _tlg_accel is available, rebind the three hot-loop functions to
# their C implementations.  The pure-Python versions above remain as
# _lzss_decompress_py / etc. for testing and as a fallback.
# ---------------------------------------------------------------------------

if _tlg_accel is not None:
    _lzss_decompress_py = _lzss_decompress
    _decode_golomb_channel_py = _decode_golomb_channel
    _decode_scanline_py = _decode_scanline

    _lzss_decompress = _tlg_accel.lzss_decompress
    _decode_golomb_channel = _tlg_accel.decode_golomb_channel
    _decode_scanline = _tlg_accel.decode_scanline

    _correlate_channels_py = _correlate_channels
    _correlate_channels = _tlg_accel.correlate_channels
