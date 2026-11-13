"""WADY audio decoder.

WADY is a Marble engine audio format, kept by Fudegaki Soft's engine for the
music in its ``md_bgm.med`` archives.  It codes 16-bit PCM at one byte per
sample: either a step from the previous sample, taken from a fixed nonlinear
table and scaled by a per-file factor, or a coarse absolute value.

Only this byte-per-sample coding ("v1") is supported.  A second coding ("v2"),
with interpolated runs, is known from other decoders but has not been seen in
any sample, so it is refused rather than guessed at.
"""

from __future__ import annotations

import os
import sys
import wave
from array import array
from dataclasses import dataclass
from typing import BinaryIO

from construct import Bytes, Const, ConstructError, Int8ul, Int16ul, Int32ul, Struct

WADY_MAGIC = b'WADY'

_HEADER = Struct(
    'magic' / Const(WADY_MAGIC),
    'unknown' / Int8ul,
    'scale' / Int8ul,
    'channels' / Int16ul,
    'sample_rate' / Int32ul,
    'sample_count' / Int32ul,
    'frame_count' / Int32ul,
    'pcm_size' / Int32ul,
    'reserved' / Bytes(8),
    'format_tag' / Int16ul,
    'format_channels' / Int16ul,
    'format_sample_rate' / Int32ul,
    'byte_rate' / Int32ul,
    'block_align' / Int16ul,
    'bits_per_sample' / Int16ul,
)
HEADER_SIZE = _HEADER.sizeof()

# Step sizes for codes 0x00..0x3F; bit 0x40 negates the step.
STEP = (
    0x0000, 0x0002, 0x0004, 0x0006, 0x0008, 0x000A, 0x000C, 0x000F,
    0x0012, 0x0015, 0x0018, 0x001C, 0x0020, 0x0024, 0x0028, 0x002C,
    0x0031, 0x0036, 0x003B, 0x0040, 0x0046, 0x004C, 0x0052, 0x0058,
    0x005F, 0x0066, 0x006D, 0x0074, 0x007C, 0x0084, 0x008C, 0x0094,
    0x00A0, 0x00AA, 0x00B4, 0x00BE, 0x00C8, 0x00D2, 0x00DC, 0x00E6,
    0x00F0, 0x00FF, 0x010E, 0x011D, 0x012C, 0x0140, 0x0154, 0x0168,
    0x017C, 0x0190, 0x01A9, 0x01C2, 0x01DB, 0x01F4, 0x020D, 0x0226,
    0x0244, 0x0262, 0x028A, 0x02BC, 0x02EE, 0x0320, 0x0384, 0x03E8,
)  # fmt: skip

_MASK16 = (0xFFFF).__and__


@dataclass
class WadyAudio:
    """Decoded WADY audio: interleaved signed 16-bit little-endian PCM."""

    channels: int
    sample_rate: int
    pcm: bytes

    def save_wav(self, target: str | os.PathLike | BinaryIO) -> None:
        """Write the audio as a PCM WAV file to a path or binary file object."""
        if isinstance(target, (str, os.PathLike)):
            target = os.fspath(target)
        with wave.open(target, 'wb') as w:  # type: ignore[arg-type]
            w.setnchannels(self.channels)
            w.setsampwidth(2)
            w.setframerate(self.sample_rate)
            w.writeframes(self.pcm)


def is_wady(data: bytes) -> bool:
    """Return True if *data* starts with a WADY header."""
    return len(data) >= HEADER_SIZE and data[:4] == WADY_MAGIC


def _decode_channel(coded: bytes, scale: int) -> array:
    """Decode one channel's coded bytes to unsigned 16-bit sample words."""
    # For each code, the absolute sample it sets, or None for a step.
    absolute = [None] * 0x80 + [(v << 9) & 0xFFFF for v in range(0x80, 0x100)]
    step = [STEP[v & 0x3F] * scale * (-1 if v & 0x40 else 1) for v in range(0x80)] + [0] * 0x80
    samples: list[int] = []
    append = samples.append
    prev = 0
    for v in coded:
        a = absolute[v]
        if a is None:
            prev += step[v]
        else:
            prev = a
        append(prev)
    # The running value is kept unbounded above; reduce it to 16 bits once, at C speed.
    return array('H', map(_MASK16, samples))


def decode_wady(data: bytes) -> WadyAudio:
    """Decode the WADY audio *data* to PCM.

    Raises ValueError for data that is not a valid WADY file, and
    NotImplementedError for the v2 coding.
    """
    if data[:4] != WADY_MAGIC:
        raise ValueError("Not WADY audio: missing 'WADY' signature")
    try:
        header = _HEADER.parse(data)
    except ConstructError:
        raise ValueError("WADY header is truncated") from None
    channels = header.channels
    if channels not in (1, 2):
        raise ValueError(f"Unsupported WADY channel count {channels}")
    if header.sample_count % channels:
        raise ValueError(f"WADY sample count {header.sample_count} does not divide into {channels} channels")
    body = data[HEADER_SIZE:]
    if len(body) != header.sample_count:
        raise NotImplementedError(
            f"WADY v2 coding is not supported ({len(body)} coded bytes for {header.sample_count} samples)"
        )

    pcm = array('H', bytes(2 * header.sample_count))
    for channel in range(channels):
        pcm[channel::channels] = _decode_channel(body[channel::channels], header.scale)
    if sys.byteorder == 'big':
        pcm.byteswap()
    return WadyAudio(channels, header.sample_rate, pcm.tobytes())
