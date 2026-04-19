"""Conversion between 32-bit DOS date/time values and Python :class:`datetime`.

The layout is the MS-DOS / FAT format:

    bits 31-25  year - 1980    (0-127 → 1980-2107)
    bits 24-21  month          (1-12)
    bits 20-16  day            (1-31)
    bits 15-11  hour           (0-23)
    bits 10-5   minute         (0-59)
    bits 4-0    seconds / 2    (0-29 → 0-58 seconds, 2-second resolution)

LiveMaker stores per-file timestamps as a single little-endian uint32 in
this format.  Seconds have 2-second granularity, so round-tripping an
odd-second value will clamp it to the even second below.
"""

import datetime


def encode(dt: datetime.datetime) -> int:
    """Encode *dt* to a DOS date/time uint32.

    Raises :class:`ValueError` if the year is outside 1980-2107.
    """
    if not 1980 <= dt.year <= 2107:
        raise ValueError(f"Year {dt.year} outside DOS date range 1980-2107")
    return (
        ((dt.year - 1980) & 0x7F) << 25
        | (dt.month & 0xF) << 21
        | (dt.day & 0x1F) << 16
        | (dt.hour & 0x1F) << 11
        | (dt.minute & 0x3F) << 5
        | ((dt.second // 2) & 0x1F)
    )


def decode(value: int) -> datetime.datetime:
    """Decode a DOS date/time uint32 to a naive :class:`datetime`.

    Returns :data:`None`-free values; callers that need a timezone-aware
    object should attach one themselves.  Invalid encodings raise
    :class:`ValueError` via :class:`datetime`'s own validation.
    """
    year = ((value >> 25) & 0x7F) + 1980
    month = (value >> 21) & 0xF
    day = (value >> 16) & 0x1F
    hour = (value >> 11) & 0x1F
    minute = (value >> 5) & 0x3F
    second = (value & 0x1F) * 2
    return datetime.datetime(year, month, day, hour, minute, second)  # noqa: DTZ001
