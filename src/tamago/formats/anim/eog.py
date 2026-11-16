"""EOG audio: Ogg Vorbis behind an 8-byte header.

An EOG file is ``CRM\\0``, a u32 (little-endian) that gives the decoded length
in bytes of 16-bit PCM, then an ordinary Ogg Vorbis stream to the end of the
file.  The engine does not appear to rely on the length: a few shipped files
hold 0 or the MSVC heap fill ``0xCDCDCDCD`` there.
"""

import logging
import struct

logger = logging.getLogger(__name__)

EOG_MAGIC = b'CRM\x00'
EOG_HEADER_SIZE = 8
OGG_MAGIC = b'OggS'
MAX_U32 = 0xFFFFFFFF

_PAGE_HEADER = struct.Struct('<4sBBqIIIB')
_VORBIS_ID = b'\x01vorbis'


def is_eog(data: bytes) -> bool:
    """Return True if *data* is EOG-wrapped Ogg."""
    return data[:4] == EOG_MAGIC and data[EOG_HEADER_SIZE : EOG_HEADER_SIZE + 4] == OGG_MAGIC


def unwrap_eog(data: bytes) -> bytes:
    """Return the Ogg stream inside EOG *data*.  Raises ValueError if *data* is not EOG."""
    if not is_eog(data):
        raise ValueError("not EOG audio (expected 'CRM\\0' followed by an Ogg stream)")
    return bytes(data[EOG_HEADER_SIZE:])


def pcm_size(ogg: bytes) -> int:
    """Return the decoded size of Ogg Vorbis *ogg* as 16-bit PCM: samples x channels x 2.

    The sample count is the granule position of the last page; the channel count
    comes from the Vorbis identification header.  Raises ValueError if *ogg* is
    not a well-formed Ogg Vorbis stream.
    """
    pos = 0
    channels = None
    granule = -1
    while pos < len(ogg):
        if pos + _PAGE_HEADER.size > len(ogg):
            raise ValueError(f"truncated Ogg page header at offset {pos}")
        magic, _version, _flags, page_granule, _serial, _seq, _crc, segments = _PAGE_HEADER.unpack_from(ogg, pos)
        if magic != OGG_MAGIC:
            raise ValueError(f"expected an Ogg page at offset {pos}")
        body = pos + _PAGE_HEADER.size + segments
        if body > len(ogg):
            raise ValueError(f"truncated Ogg segment table at offset {pos}")
        if channels is None:
            if ogg[body : body + len(_VORBIS_ID)] != _VORBIS_ID or body + 12 > len(ogg):
                raise ValueError("the Ogg stream does not start with a Vorbis identification header")
            channels = ogg[body + 11]
        if page_granule >= 0:
            granule = page_granule
        pos = body + sum(ogg[pos + _PAGE_HEADER.size : body])
        if pos > len(ogg):
            raise ValueError("truncated Ogg page")
    if channels is None:
        raise ValueError("empty Ogg stream")
    return max(granule, 0) * channels * 2


def wrap_ogg(ogg: bytes) -> bytes:
    """Wrap Ogg Vorbis *ogg* as EOG, the inverse of :func:`unwrap_eog`.

    Raises ValueError if *ogg* does not start with an Ogg page.  If the PCM size
    cannot be worked out (the stream is malformed or not Vorbis), 0 is stored with
    a warning, as some shipped files have.
    """
    if ogg[:4] != OGG_MAGIC:
        raise ValueError("not an Ogg stream (expected 'OggS')")
    try:
        size = pcm_size(ogg)
    except ValueError as exc:
        logger.warning('Cannot work out the decoded size of an Ogg stream (%s); storing 0', exc)
        size = 0
    if size > MAX_U32:
        logger.warning('Decoded size %d does not fit in 32 bits; storing 0', size)
        size = 0
    return EOG_MAGIC + struct.pack('<I', size) + ogg
