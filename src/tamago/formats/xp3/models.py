"""XP3 archive format data models and binary structure definitions.

An XP3 archive consists of:
  1. A header with magic bytes and an offset to the file table
  2. File data segments (compressed and/or encrypted)
  3. A file table (optionally zlib-compressed) containing metadata

The file table is a sequence of TLV (tag-length-value) sections, each with a
4-byte ASCII tag, an 8-byte little-endian size, and that many bytes of payload.

The header may include a continuation block: if the byte at the initial
info_offset is 0x80, skip 8 bytes and read the real offset.
"""

from construct import (
    Bytes,
    Computed,
    Const,
    ExprAdapter,
    Flag,
    GreedyBytes,
    GreedyRange,
    If,
    Int16ul,
    Int32ul,
    Int64ul,
    Padding,
    Prefixed,
    Rebuild,
    Struct,
    Switch,
    this,
)

XP3_MAGIC = b"XP3\x0d\x0a\x20\x0a\x1a\x8b\x67\x01"


def _xp3_string():
    """Length-prefixed UTF-16LE string: 2-byte character count + encoded characters.

    Returns (name_size, file_name) subconstructs for use with Struct(*_xp3_string()).
    """
    return (
        "name_size" / Rebuild(Int16ul, lambda ctx: len(ctx.file_name)),
        "file_name"
        / ExprAdapter(
            Bytes(this.name_size * 2),
            decoder=lambda obj, _ctx: obj.decode("utf_16le"),
            encoder=lambda obj, _ctx: obj.encode("utf_16le"),
        ),
    )


# ---------------------------------------------------------------------------
# XP3 binary format definitions
# ---------------------------------------------------------------------------

XP3Header = "Archive header" * Struct(
    "magic" / Const(XP3_MAGIC),
    "info_offset" / Int64ul * "byte offset to the file table (or continuation block)",
)

XP3CreateHeader = "Full header as written by tamago (includes continuation block)" * Struct(
    "magic" / Const(XP3_MAGIC),
    "info_offset" / Const(b"\x17\x00\x00\x00\x00\x00\x00\x00") * "points to continuation at 0x17",
    "version" / Const(b"\x01\x00\x00\x00"),
    "continuation" / Const(b"\x80"),
    Padding(8) * "reserved",
    "real_info_offset" / Int64ul * "patched by write_info() after the file table is written",
)

XP3IndexHeader = "File table index header (precedes the file table data)" * Struct(
    "compressed" / Flag * "whether the file table data is zlib-compressed",
    "compressed_size" / If(this.compressed, Int64ul),
    "uncompressed_size" / Int64ul,
)

XP3Segment = "Data segment entry within a 'segm' chunk (28 bytes)" * Struct(
    "flags" / Int32ul * "bit 0 = zlib-compressed",
    "compressed" / Computed(lambda ctx: bool(ctx.flags & 1)),
    "offset" / Int64ul * "absolute byte offset of segment data in the archive",
    "original_size" / Int64ul,
    "compressed_size" / Int64ul,
)

XP3InfoChunk = "'info' chunk -- file metadata" * Struct(
    "flags" / Int32ul * "bit 31 = encrypted",
    "encrypted" / Computed(lambda ctx: bool(ctx.flags & (1 << 31))),
    "original_size" / Int64ul,
    "compressed_size" / Int64ul,
    *_xp3_string(),
)

XP3AdlrChunk = "'adlr' chunk -- adler32 hash, used as encryption key" * Struct(
    "key" / Int32ul,
)

XP3TimeChunk = "'time' chunk -- Windows FILETIME (100ns intervals since 1601-01-01)" * Struct(
    "timestamp" / Int64ul,
)

XP3EliF = "'eliF' section -- alias for a duplicate file" * Struct(
    "file_hash" / Int32ul * "adler32 hash matching the target File's 'adlr' chunk",
    *_xp3_string(),
)

XP3FileChunk = "Chunk within a File section (TLV with tag-dispatched parsing)" * Struct(
    "tag" / Bytes(4),
    "data"
    / Prefixed(
        Int64ul,
        Switch(
            this.tag,
            {
                b"info": XP3InfoChunk,
                b"adlr": XP3AdlrChunk,
                b"time": XP3TimeChunk,
                b"segm": GreedyRange(XP3Segment),
            },
            default=GreedyBytes,
        ),
    ),
)

XP3Section = "Top-level file table section (TLV with tag-dispatched parsing)" * Struct(
    "tag" / Bytes(4),
    "data"
    / Prefixed(
        Int64ul,
        Switch(
            this.tag,
            {
                b"File": GreedyRange(XP3FileChunk),
                b"eliF": XP3EliF,
            },
            default=GreedyBytes,
        ),
    ),
)

XP3FileTable = GreedyRange(XP3Section)


# ---------------------------------------------------------------------------
# XP3Info — file entry metadata
# ---------------------------------------------------------------------------

XP3_FLAG_ENCRYPTED = 1 << 31


class XP3Info:
    """Metadata for a file entry in an XP3 archive.

    Segments are construct Containers parsed from XP3Segment, with fields:
    flags, compressed (bool), offset, original_size, compressed_size.
    """

    __slots__ = (
        'file_name',
        'compressed_size',
        'original_size',
        'flags',
        'key',
        'timestamp',
        'segments',
    )

    def __init__(
        self,
        file_name: str = '',
        flags: int = 0,
        original_size: int = 0,
        compressed_size: int = 0,
        key: int = 0,
        segments: list | None = None,
    ):
        self.file_name = file_name
        self.flags = flags
        self.original_size = original_size
        self.compressed_size = compressed_size
        self.key = key
        self.segments = segments if segments is not None else []

    @property
    def encrypted(self) -> bool:
        return bool(self.flags & XP3_FLAG_ENCRYPTED)

    def __repr__(self):
        return (
            f"XP3Info(file_name={self.file_name!r}, key={self.key!r},"
            f" compressed_size={self.compressed_size!r}, original_size={self.original_size!r})"
        )

    def get_info_bytes(self) -> bytes:
        """Build binary bytes for a File section."""
        # TODO: time chunks
        # TODO: eliF sections

        return XP3Section.build(
            {
                "tag": b"File",
                "data": [
                    {
                        "tag": b"info",
                        "data": {
                            "flags": self.flags,
                            "original_size": self.original_size,
                            "compressed_size": self.compressed_size,
                            "file_name": self.file_name,
                        },
                    },
                    {
                        "tag": b"segm",
                        "data": [
                            {
                                "flags": s.flags,
                                "offset": s.offset,
                                "original_size": s.original_size,
                                "compressed_size": s.compressed_size,
                            }
                            for s in self.segments
                        ],
                    },
                    {
                        "tag": b"adlr",
                        "data": {"key": self.key},
                    },
                ],
            }
        )
