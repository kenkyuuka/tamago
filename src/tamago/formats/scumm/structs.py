"""Fixed-layout block bodies of the Humongous SCUMM resource files (all little-endian)."""

from construct import Array, Bytes, Int8ul, Int16sl, Int16ul, Int32sl, Int32ul, Struct, this

# HSHD: header of a DIGI/TALK sound. The bits/channels bytes are often
# uninitialised garbage; the engine plays every DIGI as 8-bit mono.
SoundHeader = Struct(
    'compressed' / Int8ul,
    'formatted' / Int8ul,
    'kill_priority' / Int8ul,
    'dead_priority' / Int8ul,
    'left_volume' / Int8ul,
    'right_volume' / Int8ul,
    'rate' / Int16ul,
    'mondo_offset' / Int32ul,
    'bits_per_sample' / Int8ul,
    'channels' / Int8ul,
)

# RMHD (SCUMM v6 / HE): room size.
RoomHeader = Struct(
    'width' / Int16ul,
    'height' / Int16ul,
    'object_count' / Int16ul,
)

# IMHD (SCUMM v6 / HE): object image header.
ImageHeader = Struct(
    'object' / Int16ul,
    'image_count' / Int16ul,
    'flags' / Int16ul,
    'unknown' / Int16ul,
    'x' / Int16sl,
    'y' / Int16sl,
    'width' / Int16ul,
    'height' / Int16ul,
)

# CDHD (SCUMM v6 / HE): object code header; only the leading fields are used.
CodeHeader = Struct(
    'object' / Int16ul,
)

# WIZH: WIZ image header.
WizHeader = Struct(
    'codec' / Int32ul,
    'width' / Int32ul,
    'height' / Int32ul,
)

# A resource directory (DIRI, DIRR, DIRS, DIRN, DIRC, DIRF, DIRM, DIRT) in an
# HE index: per entry its room, its offset from the room's LFLF body, and its size.
Directory = Struct(
    'count' / Int16ul,
    'rooms' / Array(this.count, Int8ul),
    'offsets' / Array(this.count, Int32ul),
    'sizes' / Array(this.count, Int32ul),
)

# DLFL: offset of every room's LFLF body in the data file.
RoomOffsets = Struct(
    'count' / Int16ul,
    'offsets' / Array(this.count, Int32ul),
)

# Song table entries of a .he4 music file: 25 bytes in SGHD (HE < 80), or the
# body of each SGEN block (HE >= 80).
SongEntry = Struct(
    'song' / Int32sl,
    'offset' / Int32sl,
    'size' / Int32sl,
)
OldSongEntry = Struct(
    'song' / Int32sl,
    'offset' / Int32sl,
    'size' / Int32sl,
    'name' / Bytes(13),
)

# AKHD: costume header.
AkosHeader = Struct(
    'version' / Int16ul,
    'flags' / Int16ul,
    'chore_count' / Int16ul,
    'cel_count' / Int16ul,
    'codec' / Int16ul,
    'layer_count' / Int16ul,
)

# AKOF entry: where a cel's pixels (in AKCD) and size (in AKCI) are.
AkosOffset = Struct(
    'akcd' / Int32ul,
    'akci' / Int16ul,
)

# AKCI entry in HE games: only the cel's size (ScummVM's 12-byte CostumeInfo
# does not apply; the entries are 4 bytes apart).
CelInfo = Struct(
    'width' / Int16ul,
    'height' / Int16ul,
)
