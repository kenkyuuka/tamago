"""Synthetic Humongous SCUMM files, built without the library so that tests check it independently."""

from __future__ import annotations

import struct

XOR = 0x69


def block(tag: str, body: bytes = b'') -> bytes:
    return tag.encode('ascii') + struct.pack('>I', 8 + len(body)) + body


def xor(data: bytes) -> bytes:
    return bytes(b ^ XOR for b in data)


class BitWriter:
    """Writes values least-significant bit first, as the SCUMM bit-stream codecs read them."""

    def __init__(self):
        self.bits: list[int] = []

    def put(self, value: int, count: int = 1) -> BitWriter:
        self.bits += [(value >> i) & 1 for i in range(count)]
        return self

    def bytes(self, pad_to: int = 0) -> bytes:
        bits = self.bits + [0] * (-len(self.bits) % 8)
        out = bytes(sum(bits[i + j] << j for j in range(8)) for i in range(0, len(bits), 8))
        return out.ljust(pad_to, b'\0')


# -- sounds ------------------------------------------------------------------

# 8-bit unsigned PCM: any bytes will do.
MOCK_TURTLE = b'Beautiful Soup, so rich and green'
WHITE_RABBIT = b'Oh my ears and whiskers!'
QUEEN = b'Off with her head!'


def hshd(rate: int, *, bits: int = 0xD8, channels: int = 0xF1) -> bytes:
    """An HSHD body; the bits/channels bytes default to the garbage seen in the games."""
    return struct.pack('<BBBBBBHIBBH', 0, 0, 0x80, 0x80, 0xFF, 0xFF, rate, 0, bits, channels, 0)


def digi(samples: bytes, rate: int = 11025, *, tag: str = 'DIGI', sbng: bytes | None = None) -> bytes:
    body = block('HSHD', hshd(rate))
    if sbng is not None:
        body += block('SBNG', sbng)
    return block(tag, body + block('SDAT', samples))


def wav(samples: bytes, rate: int) -> bytes:
    """The WAV file a converter should produce: PCM, mono, 8-bit."""
    fmt = struct.pack('<HHIIHH', 1, 1, rate, rate, 1, 8)
    data = b'data' + struct.pack('<I', len(samples)) + samples + (b'\0' if len(samples) % 2 else b'')
    body = b'WAVE' + b'fmt ' + struct.pack('<I', 16) + fmt + data
    return b'RIFF' + struct.pack('<I', len(body)) + body


# -- images --------------------------------------------------------------------

# A palette whose entry i is (i, 255 - i, 2i mod 256), so that colours identify indices.
PALETTE = bytes(v for i in range(256) for v in (i, 255 - i, (2 * i) & 0xFF))
TRANSPARENT = 5


def rgb(index: int) -> tuple[int, int, int]:
    return PALETTE[3 * index], PALETTE[3 * index + 1], PALETTE[3 * index + 2]


def pals(palette: bytes = PALETTE) -> bytes:
    """PALS > WRAP > OFFS + APAL, with one palette."""
    offs = block('OFFS', struct.pack('<I', 4 + 8))
    return block('PALS', block('WRAP', offs + block('APAL', palette)))


def smap(strips: list[bytes]) -> bytes:
    """An SMAP block from encoded strips (each starting with its codec byte)."""
    table_size = 8 + 4 * len(strips)
    offsets, pos = [], table_size
    for strip in strips:
        offsets.append(pos)
        pos += len(strip)
    return block('SMAP', struct.pack(f'<{len(strips)}I', *offsets) + b''.join(strips))


def raw_strip(pixels: list[int], *, transparent: bool = False) -> bytes:
    """A strip in codec 1 (raw) or 149 (raw with transparency)."""
    return bytes([149 if transparent else 1, *pixels])


def imhd(obj: int, states: int, width: int, height: int, x: int = 0, y: int = 0) -> bytes:
    return block('IMHD', struct.pack('<HHHHhhHHH', obj, states, 1, 0, x, y, width, height, 0))


def obcd(obj: int, name: bytes) -> bytes:
    cdhd = block('CDHD', struct.pack('<HhhHHBB', obj, 0, 0, 8, 2, 0, 0))
    return block('OBCD', cdhd + block('VERB', b'\0') + block('OBNA', name + b'\0'))


# A 16 x 2 background in codec 138 (new major/minor, 8-bit literals): the
# first colour 0x2A, then a literal 7, then repeats.
BACKGROUND_WIDTH, BACKGROUND_HEIGHT = 16, 2
# The stream is long enough for every pixel, as real data is.
BACKGROUND_BMAP = bytes([138, 0x2A]) + BitWriter().put(1).put(0).put(7, 8).bytes(pad_to=8)
BACKGROUND_PIXELS = [0x2A] + [7] * (BACKGROUND_WIDTH * BACKGROUND_HEIGHT - 1)

# A two-strip 16 x 2 object image, state 1: a raw strip, then a raw
# transparent strip whose colour-5 pixels are see-through.
OBJECT_NUMBER = 7
OBJECT_STRIP_A = [10, 11, 12, 13, 14, 15, 16, 17, 5, 5, 5, 5, 5, 5, 5, 5]
OBJECT_STRIP_B = [20, 5, 21, 5, 22, 5, 23, 5, 24, 25, 26, 27, 28, 29, 30, 31]


def rmda(*, transparent_u16: bool = True) -> bytes:
    trns = struct.pack('<H', TRANSPARENT) if transparent_u16 else bytes([TRANSPARENT])
    obim = block(
        'OBIM',
        imhd(OBJECT_NUMBER, 1, 16, 2)
        + block('IM01', smap([raw_strip(OBJECT_STRIP_A), raw_strip(OBJECT_STRIP_B, transparent=True)])),
    )
    return block(
        'RMDA',
        block('RMHD', struct.pack('<HHH', BACKGROUND_WIDTH, BACKGROUND_HEIGHT, 1))
        + block('CYCL', b'\0')
        + block('TRNS', trns)
        + pals()
        + obim
        + obcd(OBJECT_NUMBER, b'Cheshire Cat')
        + block('EXCD', b'\x65')
        + block('ENCD', b'\x65'),
    )


def rmim() -> bytes:
    return block('RMIM', block('RMIH', b'\0\0') + block('IM00', block('BMAP', BACKGROUND_BMAP)))


# A 4 x 3 WIZ image in TRLE (codec 1): row 0 is "skip 1, literal 40 41,
# skip 1"; row 1 is empty (all transparent); row 2 is "run of 4 pixels of colour 42".
WIZ_WIDTH, WIZ_HEIGHT = 4, 3
WIZ_TRLE = (
    struct.pack('<H', 5)
    + bytes([0b11, 0b100, 40, 41, 0b11])
    + struct.pack('<H', 0)
    + struct.pack('<H', 2)
    + bytes([0b1110, 42])
)


def awiz(*, rgbs: bytes | None = None) -> bytes:
    body = block('WIZH', struct.pack('<III', 1, WIZ_WIDTH, WIZ_HEIGHT))
    if rgbs is not None:
        body += block('RGBS', rgbs)
    return block('AWIZ', body + block('SPOT', struct.pack('<ii', 0, 0)) + block('WIZD', WIZ_TRLE))


# -- costumes ----------------------------------------------------------------

# A 2 x 3 BYLE cel (16 slots: high nibble = slot, low nibble = length). Down
# column 0: slot 0, then slots 2, 2; down column 1: slots 3, 3 (length in the
# next byte), then slot 0.
BYLE_CEL = bytes([0x01, 0x22, 0x30, 0x02, 0x01])
BYLE_SLOTS = [[0, 3], [2, 3], [2, 0]]  # row by row
CEL_AKPL = bytes([0, 0, 210, 211]) + bytes(range(4, 16))
ORANGE, YELLOW = (255, 143, 19), (199, 191, 0)


def short_rgbs() -> bytes:
    """An HE 71 RGBS: one colour per AKPL slot."""
    colours = [(0, 0, 0), (0, 0, 0), ORANGE, YELLOW] + [(9, 9, 9)] * 12
    return bytes(v for c in colours for v in c)


def full_rgbs() -> bytes:
    """An HE 80+ RGBS: a 256-entry palette, indexed by AKPL value."""
    rgbs = bytearray(768)
    rgbs[3 * 210 : 3 * 210 + 3] = bytes(ORANGE)
    rgbs[3 * 211 : 3 * 211 + 3] = bytes(YELLOW)
    return bytes(rgbs)


def sqdb(names: list[bytes]) -> bytes:
    """A sequence table (HE 80-90) naming the costume's animation sequences."""
    seqis = [block('SEQI', block('NAME', n + b'\0') + block('STOF', bytes(4)) + block('SIZE', bytes(4))) for n in names]
    offsets, pos = [], 0
    for seqi in seqis:
        offsets.append(pos)
        pos += len(seqi)
    offs = block('OFFS', struct.pack(f'<{len(seqis)}I', *offsets))
    return block('SQDB', block('WRAP', offs + b''.join(seqis)))


def akos(
    codec: int,
    cels: list[tuple[int, int, bytes]],
    *,
    akpl: bytes = CEL_AKPL,
    rgbs: bytes | None = None,
    sequences: list[bytes] | None = None,
) -> bytes:
    """A costume with the given ``(width, height, data)`` cels, and optionally named sequences."""
    akof, akci, akcd = b'', b'', b''
    for i, (width, height, data) in enumerate(cels):
        akof += struct.pack('<IH', len(akcd), 4 * i)
        akci += struct.pack('<HH', width, height)
        akcd += data
    body = block('AKHD', struct.pack('<6H', 1, 0, 0, len(cels), codec, 1)) + block('AKPL', akpl)
    if rgbs is not None:
        body += block('RGBS', rgbs)
    body += block('AKSQ', b'\0') + block('AKCH', b'\0') + block('AKOF', akof) + block('AKCI', akci)
    if sequences is not None:
        body += sqdb(sequences)
    return block('AKOS', body + block('AKCD', akcd))


# The costume in the sample room: the BYLE cel, then an empty (0 x 0) cel,
# with two named sequences (the first names its folder).
COSTUME = akos(1, [(2, 3, BYLE_CEL), (0, 0, b'')], rgbs=short_rgbs(), sequences=[b'', b'Alice shrinks', b'grows'])

# -- whole files ------------------------------------------------------------

SCRIPT = block('SCRP', b'\x65 Drink me')


def room_file() -> tuple[bytes, list[int], dict[str, tuple[int, int, int]]]:
    """A one-room ``.he1`` (not yet obfuscated), the DLFL offsets, and where each resource lives.

    The room holds, in order: RMIM, RMDA, a global script (1), a sound (2) in
    a SOUN wrapper with a stray trailing byte as in Freddi Fish 1, a bare DIGI
    sound (3), a WIZ image (4) and a costume (1).
    """
    parts = [
        ('RMIM', rmim()),
        ('RMDA', rmda()),
        ('SCRP', SCRIPT),
        ('SOUN', block('SOUN', digi(MOCK_TURTLE, 11025) + b'\x80')),
        ('DIGI', digi(WHITE_RABBIT, 11000)),
        ('AWIZ', awiz()),
        ('AKOS', COSTUME),
    ]
    places: dict[str, tuple[int, int, int]] = {}
    pos = 0
    for tag, data in parts:
        places[tag] = (1, pos, len(data))
        pos += len(data)
    lflf = block('LFLF', b''.join(data for _tag, data in parts))
    return block('LECF', lflf), [0, 16], places


def directory(count: int, entries: dict[int, tuple[int, int, int]]) -> bytes:
    """A DIRx body with *count* slots; *entries* maps a number to (room, offset, size)."""
    rooms = [entries.get(i, (0, 0, 0))[0] for i in range(count)]
    offsets = [entries.get(i, (0, 0, 0))[1] for i in range(count)]
    sizes = [entries.get(i, (0, 0, 0xFFFFFFFF))[2] for i in range(count)]
    return struct.pack(f'<H{count}B{count}I{count}I', count, *rooms, *offsets, *sizes)


def index_file(room_offsets: list[int], places: dict[str, tuple[int, int, int]]) -> bytes:
    """A ``.he0`` (not yet obfuscated) describing :func:`room_file`."""
    return (
        block('RNAM', b'\0')
        + block('MAXS', bytes(30))
        + block('DIRI', directory(2, {1: places['RMIM']}))
        + block('DIRR', directory(2, {1: places['RMDA']}))
        + block('DIRS', directory(2, {1: places['SCRP']}))
        + block('DIRN', directory(4, {2: places['SOUN'], 3: places['DIGI']}))
        + block('DIRC', directory(2, {1: places['AKOS']}))
        + block('DIRF', directory(1, {}))
        + block('DIRM', directory(5, {4: places['AWIZ']}))
        + block('DLFL', struct.pack(f'<H{len(room_offsets)}I', len(room_offsets), *room_offsets))
        + block('DOBJ', b'\0\0')
        + block('AARY', b'\0\0')
    )


def speech_file() -> tuple[bytes, list[int]]:
    """A ``.he2`` (not yet obfuscated) with two lines, and the offsets of their TALK blocks."""
    first = digi(QUEEN, 11000, tag='TALK', sbng=b'\x00\x20')
    second = digi(WHITE_RABBIT, 11025, tag='TALK')
    return block('TLKB', first + second), [8, 8 + len(first)]


def music_file(*, old: bool) -> bytes:
    """A ``.he4`` with songs 4000 and 4001, in the HE < 80 (*old*) or HE >= 80 table layout."""
    songs = [(4000, digi(MOCK_TURTLE, 11025)), (4001, digi(QUEEN, 11000))]
    if old:
        header_size = 8 + 8 + 4 + 25 * len(songs)
    else:
        header_size = 8 + 8 + 32 + 21 * len(songs)
    entries, pos = [], header_size
    for number, data in songs:
        entries.append((number, pos, len(data)))
        pos += len(data)
    if old:
        table = struct.pack('<I', len(songs)) + b''.join(struct.pack('<iii', *e) + b'abcdefghijklm' for e in entries)
        head = block('SGHD', table)
    else:
        head = block('SGHD', struct.pack('<I', len(songs)) + bytes(28))
        head += b''.join(block('SGEN', struct.pack('<iii', *e) + b'\0') for e in entries)
    return block('SONG', head + b''.join(data for _n, data in songs))
