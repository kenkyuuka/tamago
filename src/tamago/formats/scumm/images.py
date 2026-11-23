"""Humongous room backgrounds, object images and WIZ images to PIL images."""

from __future__ import annotations

from dataclasses import dataclass

import construct
from PIL import Image

from tamago.formats.scumm import codecs
from tamago.formats.scumm.blocks import Block
from tamago.formats.scumm.structs import AkosHeader, AkosOffset, CelInfo, ImageHeader, RoomHeader, WizHeader

PALETTE_SIZE = 768
# Transparency mask byte (1 = transparent) to alpha.
_ALPHA = bytes([255, 0]) + bytes(254)
DEFAULT_TRANSPARENT = 5

# WIZ codecs (WizCompressionTypes in ScummVM's wiz_he.h).
WIZ_RAW = 0
WIZ_TRLE = 1
WIZ_RAW_16BPP = 2


class ImageError(ValueError):
    """An image block cannot be decoded."""


def _image(pixels: bytearray, mask: bytearray | None, width: int, height: int, palette: bytes) -> Image.Image:
    """An indexed image, or RGBA when some pixels are transparent."""
    im = Image.frombytes('P', (width, height), bytes(pixels))
    im.putpalette(palette[:PALETTE_SIZE].ljust(PALETTE_SIZE, b'\0'))
    if mask is None:
        return im
    rgba = im.convert('RGBA')
    alpha = Image.frombytes('L', (width, height), bytes(mask).translate(_ALPHA))
    rgba.putalpha(alpha)
    return rgba


@dataclass
class RoomInfo:
    """What decoding a room's images needs from its RMDA block."""

    width: int
    height: int
    transparent: int
    palette: bytes
    object_names: dict[int, str]


def first_palette(pals: Block) -> bytes | None:
    """Palette 0 of a ``PALS > WRAP > OFFS + APAL...`` block."""
    wrap = pals.find('WRAP')
    if wrap is None:
        return None
    offs = wrap.find('OFFS')
    if offs is None or len(offs.body) < 4:
        return None
    start = offs.body_offset + int.from_bytes(offs.body[:4], 'little')
    palette = offs.data[start : start + PALETTE_SIZE]
    return palette if len(palette) == PALETTE_SIZE else None


def room_info(rmda: Block) -> RoomInfo:
    """Size, transparent colour, palette and object names of a room."""
    rmhd = rmda.find('RMHD')
    if rmhd is None:
        raise ImageError("room has no RMHD")
    try:
        header = RoomHeader.parse(rmhd.body)
    except construct.ConstructError as e:
        raise ImageError(f"malformed RMHD: {e}") from None
    trns = rmda.find('TRNS')
    transparent = trns.body[0] if trns is not None and trns.body else DEFAULT_TRANSPARENT
    pals = rmda.find('PALS')
    palette = first_palette(pals) if pals is not None else None
    if palette is None:
        # Fall back to a grey ramp so that the picture is at least visible.
        palette = bytes(v for i in range(256) for v in (i, i, i))
    names: dict[int, str] = {}
    for obcd in rmda.find_all('OBCD'):
        cdhd, obna = obcd.find('CDHD'), obcd.find('OBNA')
        if cdhd is None or obna is None or len(cdhd.body) < 2:
            continue
        name = obna.body.split(b'\0', 1)[0].decode('latin-1')
        if name:
            names[int.from_bytes(cdhd.body[:2], 'little')] = name
    return RoomInfo(header.width, header.height, transparent, palette, names)


def _bmap_background(bmap: Block, width: int, height: int) -> bytearray:
    body = bmap.body
    if not body:
        raise ImageError("empty BMAP")
    code = body[0]
    if code == codecs.SOLID_FILL:
        return bytearray([body[1] if len(body) > 1 else 0]) * (width * height)
    # ScummVM draws only 4-8-bit literals (134-138, 144-148), but Freddi Fish 1
    # has an unused 8 x 8 room in 143, which decodes the same way.
    if 131 <= code <= 138 or 141 <= code <= 148:
        return codecs.decode_nmajmin(bmap.data, bmap.body_offset + 1, width * height, code % 10)
    raise ImageError(f"unknown BMAP background codec {code}")


def background(rmim: Block, room: RoomInfo) -> Image.Image:
    """The background of a room, from its RMIM block."""
    im00 = rmim.find('IM00')
    if im00 is None:
        raise ImageError("RMIM has no IM00")
    try:
        bmap = im00.find('BMAP')
        if bmap is not None:
            pixels = _bmap_background(bmap, room.width, room.height)
        else:
            smap = im00.find('SMAP')
            if smap is None:
                raise ImageError("IM00 has neither BMAP nor SMAP")
            # Backgrounds are opaque: the transparent colour only matters for objects.
            pixels, _mask = codecs.decode_smap(smap.raw, room.width, room.height, -1)
    except codecs.CodecError as e:
        raise ImageError(str(e)) from None
    return _image(pixels, None, room.width, room.height, room.palette)


def _bmap_object(bmap: Block, width: int, height: int) -> tuple[bytearray, bytearray | None]:
    body = bmap.body
    if not body:
        raise ImageError("empty BMAP")
    code = body[0]
    if code == codecs.SOLID_FILL:
        return bytearray([body[1] if len(body) > 1 else 0]) * (width * height), None
    if code in (codecs.TRLE_8BIT, codecs.RLE_8BIT):
        return codecs.decode_trle(bmap.data, bmap.body_offset + 1, width, height)
    raise ImageError(f"unknown BMAP object codec {code}")


@dataclass
class ObjectImages:
    """An object's images (an OBIM block): one ``IMxx`` block per state, ``IM01`` being state 1."""

    number: int
    width: int
    height: int
    states: list[tuple[int, Block]]


def object_states(obim: Block) -> ObjectImages:
    """The object number, size and drawable states of an OBIM block, without decoding them."""
    imhd = obim.find('IMHD')
    if imhd is None:
        raise ImageError("OBIM has no IMHD")
    try:
        header = ImageHeader.parse(imhd.body)
    except construct.ConstructError as e:
        raise ImageError(f"malformed IMHD: {e}") from None
    states = []
    if header.width and header.height:
        for child in obim.try_children() or ():
            tag = child.tag
            if not tag.startswith('IM') or tag == 'IMHD':
                continue
            try:
                state = int(tag[2:], 16)
            except ValueError:
                continue
            if child.find('BMAP') is not None or child.find('SMAP') is not None:
                states.append((state, child))
    return ObjectImages(header.object, header.width, header.height, states)


def object_image(state: Block, width: int, height: int, room: RoomInfo) -> Image.Image:
    """One state of an object (an ``IMxx`` block holding a BMAP or SMAP)."""
    try:
        bmap = state.find('BMAP')
        if bmap is not None:
            pixels, mask = _bmap_object(bmap, width, height)
        else:
            smap = state.find('SMAP')
            if smap is None:
                raise ImageError(f"{state.tag} has neither BMAP nor SMAP")
            pixels, mask = codecs.decode_smap(smap.raw, width, height, room.transparent)
    except codecs.CodecError as e:
        raise ImageError(str(e)) from None
    return _image(pixels, mask, width, height, room.palette)


def _rgb555(data: bytes, width: int, height: int) -> Image.Image:
    count = width * height
    if len(data) < 2 * count:
        raise ImageError("16-bit WIZ data is truncated")
    out = bytearray(3 * count)
    for i in range(count):
        v = data[2 * i] | (data[2 * i + 1] << 8)
        r, g, b = (v >> 10) & 31, (v >> 5) & 31, v & 31
        out[3 * i : 3 * i + 3] = bytes(((r << 3) | (r >> 2), (g << 3) | (g >> 2), (b << 3) | (b >> 2)))
    return Image.frombytes('RGB', (width, height), bytes(out))


def is_picture(awiz: Block) -> bool:
    """Whether an AWIZ holds a picture: some hold only a colour-mixing table (XMAP)."""
    return awiz.find('WIZH') is not None or awiz.find('XMAP') is None


def wiz_image(awiz: Block, palette: bytes) -> Image.Image:
    """A WIZ image (an AWIZ block). *palette* is used when the image has no RGBS of its own."""
    wizh, wizd = awiz.find('WIZH'), awiz.find('WIZD')
    if wizh is None or wizd is None:
        raise ImageError("AWIZ lacks WIZH or WIZD")
    try:
        header = WizHeader.parse(wizh.body)
    except construct.ConstructError as e:
        raise ImageError(f"malformed WIZH: {e}") from None
    rgbs = awiz.find('RGBS')
    if rgbs is not None and len(rgbs.body) >= PALETTE_SIZE:
        palette = rgbs.body
    width, height = header.width, header.height
    if not (0 < width <= 8192 and 0 < height <= 8192):
        raise ImageError(f"implausible WIZ size {width}x{height}")
    try:
        if header.codec == WIZ_TRLE:
            pixels, mask = codecs.decode_trle(wizd.data, wizd.body_offset, width, height)
        elif header.codec == WIZ_RAW:
            pixels, mask = codecs.decode_raw(wizd.data, wizd.body_offset, width * height), None
        elif header.codec == WIZ_RAW_16BPP:
            return _rgb555(wizd.body, width, height)
        else:
            raise ImageError(f"unsupported WIZ codec {header.codec}")
    except codecs.CodecError as e:
        raise ImageError(str(e)) from None
    return _image(pixels, mask, width, height, palette)


def multi_states(mult: Block, palette: bytes) -> tuple[list[Block], bytes]:
    """The AWIZ blocks of a MULT (its states, numbered from 0) and the palette they default to."""
    defa = mult.find('DEFA')
    if defa is not None:
        rgbs = defa.find('RGBS')
        if rgbs is not None and len(rgbs.body) >= PALETTE_SIZE:
            palette = rgbs.body
    wrap = mult.find('WRAP')
    if wrap is None:
        raise ImageError("MULT has no WRAP")
    return wrap.find_all('AWIZ'), palette


# Costume cel codecs (AKOS_*_CODEC in ScummVM's akos.h).
AKOS_BYLE_RLE = 1
AKOS_MAJMIN = 16
AKOS_TRLE = 32


@dataclass
class Costume:
    """The cels of a costume (an AKOS block) and what drawing them needs."""

    codec: int
    slots: bytes
    rgbs: bytes | None
    cels: list[tuple[int, int, int, int]]
    """Per cel: its number, width, height and the absolute position of its pixel data."""


def costume_cels(akos: Block) -> Costume:
    """The drawable cels of an AKOS block, without decoding them."""
    akhd, akof = akos.find('AKHD'), akos.find('AKOF')
    if akhd is None:
        raise ImageError("AKOS has no AKHD")
    try:
        header = AkosHeader.parse(akhd.body)
    except construct.ConstructError as e:
        raise ImageError(f"malformed AKHD: {e}") from None
    akpl, rgbs = akos.find('AKPL'), akos.find('RGBS')
    costume = Costume(header.codec, akpl.body if akpl is not None else b'', rgbs.body if rgbs is not None else None, [])
    if akof is None or not akof.body:
        return costume
    akci, akcd = akos.find('AKCI'), akos.find('AKCD')
    if akci is None or akcd is None:
        raise ImageError("AKOS has cels but no AKCI or AKCD")
    entry = AkosOffset.sizeof()
    try:
        for cel in range(len(akof.body) // entry):
            offsets = AkosOffset.parse(akof.body[cel * entry :])
            info = CelInfo.parse(akci.body[offsets.akci :])
            if info.width and info.height:
                costume.cels.append((cel, info.width, info.height, akcd.body_offset + offsets.akcd))
    except construct.ConstructError as e:
        raise ImageError(f"malformed cel table: {e}") from None
    return costume


def costume_name(akos: Block) -> str | None:
    """The name of a costume's first animation sequence (``SQDB > WRAP > SEQI > NAME``), if it has one.

    Freddi Fish 2 and 3 name their sequences ("freddi swims in"); earlier and
    later games do not.
    """
    sqdb = akos.find('SQDB')
    wrap = sqdb.find('WRAP') if sqdb is not None else None
    for seqi in wrap.find_all('SEQI') if wrap is not None else ():
        name = seqi.find('NAME')
        if name is not None:
            text = name.body.split(b'\0', 1)[0].decode('latin-1').strip()
            if text:
                return text
    return None


def _full_palette(rgbs: bytes | None, room_palette: bytes) -> bytes:
    return rgbs if rgbs is not None and len(rgbs) >= PALETTE_SIZE else room_palette


def cel_image(akos: Block, costume: Costume, cel: tuple[int, int, int, int], room_palette: bytes) -> Image.Image:
    """One cel of a costume as an RGBA image.

    *room_palette* stands in for the palette the engine has loaded when the
    costume carries no full palette of its own.
    """
    _number, width, height, pos = cel
    data = akos.data
    try:
        if costume.codec == AKOS_BYLE_RLE:
            slots = costume.slots
            if not slots:
                raise ImageError("BYLE costume has no AKPL")
            pixels = codecs.decode_byle(data, pos, width, height, len(slots))
            mask = codecs.mask_of(pixels, 0)
            rgbs = costume.rgbs
            if rgbs is not None and 3 * len(slots) <= len(rgbs) < PALETTE_SIZE:
                # HE 71: RGBS holds one colour per slot.
                palette = rgbs
            else:
                # Slot c is drawn as palette entry AKPL[c].
                pixels = pixels.translate(slots.ljust(256, b'\0')[:256])
                palette = _full_palette(rgbs, room_palette)
        elif costume.codec == AKOS_TRLE:
            pixels, mask = codecs.decode_trle(data, pos, width, height)
            palette = _full_palette(costume.rgbs, room_palette)
        elif costume.codec == AKOS_MAJMIN:
            pixels = codecs.decode_majmin(data, pos + 1, width * height, data[pos] if pos < len(data) else 8)
            mask = codecs.mask_of(pixels, costume.slots[0]) if costume.slots else None
            palette = _full_palette(costume.rgbs, room_palette)
        else:
            raise ImageError(f"unsupported costume codec {costume.codec}")
    except codecs.CodecError as e:
        raise ImageError(str(e)) from None
    return _image(pixels, mask, width, height, palette).convert('RGBA')
