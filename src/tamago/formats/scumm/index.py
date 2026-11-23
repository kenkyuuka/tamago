"""The index file (``.he0``) of a Humongous SCUMM game: where every numbered resource lives."""

from __future__ import annotations

import logging
import pathlib
from dataclasses import dataclass, field

import construct

from tamago.formats.scumm.blocks import BlockError, deobfuscate, detect_key, top_level
from tamago.formats.scumm.structs import Directory, RoomOffsets

logger = logging.getLogger(__name__)

# Directory block -> resource kind, used to name the resources.
DIRECTORY_KINDS = {
    'DIRI': 'room-image',
    'DIRR': 'room',
    'DIRS': 'script',
    'DIRN': 'sound',
    'DIRC': 'costume',
    'DIRF': 'charset',
    'DIRM': 'image',
    'DIRT': 'talkie',
}

INDEX_TAGS = frozenset({'RNAM', 'MAXS', 'DLFL', 'DOBJ', 'AARY', 'DISK', 'SVER', 'INIB', *DIRECTORY_KINDS})


@dataclass
class Index:
    """The parts of a ``.he0`` index needed to name resources.

    ``resources`` maps ``(room, offset)``, the offset being relative to the
    room's LFLF body, to ``(kind, number)``.
    """

    room_offsets: list[int] = field(default_factory=list)
    room_names: dict[int, str] = field(default_factory=dict)
    resources: dict[tuple[int, int], tuple[str, int]] = field(default_factory=dict)

    def room_at(self, body_offset: int) -> int | None:
        """The number of the room whose LFLF body starts at *body_offset* in the data file."""
        for room, offset in enumerate(self.room_offsets):
            if room and offset == body_offset:
                return room
        return None


def is_index(data: bytes) -> bool:
    """Whether *data* (at least the first 8 bytes) is the start of an HE index file."""
    key = detect_key(data)
    if key is None:
        return False
    return deobfuscate(data[:4], key).decode('ascii') in INDEX_TAGS


def _room_names(body: bytes) -> dict[int, str]:
    """Parse RNAM in either layout: u8 room + 9 bytes XOR 0xFF (HE < 80), or u16 room + NUL-terminated name."""
    names: dict[int, str] = {}
    if not body or body[0] == 0:
        return names
    # The old layout has fixed 10-byte entries ending in a zero byte.
    if len(body) % 10 == 1 and body[-1] == 0:
        for pos in range(0, len(body) - 1, 10):
            raw = bytes(b ^ 0xFF for b in body[pos + 1 : pos + 10])
            names[body[pos]] = raw.split(b'\0', 1)[0].decode('latin-1')
        return names
    pos = 0
    while pos + 2 <= len(body):
        room = int.from_bytes(body[pos : pos + 2], 'little')
        if room == 0:
            break
        end = body.find(b'\0', pos + 2)
        if end < 0:
            break
        names[room] = body[pos + 2 : end].decode('latin-1')
        pos = end + 1
    return names


def parse_index(data: bytes) -> Index:
    """Parse a (possibly obfuscated) ``.he0`` index file."""
    key = detect_key(data)
    if key is None:
        raise ValueError("not a SCUMM index file")
    data = deobfuscate(data, key)
    index = Index()
    try:
        blocks = top_level(data)
    except BlockError as e:
        raise ValueError(f"malformed index: {e}") from None
    for block in blocks:
        try:
            if block.tag == 'DLFL':
                index.room_offsets = list(RoomOffsets.parse(block.body).offsets)
            elif block.tag == 'RNAM':
                index.room_names = _room_names(block.body)
            elif block.tag in DIRECTORY_KINDS:
                kind = DIRECTORY_KINDS[block.tag]
                directory = Directory.parse(block.body)
                for number, (room, offset) in enumerate(zip(directory.rooms, directory.offsets, strict=True)):
                    if room == 0 or number == 0:
                        continue
                    index.resources.setdefault((room, offset), (kind, number))
        except construct.ConstructError as e:
            raise ValueError(f"malformed {block.tag} in index: {e}") from None
    return index


def index_path_for(path: pathlib.Path) -> pathlib.Path | None:
    """The ``.he0`` beside a game file, matched case-insensitively, or ``None``."""
    path = pathlib.Path(path)
    stem = path.name.rsplit('.', 1)[0].lower()
    try:
        siblings = list(path.parent.iterdir())
    except OSError:
        return None
    for sibling in siblings:
        if sibling.name.lower() == f'{stem}.he0' and sibling != path:
            return sibling
    return None


def load_index_for(path: pathlib.Path) -> Index | None:
    """Parse the index beside *path*, or ``None`` if there is none or it cannot be read."""
    index_path = index_path_for(path)
    if index_path is None:
        return None
    try:
        return parse_index(index_path.read_bytes())
    except (OSError, ValueError) as e:
        logger.warning('cannot read index %s: %s; naming resources by position', index_path, e)
        return None
