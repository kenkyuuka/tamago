"""Read the files of a Humongous SCUMM game and extract their resources.

Each file is read on its own: the index (``.he0``), a room data file
(``.he1`` or ``.(A)``), speech (``.he2``) or music (``.he4``). A room data file
uses the index beside it, when there is one, to name resources by number.

Extraction converts sounds to WAV and images to PNG, writing every other
block as it is stored (without the XOR obfuscation). Costumes are written as
stored too, with each of their cels as a PNG in a directory beside them. Without conversion,
every block is written as stored. A sound or image that cannot be converted
is written as stored too, under its raw name, with a warning.
"""

from __future__ import annotations

import io
import logging
import os
import pathlib
import re
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial

import construct

from tamago.formats.member_paths import member_path, plan_extraction
from tamago.formats.scumm import audio, images
from tamago.formats.scumm.blocks import Block, BlockError, deobfuscate, detect_key, read_header, top_level
from tamago.formats.scumm.index import INDEX_TAGS, Index, load_index_for
from tamago.formats.scumm.structs import OldSongEntry, SongEntry

logger = logging.getLogger(__name__)

KIND_INDEX = 'index'
KIND_ROOMS = 'rooms'
KIND_SPEECH = 'speech'
KIND_MUSIC = 'music'

_FIRST_TAG_KINDS = {'LECF': KIND_ROOMS, 'TLKB': KIND_SPEECH, 'SONG': KIND_MUSIC}

# Room children with fixed names inside the room's directory.
_ROOM_PARTS = {'RMIM': 'background', 'RMDA': 'room'}
_WIZ_TAGS = frozenset({'AWIZ', 'MULT'})
_UNSAFE_CHARS = re.compile(r'[^A-Za-z0-9_.-]+')
_GREY = bytes(v for i in range(256) for v in (i, i, i))


def file_kind(header: bytes) -> str | None:
    """What a Humongous SCUMM file holds, from its first 8 bytes, or ``None`` if it is not one."""
    key = detect_key(header)
    if key is None or len(header) < 8:
        return None
    try:
        tag, _size = read_header(deobfuscate(header[:8], key), 0)
    except BlockError:
        return None
    if tag in _FIRST_TAG_KINDS:
        return _FIRST_TAG_KINDS[tag]
    if tag in INDEX_TAGS:
        return KIND_INDEX
    return None


def is_he_file(path: str | os.PathLike) -> bool:
    """Whether *path* is a Humongous SCUMM index, room data, speech or music file."""
    try:
        with open(path, 'rb') as f:
            header = f.read(8)
    except OSError:
        return False
    return file_kind(header) is not None


@dataclass
class Member:
    """One file to extract.

    ``produce`` makes its contents. For a converted member, ``fallback`` is the
    raw block to write instead if conversion fails (``produce`` raising
    :class:`ValueError`). An ``optional`` member (a costume cel, whose costume
    is written as stored anyway) is skipped instead.
    """

    file_name: str
    produce: Callable[[], bytes]
    fallback: Member | None = None
    optional: bool = False


def _png(image) -> bytes:
    buf = io.BytesIO()
    image.save(buf, format='PNG')
    return buf.getvalue()


def _background_png(block: Block, info: images.RoomInfo) -> bytes:
    return _png(images.background(block, info))


def _object_png(block: Block, obj: images.ObjectImages, info: images.RoomInfo) -> bytes:
    return _png(images.object_image(block, obj.width, obj.height, info))


def _wiz_png(block: Block, palette: bytes) -> bytes:
    return _png(images.wiz_image(block, palette))


def _cel_png(akos: Block, costume: images.Costume, cel: tuple[int, int, int, int], palette: bytes) -> bytes:
    return _png(images.cel_image(akos, costume, cel, palette))


def _safe(name: str) -> str:
    return _UNSAFE_CHARS.sub('_', name).strip('_')


def _ext(block: Block) -> str:
    return block.tag.lower().strip()


def _raw(name: str, block: Block) -> Member:
    return Member(name, lambda: block.raw)


class HEFile:
    """A Humongous SCUMM resource file, deobfuscated in memory.

    *index* overrides the ``.he0`` that a room data file otherwise looks for
    beside itself; ``use_index=False`` names resources by position instead.
    """

    def __init__(self, path: str | os.PathLike, *, index: Index | None = None, use_index: bool = True):
        self.path = pathlib.Path(path)
        raw = self.path.read_bytes()
        kind = file_kind(raw[:8])
        if kind is None:
            raise ValueError(f"{self.path} is not a Humongous SCUMM resource file")
        self.kind = kind
        self.key = detect_key(raw) or 0
        self.data = deobfuscate(raw, self.key)
        if index is None and use_index and kind == KIND_ROOMS:
            index = load_index_for(self.path)
        self.index = index

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    # -- members -----------------------------------------------------------

    def members(self, *, convert: bool = True) -> list[Member]:
        """The files that :meth:`extract_all` writes, in file order."""
        try:
            if self.kind == KIND_ROOMS:
                return self._room_members(convert)
            if self.kind == KIND_SPEECH:
                return self._speech_members(convert)
            if self.kind == KIND_MUSIC:
                return self._music_members(convert)
            return self._index_members()
        except BlockError as e:
            raise ValueError(f"{self.path}: {e}") from None

    def namelist(self, *, convert: bool = True) -> list[str]:
        return [m.file_name for m in self.members(convert=convert)]

    def produce(self, member: Member) -> tuple[str, bytes] | None:
        """The name and contents to write for *member*.

        If conversion fails, that is its fallback's name and contents, or
        ``None`` for an optional member.
        """
        try:
            return member.file_name, member.produce()
        except ValueError as e:
            if member.optional:
                logger.warning('%s: %s skipped: %s', self.path.name, member.file_name, e)
                return None
            if member.fallback is None:
                raise
            logger.warning('%s: %s not converted (%s); writing it as stored', self.path.name, member.file_name, e)
            return member.fallback.file_name, member.fallback.produce()

    def read(self, name: str, *, convert: bool = True) -> bytes:
        """The contents of the member called *name*."""
        for member in self.members(convert=convert):
            if member.file_name == name:
                produced = self.produce(member)
                if produced is None:
                    raise ValueError(f"{name} cannot be converted")
                return produced[1]
        raise KeyError(name)

    def extract_all(self, out_dir: str | os.PathLike, *, glob: str | None = None, convert: bool = True) -> int:
        """Write every member (or those matching *glob*) under *out_dir*; returns how many were written."""
        written = 0
        for member, target in plan_extraction(self.members(convert=convert), out_dir, glob):
            produced = self.produce(member)
            if produced is None:
                continue
            name, data = produced
            path = target if name == member.file_name else member_path(out_dir, name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'xb') as f:
                f.write(data)
            written += 1
        return written

    # -- index -------------------------------------------------------------

    def _index_members(self) -> list[Member]:
        members = []
        seen: dict[str, int] = {}
        for block in top_level(self.data):
            n = seen.get(block.tag, 0)
            seen[block.tag] = n + 1
            members.append(_raw(f'{_ext(block)}{f"-{n}" if n else ""}.bin', block))
        return members

    # -- sounds --------------------------------------------------------------

    @staticmethod
    def _sound_member(stem: str, block: Block, convert: bool) -> Member:
        raw = _raw(f'{stem}.{_ext(block)}', block)
        if not convert:
            return raw
        return Member(f'{stem}.wav', partial(audio.sound_to_wav, block), raw)

    def _speech_members(self, convert: bool) -> list[Member]:
        tlkb = top_level(self.data)[0]
        # Scripts play a line by its offset in the file: the only name it has.
        return [self._sound_member(f'talk-{block.offset:09d}', block, convert) for block in tlkb.children()]

    def _song_numbers(self, song: Block) -> dict[int, int]:
        """Song number of each song block, by absolute offset."""
        children = song.children()
        if not children or children[0].tag != 'SGHD':
            return {}
        sghd = children[0]
        try:
            sgens = [c for c in children if c.tag == 'SGEN']
            if sgens:
                entries = [SongEntry.parse(c.body) for c in sgens]
            else:
                count = int.from_bytes(sghd.body[:4], 'little')
                size = OldSongEntry.sizeof()
                entries = [OldSongEntry.parse(sghd.body[4 + i * size :]) for i in range(count)]
        except construct.ConstructError as e:
            logger.warning('%s: malformed song table: %s', self.path.name, e)
            return {}
        return {entry.offset: entry.song for entry in entries}

    def _music_members(self, convert: bool) -> list[Member]:
        song = top_level(self.data)[0]
        numbers = self._song_numbers(song)
        members = []
        position = 0
        for block in song.children():
            if block.tag in ('SGHD', 'SGEN'):
                continue
            number = numbers.get(block.offset)
            stem = f'song-{number}' if number is not None else f'{_ext(block)}-{position:03d}'
            position += 1
            if block.tag in audio.SOUND_TAGS:
                members.append(self._sound_member(stem, block, convert))
            else:
                members.append(_raw(f'{stem}.{_ext(block)}', block))
        return members

    # -- rooms ---------------------------------------------------------------

    def _room_members(self, convert: bool) -> list[Member]:
        lecf = top_level(self.data)[0]
        members: list[Member] = []
        for position, lflf in enumerate(lecf.find_all('LFLF'), 1):
            room = self.index.room_at(lflf.body_offset) if self.index else None
            members += self._one_room(position if room is None else room, lflf, convert)
        return members

    def _resource_stem(self, room: int, lflf: Block, block: Block, counters: dict[str, int]) -> str:
        if block.tag in _ROOM_PARTS:
            return _ROOM_PARTS[block.tag]
        if self.index is not None:
            found = self.index.resources.get((room, block.offset - lflf.body_offset))
            if found is not None:
                kind, number = found
                return f'{kind}-{number:04d}'
        tag = _ext(block)
        n = counters.get(tag, 0)
        counters[tag] = n + 1
        return f'{tag}-{n:03d}'

    def _one_room(self, room: int, lflf: Block, convert: bool) -> list[Member]:
        prefix = f'room-{room:03d}/'
        children = lflf.children()
        info = None
        if convert:
            rmda = next((c for c in children if c.tag == 'RMDA'), None)
            if rmda is not None:
                try:
                    info = images.room_info(rmda)
                except images.ImageError as e:
                    logger.warning('%s: room %d: %s; its images are written as stored', self.path.name, room, e)
        members: list[Member] = []
        counters: dict[str, int] = {}
        for block in children:
            stem = prefix + self._resource_stem(room, lflf, block, counters)
            raw = _raw(f'{stem}.{_ext(block)}', block)
            if not convert:
                members.append(raw)
            elif block.tag in audio.SOUND_TAGS:
                members.append(self._sound_member(stem, block, convert))
            elif block.tag == 'RMIM' and info is not None:
                members.append(Member(f'{stem}.png', partial(_background_png, block, info), raw))
            elif block.tag == 'RMDA':
                members.append(raw)
                if info is not None:
                    members += self._object_members(prefix, block, info)
            elif block.tag in _WIZ_TAGS:
                members += self._wiz_members(stem, raw, block, info.palette if info else _GREY)
            elif block.tag == 'AKOS':
                members.append(raw)
                members += self._cel_members(stem, block, info.palette if info else _GREY)
            else:
                members.append(raw)
        return members

    def _object_members(self, prefix: str, rmda: Block, info: images.RoomInfo) -> list[Member]:
        members = []
        for obim in rmda.find_all('OBIM'):
            try:
                obj = images.object_states(obim)
            except images.ImageError as e:
                logger.warning('%s: %sobject image at %#x skipped: %s', self.path.name, prefix, obim.offset, e)
                continue
            name = _safe(info.object_names.get(obj.number, ''))
            stem = f'{prefix}objects/object-{obj.number:04d}' + (f'-{name}' if name else '')
            for state, block in obj.states:
                members.append(
                    Member(
                        f'{stem}-{state:02d}.png',
                        partial(_object_png, block, obj, info),
                        _raw(f'{stem}-{state:02d}.{_ext(block)}', block),
                    )
                )
        return members

    def _cel_members(self, stem: str, akos: Block, palette: bytes) -> list[Member]:
        """One PNG per cel of a costume, in a directory named after it and its first sequence, if named.

        The costume itself is kept as stored.
        """
        try:
            costume = images.costume_cels(akos)
        except images.ImageError as e:
            logger.warning('%s: %s cels skipped: %s', self.path.name, stem, e)
            return []
        name = _safe(images.costume_name(akos) or '')
        folder = f'{stem}-{name}' if name else stem
        return [
            Member(f'{folder}/cel-{cel[0]:03d}.png', partial(_cel_png, akos, costume, cel, palette), optional=True)
            for cel in costume.cels
        ]

    def _wiz_members(self, stem: str, raw: Member, block: Block, palette: bytes) -> list[Member]:
        if block.tag == 'AWIZ':
            if not images.is_picture(block):
                return [raw]
            return [Member(f'{stem}.png', partial(_wiz_png, block, palette), raw)]
        try:
            states, palette = images.multi_states(block, palette)
        except images.ImageError as e:
            logger.warning('%s: %s written as stored: %s', self.path.name, raw.file_name, e)
            return [raw]
        members = []
        for state, awiz in enumerate(states):
            state_raw = _raw(f'{stem}-{state:02d}.awiz', awiz)
            if images.is_picture(awiz):
                members.append(Member(f'{stem}-{state:02d}.png', partial(_wiz_png, awiz, palette), state_raw))
            else:
                members.append(state_raw)
        return members
