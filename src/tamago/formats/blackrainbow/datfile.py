"""Reader and writer for BlackRainbow ADVDX resource archives (``.dat``/``.pak``).

An archive is a 16-byte header (kind, game ID, slot count, data base), a table
of ``slot_count`` offsets relative to the data base (``0xFFFFFFFF`` marks an
unused slot), and one record per used slot: a 32-byte cp932 name, a u32 size
and the member's bytes.  There is no signature, so archives are recognised by
their structure.

The engine addresses members by slot number, not by name: names may be empty
or garbled, and unused slots are common.  Extraction therefore writes a
manifest (:data:`MANIFEST_NAME`) recording each member's slot and stored name,
and :meth:`DATFile.write_all` puts every member back in its slot.
"""

import fnmatch
import json
import logging
import os
import pathlib
import struct
from typing import BinaryIO

from construct import Bytes, Int32ul, Struct

from tamago.formats.blackrainbow.bmd import BMD_MAGIC, bmd_to_png, is_bmd, png_to_bmd
from tamago.formats.member_paths import member_path, plan_extraction

logger = logging.getLogger(__name__)

KIND_IMAGE = 2
KIND_SOUND = 4
KIND_SCRIPT = 5
KIND_READ = 6
KINDS = {KIND_IMAGE: 'image', KIND_SOUND: 'sound', KIND_SCRIPT: 'script', KIND_READ: 'read'}

MANIFEST_NAME = '_advdx_manifest.json'
MANIFEST_FORMAT = 'advdx'

UNUSED = 0xFFFFFFFF
MAX_U32 = 0xFFFFFFFF
NAME_SIZE = 32

DATHeader = Struct(
    'kind' / Int32ul,
    'game_id' / Int32ul,
    'slot_count' / Int32ul,
    'data_base' / Int32ul,
)
HEADER_SIZE = DATHeader.sizeof()

RecordHeader = Struct(
    'name' / Bytes(NAME_SIZE),
    'size' / Int32ul,
)
RECORD_HEADER_SIZE = RecordHeader.sizeof()

_PNG_MAGIC = b'\x89PNG\r\n\x1a\n'
_OGG_MAGIC = b'OggS'
_KIND_EXTENSIONS = {'.bmd': KIND_IMAGE, '.png': KIND_IMAGE, '.ogg': KIND_SOUND, '.spt': KIND_SCRIPT, '.rdd': KIND_READ}


def _read_layout(fp: BinaryIO, file_size: int):
    """Return (header, slot table) if *fp* holds an ADVDX archive, else None."""
    if file_size < HEADER_SIZE:
        return None
    fp.seek(0)
    header = DATHeader.parse(fp.read(HEADER_SIZE))
    if header.kind not in KINDS or header.slot_count < 1:
        return None
    if header.data_base != HEADER_SIZE + 4 * header.slot_count or header.data_base > file_size:
        return None
    table = struct.unpack(f'<{header.slot_count}I', fp.read(4 * header.slot_count))
    used = [offset for offset in table if offset != UNUSED]
    if not used or any(header.data_base + offset + RECORD_HEADER_SIZE > file_size for offset in used):
        return None
    return header, table


def is_advdx_dat(path: str | os.PathLike) -> bool:
    """Return True if the file at *path* has the structure of an ADVDX archive."""
    try:
        with open(path, 'rb') as fp:
            return _read_layout(fp, os.fstat(fp.fileno()).st_size) is not None
    except OSError:
        return False


def _decode_name(raw: bytes) -> str | None:
    """The member name stored as *raw*, or None if it is empty or not valid cp932."""
    if not raw:
        return None
    try:
        return raw.decode('cp932')
    except UnicodeDecodeError:
        return None


def _usable_file_name(name: str | None) -> bool:
    """Whether a stored name can be used as a file name directly."""
    if not name or '/' in name or '\\' in name or name[-1] in '. ' or name.lower() == MANIFEST_NAME.lower():
        return False
    try:
        member_path('.', name)
    except ValueError:
        return False
    return not any(ord(c) < 0x20 for c in name)


def _encode_name(name: str) -> bytes:
    try:
        raw = name.encode('cp932')
    except UnicodeEncodeError:
        raise ValueError(f"ADVDX member name {name!r} cannot be encoded as cp932") from None
    if b'\0' in raw:
        raise ValueError(f"ADVDX member name {name!r} contains a NUL")
    if len(raw) > NAME_SIZE:
        raise ValueError(f"ADVDX member name {name!r} is longer than {NAME_SIZE} bytes in cp932")
    return raw


class DATInfo:
    """Metadata for one member (used slot) of an ADVDX archive.

    *raw_name* is the stored name; *name* is its text, or None if it is empty
    or not valid cp932.  *file_name* is the name the member is extracted under:
    the stored name when it is a usable, unique file name, otherwise one made
    from the slot number.  *size* comes from the slot table; *stored_size* is
    the record's size field, which differs only where a long name overwrote it.
    """

    __slots__ = ('slot', 'raw_name', 'name', 'file_name', 'offset', 'size', 'stored_size')

    def __init__(self, slot: int, raw_name: bytes, offset: int, size: int, stored_size: int):
        self.slot = slot
        self.raw_name = raw_name
        self.name = _decode_name(raw_name)
        self.file_name = ''
        self.offset = offset
        self.size = size
        self.stored_size = stored_size

    def __repr__(self):
        return f"DATInfo(slot={self.slot!r}, file_name={self.file_name!r}, size={self.size!r})"


class _Pending:
    __slots__ = ('slot', 'raw_name', 'source', 'source_size', 'is_png', 'sniffed_kind')

    def __init__(self, slot, raw_name, source, source_size, is_png, sniffed_kind):
        self.slot = slot
        self.raw_name = raw_name
        self.source = source
        self.source_size = source_size
        self.is_png = is_png
        self.sniffed_kind = sniffed_kind


class DATFile:
    """Read or create ADVDX archives.

    In ``mode='w'``, *kind*, *game_id* and *slots* set the header; any left as
    None are taken from a manifest read by :meth:`write_all`, or else inferred
    (kind from the members, game ID 0, one slot past the highest used).  Members
    are read from their source files when the archive is closed.
    """

    def __init__(
        self,
        file: str | os.PathLike,
        mode: str = 'r',
        kind: int | None = None,
        game_id: int | None = None,
        slots: int | None = None,
    ):
        self.fp: BinaryIO | None = None
        if mode not in ('r', 'w'):
            raise ValueError(f"Invalid mode: {mode!r} (expected 'r' or 'w')")
        if kind is not None and kind not in KINDS:
            raise ValueError(f"Unknown ADVDX archive kind {kind!r} (expected one of {sorted(KINDS)})")
        if game_id is not None and not 0 <= game_id <= MAX_U32:
            raise ValueError(f"ADVDX game ID out of range: {game_id!r}")
        if slots is not None and not 1 <= slots <= (MAX_U32 - HEADER_SIZE) // 4:
            raise ValueError(f"ADVDX slot count out of range: {slots!r}")
        self.filename = os.fspath(file)
        self.mode = mode
        self.kind = kind
        self.game_id = game_id
        self.slot_count = slots
        self.trailer = b''
        self.files: list[DATInfo] = []
        self._by_name: dict[str, DATInfo] = {}
        self._pending: list[_Pending] = []

        if mode == 'r':
            self._open_for_read()
        else:
            self.fp = open(self.filename, 'wb')

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None and self.mode == 'w' and self.fp is not None:
            # Don't finalize a half-staged archive: that would mask the error.
            fp = self.fp
            self.fp = None
            fp.close()
            return
        self.close()

    def __del__(self):
        self.close()

    def close(self):
        """Close the archive, finalizing it if in write mode."""
        if self.fp is None:
            return
        try:
            if self.mode == 'w':
                self._finalize()
        finally:
            fp = self.fp
            self.fp = None
            fp.close()

    # -- reading ---------------------------------------------------------------

    def _open_for_read(self):
        fp = open(self.filename, 'rb')
        try:
            self._read_index(fp, os.fstat(fp.fileno()).st_size)
            self.fp = fp
        except Exception:
            fp.close()
            raise

    def _read_index(self, fp: BinaryIO, file_size: int):
        layout = _read_layout(fp, file_size)
        if layout is None:
            raise ValueError(f"{self.filename} is not an ADVDX archive (its header and slot table do not fit)")
        header, table = layout
        self.kind = header.kind
        self.game_id = header.game_id
        self.slot_count = header.slot_count

        # Records are found through the slot table; each runs to the next one.
        records = sorted((header.data_base + offset, slot) for slot, offset in enumerate(table) if offset != UNUSED)
        infos = []
        for k, (start, slot) in enumerate(records):
            fp.seek(start)
            record = RecordHeader.parse(fp.read(RECORD_HEADER_SIZE))
            body = start + RECORD_HEADER_SIZE
            if k + 1 < len(records):
                size = records[k + 1][0] - body
                if size < 0:
                    raise ValueError(f"{self.filename}: the record in slot {slot} overlaps the next one")
            elif body + record.size <= file_size:
                size = record.size
                fp.seek(body + size)
                self.trailer = fp.read()
            else:
                # The size field was overwritten: the last member runs to the end.
                size = file_size - body
            infos.append(DATInfo(slot, record.name.split(b'\0', 1)[0], body, size, record.size))

        infos.sort(key=lambda info: info.slot)
        self._assign_file_names(fp, infos)
        self.files = infos
        self._by_name = {info.file_name: info for info in infos}

    def _extension(self, fp: BinaryIO, info: DATInfo) -> str:
        fp.seek(info.offset)
        head = fp.read(4) if info.size >= 4 else b''
        if head == BMD_MAGIC:
            return '.bmd'
        if head == _OGG_MAGIC:
            return '.ogg'
        if self.kind == KIND_SCRIPT:
            return '.spt'
        if self.kind == KIND_READ:
            return '.rdd'
        return '.bin'

    def _assign_file_names(self, fp: BinaryIO, infos: list[DATInfo]):
        taken: set[str] = set()
        unnamed = []
        for info in infos:
            name = info.name
            if name is not None and _usable_file_name(name) and name.lower() not in taken:
                info.file_name = name
                taken.add(name.lower())
            else:
                unnamed.append(info)
        assert self.slot_count is not None
        width = max(3, len(str(self.slot_count - 1)))
        for info in unnamed:
            stem, ext = f'{info.slot:0{width}d}', self._extension(fp, info)
            candidate, n = stem + ext, 1
            while candidate.lower() in taken:
                n += 1
                candidate = f'{stem}_{n}{ext}'
            info.file_name = candidate
            taken.add(candidate.lower())

    def _check_readable(self):
        if self.fp is None:
            raise ValueError("I/O operation on closed ADVDX archive")
        if self.mode != 'r':
            raise ValueError("reading requires mode='r'")

    def namelist(self) -> list[str]:
        """The members' extraction names, in slot order."""
        return [info.file_name for info in self.files]

    def getinfo(self, name: str) -> DATInfo:
        """The :class:`DATInfo` of the member extracted as *name*."""
        try:
            return self._by_name[name]
        except KeyError:
            raise KeyError(f"No member named {name!r}") from None

    def read(self, member: 'DATInfo | str') -> bytes:
        """Return the contents of *member*, a :class:`DATInfo` or an extraction name."""
        self._check_readable()
        info = member if isinstance(member, DATInfo) else self.getinfo(member)
        assert self.fp is not None
        self.fp.seek(info.offset)
        data = self.fp.read(info.size)
        if len(data) != info.size:
            raise ValueError(f"Unexpected end of archive data in member {info.file_name!r}")
        return data

    @staticmethod
    def png_name(name: str) -> str:
        """The name a member extracted as *name* gets when converted to PNG."""
        if name.lower().endswith('.bmd'):
            return name[:-4] + '.png'
        return name + '.png'

    def extract(self, member: 'DATInfo | str', path: str | os.PathLike, convert_bmd: bool = False) -> str:
        """Extract *member* to a new file at *path*, returning the path written.

        With *convert_bmd*, a _BMD image is written as PNG, and a ``.bmd``
        suffix of *path* becomes ``.png`` (otherwise ``.png`` is appended).
        """
        data = self.read(member)
        path = os.fspath(path)
        if convert_bmd and is_bmd(data):
            data = bmd_to_png(data)
            directory, base = os.path.split(path)
            path = os.path.join(directory, self.png_name(base))
        with open(path, 'xb') as f:
            f.write(data)
        return path

    def extract_all(self, path: str | os.PathLike, glob: str | None = None, convert_bmd: bool = False):
        """Extract members to directory *path*, with a manifest of their slots and names.

        If *glob* is given, only members whose extraction names match it are
        extracted (and listed in the manifest).  *convert_bmd* writes images as
        PNG, as in :meth:`extract`.  Raises ValueError, before writing anything,
        if a selected member's name would place it outside *path*.
        """
        self._check_readable()
        plan = plan_extraction(self.files, path, glob)
        os.makedirs(path, exist_ok=True)
        claimed = {info.file_name.lower() for info in self.files} | {MANIFEST_NAME.lower()}
        members = []
        for info, planned in plan:
            data = self.read(info)
            filepath = planned
            if convert_bmd and is_bmd(data):
                png = self.png_name(info.file_name)
                if png.lower() in claimed:
                    png = info.file_name + '.png'
                claimed.add(png.lower())
                data = bmd_to_png(data)
                filepath = member_path(path, png)
            with open(filepath, 'xb') as f:
                f.write(data)
            members.append(self._manifest_entry(info, os.path.basename(filepath)))

        manifest: dict = {
            'format': MANIFEST_FORMAT,
            'kind': self.kind,
            'game_id': self.game_id,
            'slots': self.slot_count,
        }
        if self.trailer:
            manifest['trailer'] = self.trailer.hex()
        manifest['members'] = members
        with open(os.path.join(path, MANIFEST_NAME), 'x', encoding='utf-8') as f:
            json.dump(manifest, f, ensure_ascii=False, indent=1)
            f.write('\n')

    @staticmethod
    def _manifest_entry(info: DATInfo, file_name: str) -> dict:
        entry: dict = {'slot': info.slot, 'file': file_name}
        if info.raw_name and info.name is None:
            entry['name_hex'] = info.raw_name.hex()
        elif (info.name or '') != file_name:
            entry['name'] = info.name or ''
        return entry

    # -- creation --------------------------------------------------------------

    def _check_writable(self):
        if self.fp is None:
            raise ValueError("I/O operation on closed ADVDX archive")
        if self.mode != 'w':
            raise ValueError("writing requires mode='w'")

    def write(
        self,
        filepath: str | os.PathLike,
        arcname: str | None = None,
        slot: int | None = None,
        raw_name: bytes | None = None,
    ):
        """Add the file at *filepath* as a member.

        The member is named *arcname* (default: the file's name, with a
        ``.png`` suffix changed to ``.bmd`` for a PNG file), or stored with the
        exact name bytes *raw_name*.  *slot* places it in that slot; otherwise
        it takes the lowest free slot when the archive is closed.  In an image
        archive, PNG files are encoded as _BMD.
        """
        self._check_writable()
        filepath = os.fspath(filepath)
        with open(filepath, 'rb') as source:
            source_size = os.fstat(source.fileno()).st_size
            head = source.read(len(_PNG_MAGIC))
        is_png = head == _PNG_MAGIC

        if raw_name is None:
            name = arcname if arcname is not None else os.path.basename(filepath)
            if arcname is None and is_png and name.lower().endswith('.png'):
                name = name[:-4] + '.bmd'
            raw_name = _encode_name(name)
        elif len(raw_name) > NAME_SIZE or b'\0' in raw_name:
            raise ValueError(f"ADVDX member name {raw_name!r} must be at most {NAME_SIZE} bytes, without NULs")

        if slot is not None:
            if not 0 <= slot < (MAX_U32 - HEADER_SIZE) // 4:
                raise ValueError(f"ADVDX slot out of range: {slot!r}")
            if any(p.slot == slot for p in self._pending):
                raise ValueError(f"Two members were given slot {slot}")

        if is_png or head[:4] == BMD_MAGIC:
            sniffed: int | None = KIND_IMAGE
        elif head[:4] == _OGG_MAGIC:
            sniffed = KIND_SOUND
        else:
            sniffed = _KIND_EXTENSIONS.get(os.path.splitext(raw_name.decode('cp932', 'replace'))[1].lower())
        self._pending.append(_Pending(slot, raw_name, filepath, source_size, is_png, sniffed))
        logger.debug('staged %s: slot=%s size=%#x', filepath, slot, source_size)

    def write_all(self, path: str | os.PathLike, glob: str | None = None):
        """Add the files in directory *path*, following its manifest if it has one.

        Members listed in the manifest go back into their slots under their
        stored names, and the manifest supplies the kind, game ID, slot count
        and trailer unless they were given to the constructor.  Other files
        take free slots in name order.  *glob* matches the names files have on
        disk.  Subdirectories are refused: archives have no folders.
        """
        self._check_writable()
        assert self.fp is not None
        root = pathlib.Path(path)
        output = os.fstat(self.fp.fileno())
        listed: set[str] = set()

        manifest_path = root / MANIFEST_NAME
        if manifest_path.is_file():
            for entry in self._apply_manifest(manifest_path):
                listed.add(entry['file'])
                if glob and not fnmatch.fnmatch(entry['file'], glob):
                    continue
                source = root / entry['file']
                if not source.is_file():
                    raise ValueError(f"The manifest lists {entry['file']!r}, which is missing from {root}")
                self.write(source, slot=entry['slot'], raw_name=entry['raw_name'])

        for child in sorted(root.iterdir()):
            if child.name == MANIFEST_NAME or child.name in listed:
                continue
            if child.is_dir():
                raise ValueError(f"{child} is a directory, but ADVDX archives cannot hold folders")
            if not child.is_file() or os.path.samestat(output, child.stat()):
                continue
            if glob and not fnmatch.fnmatch(child.name, glob):
                continue
            self.write(child)

    def _apply_manifest(self, manifest_path: pathlib.Path) -> list[dict]:
        """Read the manifest, take its archive parameters, and return its members."""
        try:
            with open(manifest_path, encoding='utf-8') as f:
                manifest = json.load(f)
            if manifest.get('format') != MANIFEST_FORMAT:
                raise ValueError(f"not an {MANIFEST_FORMAT} manifest")
            kind, game_id, slots = int(manifest['kind']), int(manifest['game_id']), int(manifest['slots'])
            trailer = bytes.fromhex(manifest.get('trailer', ''))
            members = []
            for m in manifest['members']:
                file_name = m['file']
                if not isinstance(file_name, str) or not _usable_file_name(file_name):
                    raise ValueError(f"bad file name {file_name!r}")
                if 'name_hex' in m:
                    raw = bytes.fromhex(m['name_hex'])
                else:
                    raw = _encode_name(m.get('name', file_name))
                members.append({'slot': int(m['slot']), 'file': file_name, 'raw_name': raw})
        except (OSError, KeyError, TypeError, ValueError) as e:
            raise ValueError(f"Invalid ADVDX manifest {manifest_path}: {e}") from None
        if kind not in KINDS:
            raise ValueError(f"Invalid ADVDX manifest {manifest_path}: unknown kind {kind}")
        if self.kind is None:
            self.kind = kind
        if self.game_id is None:
            self.game_id = game_id
        if self.slot_count is None:
            self.slot_count = slots
        self.trailer = trailer
        return members

    def _infer_kind(self) -> int:
        kinds = {p.sniffed_kind for p in self._pending}
        if len(kinds) == 1 and None not in kinds:
            return kinds.pop()
        raise ValueError(
            "Cannot tell the archive kind from its members; give it explicitly "
            f"({', '.join(f'{k} = {v}' for k, v in sorted(KINDS.items()))})"
        )

    def _assign_slots(self) -> list[_Pending]:
        used = {p.slot for p in self._pending if p.slot is not None}
        free = 0
        for p in self._pending:
            if p.slot is None:
                while free in used:
                    free += 1
                p.slot = free
                used.add(free)
        needed = max(used) + 1
        if self.slot_count is None:
            self.slot_count = needed
        elif needed > self.slot_count:
            raise ValueError(f"The members need {needed} slots, but the archive has {self.slot_count}")
        return sorted(self._pending, key=lambda p: p.slot)

    def _member_data(self, p: _Pending) -> bytes:
        with open(p.source, 'rb') as f:
            data = f.read()
        if len(data) != p.source_size:
            raise ValueError(f"{p.source} changed size while the archive was being written")
        if p.is_png and self.kind == KIND_IMAGE:
            data = png_to_bmd(data)
        return data

    def _finalize(self):
        assert self.fp is not None
        if not self._pending:
            raise ValueError("An ADVDX archive needs at least one member")
        if self.kind is None:
            self.kind = self._infer_kind()
        if self.game_id is None:
            self.game_id = 0
        if self.kind in (KIND_SCRIPT, KIND_READ) and self.game_id == 0:
            logger.warning(
                "%s: a %s archive with game ID 0 will be rejected by the game unless that is its ID",
                self.filename,
                KINDS[self.kind],
            )
        pending = self._assign_slots()
        assert self.slot_count is not None

        data_base = HEADER_SIZE + 4 * self.slot_count
        table = [UNUSED] * self.slot_count
        self.fp.seek(data_base)
        offset = 0
        for p in pending:
            data = self._member_data(p)
            table[p.slot] = offset
            self.fp.write(RecordHeader.build({'name': p.raw_name.ljust(NAME_SIZE, b'\0'), 'size': len(data)}))
            self.fp.write(data)
            offset += RECORD_HEADER_SIZE + len(data)
            if data_base + offset > MAX_U32:
                raise ValueError("ADVDX archives cannot exceed 4 GiB")
        self.fp.write(self.trailer)

        self.fp.seek(0)
        header = {'kind': self.kind, 'game_id': self.game_id, 'slot_count': self.slot_count, 'data_base': data_base}
        self.fp.write(DATHeader.build(header))
        self.fp.write(struct.pack(f'<{self.slot_count}I', *table))
