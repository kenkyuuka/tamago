"""Reader and writer for Black Cyc resource packs (Black Cyc, Cyc No-nos, CYCLET).

A pack is a pair of files with the same base name: an index and a data file
holding the members back to back.  There are two kinds:

- Image packs: a ``.gtb`` index and ``.gpk`` data, with ``.dwq`` members.  The
  index is a u32 count, then the members' name offsets (into a string area
  that follows) and data offsets.  A member runs up to the next one's offset,
  or to the end of the data file.
- Voice packs: a ``.vtb`` index and ``.vpk`` data, with ``.vaw`` members.  The
  index is 12-byte records, each an 8-byte name and a u32 offset, followed by
  a sentinel record whose offset is the size of the data file.

Names are stored without the member extension, which the engine adds.  Neither
kind has a signature, compression or encryption, so packs are recognised by
an index that describes the data file beside it (:func:`is_blackcyc_pack`).

The games' packer sorts the index by name, compared case-insensitively by
lower-casing, and stores the name strings sorted by their upper-cased form.
:class:`PackFile` writes both orders the same way, so rebuilding an extracted
pack reproduces the original files byte for byte without a manifest.
"""

import fnmatch
import itertools
import os
import pathlib
import shutil
import struct
from typing import BinaryIO

from construct import Array, Bytes, Int32ul, Struct, this

from tamago.formats.member_paths import plan_extraction

IMAGE = 'image'
VOICE = 'voice'

INDEX_EXTENSIONS = {IMAGE: '.gtb', VOICE: '.vtb'}
DATA_EXTENSIONS = {IMAGE: '.gpk', VOICE: '.vpk'}
MEMBER_EXTENSIONS = {IMAGE: '.dwq', VOICE: '.vaw'}
_KIND_BY_EXTENSION = {ext: kind for kind in (IMAGE, VOICE) for ext in (INDEX_EXTENSIONS[kind], DATA_EXTENSIONS[kind])}

GtbHeader = Struct(
    'count' / Int32ul,
    'name_offsets' / Array(this.count, Int32ul),
    'data_offsets' / Array(this.count, Int32ul),
)
VOICE_NAME_SIZE = 8
VtbRecord = Struct('name' / Bytes(VOICE_NAME_SIZE), 'offset' / Int32ul)
VTB_RECORD_SIZE = VtbRecord.sizeof()

MAX_U32 = 0xFFFFFFFF


class PackInfo:
    """Metadata for one member of a Black Cyc pack."""

    __slots__ = ('file_name', 'raw_name', 'offset', 'size')

    def __init__(self, file_name: str, raw_name: bytes, offset: int, size: int):
        self.file_name = file_name
        self.raw_name = raw_name
        self.offset = offset
        self.size = size

    def __repr__(self):
        return f"PackInfo(file_name={self.file_name!r}, offset={self.offset:#x}, size={self.size})"


def pack_kind(path: str | os.PathLike) -> str:
    """Return :data:`IMAGE` or :data:`VOICE` for a pack file *path*, by its extension."""
    suffix = pathlib.Path(path).suffix
    try:
        return _KIND_BY_EXTENSION[suffix.lower()]
    except KeyError:
        raise ValueError(
            f"{os.fspath(path)} does not have a Black Cyc pack extension (.gtb, .gpk, .vtb or .vpk)"
        ) from None


def _sibling(path: pathlib.Path, extension: str, find: bool) -> pathlib.Path:
    """Return *path* with *extension*, written in the same case as *path*'s own.

    If *find* is set and no such file exists, a file whose name differs only in
    case is returned instead, as the games were made on Windows.
    """
    if path.suffix.isupper():
        extension = extension.upper()
    candidate = path.with_suffix(extension)
    if find and not candidate.exists():
        wanted = candidate.name.lower()
        try:
            matches = sorted(p for p in path.parent.iterdir() if p.name.lower() == wanted and p.is_file())
        except OSError:
            matches = []
        if matches:
            return matches[0]
    return candidate


def pack_paths(path: str | os.PathLike, find: bool = True) -> tuple[str, str, str]:
    """Return ``(kind, index_path, data_path)`` for either file of a pack pair."""
    path = pathlib.Path(path)
    kind = pack_kind(path)
    if path.suffix.lower() == INDEX_EXTENSIONS[kind]:
        index, data = path, _sibling(path, DATA_EXTENSIONS[kind], find)
    else:
        index, data = _sibling(path, INDEX_EXTENSIONS[kind], find), path
    return kind, os.fspath(index), os.fspath(data)


def _member(raw_name: bytes, kind: str, offset: int, size: int) -> PackInfo:
    if not raw_name:
        raise ValueError(f"Black Cyc member at {offset:#x} has an empty name")
    try:
        name = raw_name.decode('cp932')
    except UnicodeDecodeError:
        raise ValueError(f"Black Cyc member name is not cp932: {raw_name!r}") from None
    return PackInfo(name + MEMBER_EXTENSIONS[kind], raw_name, offset, size)


def _check_offsets(offsets: list[int], data_size: int):
    """Check that member *offsets* lie inside the data file and run forwards."""
    for offset in offsets:
        if offset > data_size:
            raise ValueError(f"Black Cyc member at {offset:#x} lies outside the data file of {data_size} bytes")
    for start, end in itertools.pairwise(offsets):
        if end < start:
            raise ValueError(f"Black Cyc member offsets are out of order ({start:#x} before {end:#x})")


def _parse_gtb(index: bytes, data_size: int) -> list[PackInfo]:
    if len(index) < 4:
        raise ValueError("Black Cyc image index is too small")
    (count,) = struct.unpack_from('<I', index)
    strings_start = 4 + 8 * count
    if strings_start > len(index):
        raise ValueError(f"Black Cyc image index of {count} members does not fit in {len(index)} bytes")
    header = GtbHeader.parse(index)
    strings = index[strings_start:]

    offsets = list(header.data_offsets)
    _check_offsets(offsets, data_size)
    members = []
    for i, (name_offset, offset) in enumerate(zip(header.name_offsets, offsets, strict=True)):
        end = strings.find(b'\0', name_offset) if name_offset < len(strings) else -1
        if end < 0:
            raise ValueError(f"Black Cyc image member {i} has a name outside the index")
        next_offset = offsets[i + 1] if i + 1 < count else data_size
        members.append(_member(strings[name_offset:end], IMAGE, offset, next_offset - offset))
    return members


def _parse_vtb(index: bytes, data_size: int) -> list[PackInfo]:
    if not index or len(index) % VTB_RECORD_SIZE:
        raise ValueError(f"Black Cyc voice index of {len(index)} bytes is not a whole number of records")
    records = [VtbRecord.parse(index[i : i + VTB_RECORD_SIZE]) for i in range(0, len(index), VTB_RECORD_SIZE)]
    offsets = [r.offset for r in records]
    _check_offsets(offsets, data_size)
    members = []
    for record, next_offset in zip(records, offsets[1:], strict=False):
        name = record.name.split(b'\0', 1)[0]
        members.append(_member(name, VOICE, record.offset, next_offset - record.offset))
    return members


def _read_index(kind: str, index_path: str, data_size: int) -> list[PackInfo]:
    with open(index_path, 'rb') as f:
        index = f.read()
    return (_parse_gtb if kind == IMAGE else _parse_vtb)(index, data_size)


def is_blackcyc_pack(path: str | os.PathLike) -> bool:
    """Return True if *path* is either file of a Black Cyc pack pair."""
    try:
        kind, index_path, data_path = pack_paths(path)
        members = _read_index(kind, index_path, os.path.getsize(data_path))
    except (OSError, ValueError):
        return False
    # Names are file names: control characters mean this is something else.
    return bool(members) and not any(c < ' ' or c == '\x7f' for m in members for c in m.file_name)


def _index_order(raw_name: bytes):
    return (raw_name.lower(), raw_name)


def _string_order(raw_name: bytes):
    return (raw_name.upper(), raw_name)


class PackFile:
    """Read or create a Black Cyc pack.

    *file* may name either file of the pair; the other is found beside it, and
    its extension says whether the pack holds images or voices.  Use
    ``mode='r'`` (default) to read an existing pack, or ``mode='w'`` to create
    one: both files are written when the pack is closed.
    """

    def __init__(self, file: str | os.PathLike, mode: str = 'r'):
        self.fp: BinaryIO | None = None
        self._open = False
        if mode not in ('r', 'w'):
            raise ValueError(f"Invalid mode: {mode!r} (expected 'r' or 'w')")
        self.filename = os.fspath(file)
        self.mode = mode
        self.kind, self.index_path, self.data_path = pack_paths(file, find=mode == 'r')
        self.files: list[PackInfo] = []
        self._pending: dict[bytes, str] = {}

        if mode == 'r':
            if not os.path.isfile(self.index_path):
                raise ValueError(f"Black Cyc index {self.index_path} is missing for {self.data_path}")
            if not os.path.isfile(self.data_path):
                raise ValueError(f"Black Cyc data file {self.data_path} is missing for {self.index_path}")
            fp = open(self.data_path, 'rb')
            try:
                self.files = _read_index(self.kind, self.index_path, os.fstat(fp.fileno()).st_size)
            except Exception:
                fp.close()
                raise
            self.fp = fp
        self._open = True

    @property
    def member_extension(self) -> str:
        return MEMBER_EXTENSIONS[self.kind]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None and self.mode == 'w':
            # Don't write a partial pack after a failure.
            self._pending.clear()
            self._open = False
            return
        self.close()

    def __del__(self):
        if getattr(self, 'mode', None) == 'r':
            self.close()

    def close(self):
        """Close the pack, writing it out if in write mode."""
        if not self._open:
            return
        self._open = False
        if self.mode == 'w':
            self._finalize()
        elif self.fp is not None:
            fp, self.fp = self.fp, None
            fp.close()

    # -- reading ---------------------------------------------------------------

    def _check_readable(self):
        if not self._open:
            raise ValueError("I/O operation on closed Black Cyc pack")
        if self.mode != 'r':
            raise ValueError("reading requires mode='r'")

    def namelist(self) -> list[str]:
        return [info.file_name for info in self.files]

    def getinfo(self, name: str) -> PackInfo:
        for info in self.files:
            if info.file_name == name:
                return info
        raise KeyError(f"No member named {name!r}")

    def read(self, member: 'PackInfo | str') -> bytes:
        """Return the contents of *member* (a :class:`PackInfo` or a name)."""
        self._check_readable()
        assert self.fp is not None
        info = member if isinstance(member, PackInfo) else self.getinfo(member)
        self.fp.seek(info.offset)
        return self.fp.read(info.size)

    def extract(self, member: 'PackInfo | str', path: str | os.PathLike):
        """Write the contents of *member* to a new file at *path*."""
        data = self.read(member)
        with open(path, 'xb') as f:
            f.write(data)

    def extract_all(self, path: str | os.PathLike, glob: str | None = None):
        """Extract members to directory *path*, or only those whose names match *glob*.

        Raises ValueError, before writing anything, if a selected member's name
        would place it outside *path*.
        """
        self._check_readable()
        plan = plan_extraction(self.files, path, glob)
        os.makedirs(path, exist_ok=True)
        for info, filepath in plan:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            self.extract(info, filepath)

    # -- creation --------------------------------------------------------------

    def _check_writable(self):
        if not self._open:
            raise ValueError("I/O operation on closed Black Cyc pack")
        if self.mode != 'w':
            raise ValueError("writing requires mode='w'")

    def write(self, filepath: str | os.PathLike, arcname: str | None = None):
        """Add the file at *filepath* as a member named *arcname* (default: the file's base name).

        The name must end in the pack's member extension (``.dwq`` or ``.vaw``,
        in any case), which is not stored.
        """
        self._check_writable()
        filepath = os.fspath(filepath)
        name = arcname if arcname is not None else os.path.basename(filepath)
        extension = self.member_extension
        if not name.lower().endswith(extension):
            raise ValueError(f"Black Cyc {self.kind} packs hold only {extension} files, not {name!r}")
        stem = name[: -len(extension)]
        if not stem:
            raise ValueError(f"Black Cyc member {name!r} would have an empty name")
        try:
            raw_name = stem.encode('cp932')
        except UnicodeEncodeError:
            raise ValueError(f"Black Cyc member name {stem!r} cannot be encoded as cp932") from None
        if b'\0' in raw_name:
            raise ValueError(f"Black Cyc member name {stem!r} contains a NUL")
        if self.kind == VOICE and len(raw_name) > VOICE_NAME_SIZE:
            raise ValueError(f"Black Cyc voice name {stem!r} must be at most {VOICE_NAME_SIZE} bytes")
        if raw_name in self._pending:
            raise ValueError(f"Black Cyc pack already has a member named {stem!r} (duplicate of {name!r})")
        self._pending[raw_name] = filepath

    def write_all(self, path: str | os.PathLike, glob: str | None = None):
        """Add the files under directory *path*.

        A file's path relative to *path*, with ``/`` separators, is its member
        name; *glob* matches these names.  Every file must have the pack's
        member extension, except the pack's own two files.
        """
        self._check_writable()
        root = pathlib.Path(path)
        own = {os.path.normcase(os.path.abspath(p)) for p in (self.index_path, self.data_path)}
        for dirpath, dirs, files in os.walk(root):
            dirs.sort()
            for file_name in sorted(files):
                source = os.path.join(dirpath, file_name)
                if os.path.normcase(os.path.abspath(source)) in own:
                    continue
                name = pathlib.Path(source).relative_to(root).as_posix()
                if glob and not fnmatch.fnmatch(name, glob):
                    continue
                self.write(source, arcname=name)

    def _finalize(self):
        """Write the data file, then the index; remove both if either fails."""
        try:
            self._write_files()
        except BaseException:
            for p in (self.data_path, self.index_path):
                try:
                    os.remove(p)
                except OSError:
                    pass
            raise
        finally:
            self._pending.clear()

    def _write_files(self):
        names = sorted(self._pending, key=_index_order)
        offsets = []
        with open(self.data_path, 'wb') as out:
            for raw_name in names:
                offsets.append(out.tell())
                with open(self._pending[raw_name], 'rb') as f:
                    shutil.copyfileobj(f, out)
            end = out.tell()
        if end > MAX_U32:
            raise ValueError("Black Cyc packs cannot exceed 4 GiB")

        if self.kind == IMAGE:
            strings = b''
            name_offsets = {}
            for raw_name in sorted(names, key=_string_order):
                name_offsets[raw_name] = len(strings)
                strings += raw_name + b'\0'
            index = (
                GtbHeader.build(
                    {
                        'count': len(names),
                        'name_offsets': [name_offsets[n] for n in names],
                        'data_offsets': offsets,
                    }
                )
                + strings
            )
        else:
            records = [
                {'name': n.ljust(VOICE_NAME_SIZE, b'\0'), 'offset': o} for n, o in zip(names, offsets, strict=True)
            ]
            records.append({'name': bytes(VOICE_NAME_SIZE), 'offset': end})
            index = b''.join(VtbRecord.build(r) for r in records)
        with open(self.index_path, 'wb') as f:
            f.write(index)
