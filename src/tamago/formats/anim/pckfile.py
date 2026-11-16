"""Reader and writer for the packs of ANIM's engine (``voice/*_wave.pck``, ``cg/psbpack.dat``).

A pack is a u32 member count, a table of (u32 0, u32 offset, u32 size) entries,
the member names as NUL-terminated cp932 strings in entry order, then the member
data back to back to the end of the file.  Every pack seen lists its members
sorted by name, ignoring ASCII case, so the writer sorts them the same way.

Voice packs hold EOG audio (see :mod:`.eog`) and lip-sync ``.csv`` tables;
``psbpack.dat`` holds E-mote ``.psb`` models.  Extraction can unwrap EOG to
plain Ogg, and creation wraps Ogg files back.
"""

import fnmatch
import logging
import os
import pathlib
from typing import BinaryIO

from construct import Int32ul, Struct

from tamago.formats.anim.eog import EOG_HEADER_SIZE, is_eog, unwrap_eog, wrap_ogg
from tamago.formats.member_paths import plan_extraction

logger = logging.getLogger(__name__)

_COUNT = Int32ul
_ENTRY = Struct(
    'reserved' / Int32ul,
    'offset' / Int32ul,
    'size' / Int32ul,
)
COUNT_SIZE = _COUNT.sizeof()
ENTRY_SIZE = _ENTRY.sizeof()
MAX_U32 = 0xFFFFFFFF
_CHUNK_SIZE = 1 << 20

EOG_SUFFIX = '.eog'
OGG_SUFFIX = '.ogg'


def _parse_index(fp: BinaryIO, size: int, strict: bool) -> 'list[tuple[bytes, int, int]] | None':
    """Parse the index of the pack in *fp*, returning (raw name, offset, size) triples.

    Returns None if it is not a pack.  With *strict*, also require what every
    real pack has: reserved fields of 0, and data that starts right after the
    names and runs contiguously to the end of the file.
    """
    fp.seek(0)
    head = fp.read(COUNT_SIZE + ENTRY_SIZE)
    if len(head) < COUNT_SIZE:
        return None
    count = _COUNT.parse(head)
    names_at = COUNT_SIZE + ENTRY_SIZE * count
    if names_at + count > size:
        return None
    if count == 0:
        return [] if size == COUNT_SIZE or not strict else None
    # The first entry bounds the name list before the whole index is read.
    first = _ENTRY.parse(head[COUNT_SIZE:])
    if not names_at + count <= first.offset <= size or (strict and first.reserved != 0):
        return None

    table = fp.read(ENTRY_SIZE * (count - 1))
    if len(table) != ENTRY_SIZE * (count - 1):
        return None
    entries = [first] + [_ENTRY.parse(table[i * ENTRY_SIZE : (i + 1) * ENTRY_SIZE]) for i in range(count - 1)]
    data_at = min(e.offset for e in entries)
    if data_at < names_at + count:
        return None
    if any(e.offset + e.size > size for e in entries):
        return None

    names = fp.read(data_at - names_at).split(b'\0')
    if len(names) <= count or any(not name for name in names[:count]):
        return None
    if strict:
        if any(e.reserved for e in entries) or names[count:] != [b''] or data_at != first.offset:
            return None
        end = data_at
        for e in entries:
            if e.offset != end:
                return None
            end += e.size
        if end != size:
            return None
    return [(names[i], e.offset, e.size) for i, e in enumerate(entries)]


def is_pck(path: str | os.PathLike) -> bool:
    """Return True if the file at *path* has the structure of an ANIM pack.

    Packs have no signature, so this parses the index and checks that it
    describes the file exactly.
    """
    try:
        with open(path, 'rb') as fp:
            size = os.fstat(fp.fileno()).st_size
            entries = _parse_index(fp, size, strict=True)
    except OSError:
        return False
    return bool(entries)


def _sort_key(raw_name: bytes) -> tuple[bytes, bytes]:
    return raw_name.lower(), raw_name


class PCKInfo:
    """Metadata for a single member of an ANIM pack."""

    __slots__ = ('file_name', 'offset', 'size')

    def __init__(self, file_name: str = '', offset: int = 0, size: int = 0):
        self.file_name = file_name
        self.offset = offset
        self.size = size

    def __repr__(self):
        return f"PCKInfo(file_name={self.file_name!r}, size={self.size!r})"


class _Pending:
    """A member staged for writing: its source file, and whether to wrap it as EOG."""

    __slots__ = ('name', 'raw_name', 'source', 'source_size', 'wrap')

    def __init__(self, name: str, raw_name: bytes, source: str, source_size: int, wrap: bool):
        self.name = name
        self.raw_name = raw_name
        self.source = source
        self.source_size = source_size
        self.wrap = wrap


class PCKFile:
    """Read or create ANIM packs.

    In ``mode='w'``, members are read from their source files when the pack is
    closed, and written sorted by name.
    """

    def __init__(self, file: str | os.PathLike, mode: str = 'r'):
        self.fp: BinaryIO | None = None
        if mode not in ('r', 'w'):
            raise ValueError(f"Invalid mode: {mode!r} (expected 'r' or 'w')")
        self.filename = os.fspath(file)
        self.mode = mode
        self.files: list[PCKInfo] = []
        self._by_name: dict[str, PCKInfo] = {}
        self._pending: list[_Pending] = []
        self._folded: set[bytes] = set()

        if mode == 'r':
            self._open_for_read()
        else:
            self.fp = open(self.filename, 'wb')

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __del__(self):
        self.close()

    def close(self):
        """Close the pack, finalizing it if in write mode."""
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
            size = os.fstat(fp.fileno()).st_size
            entries = _parse_index(fp, size, strict=False)
            if entries is None:
                raise ValueError(f"{self.filename} is not an ANIM pack (its index does not fit the file)")
            self.files = [
                PCKInfo(raw.decode('cp932', 'surrogateescape'), offset, length) for raw, offset, length in entries
            ]
            self._by_name = {info.file_name: info for info in self.files}
            self.fp = fp
        except Exception:
            fp.close()
            raise

    def _resolve(self, member: 'PCKInfo | str') -> PCKInfo:
        if self.fp is None:
            raise ValueError("I/O operation on closed ANIM pack")
        if self.mode != 'r':
            raise ValueError("reading requires mode='r'")
        if isinstance(member, PCKInfo):
            return member
        try:
            return self._by_name[member]
        except KeyError:
            raise KeyError(f"No member named {member!r}") from None

    def read(self, member: 'PCKInfo | str') -> bytes:
        """Return the stored contents of *member*, a :class:`PCKInfo` or a file name."""
        info = self._resolve(member)
        assert self.fp is not None
        self.fp.seek(info.offset)
        data = self.fp.read(info.size)
        if len(data) != info.size:
            raise ValueError(f"Unexpected end of pack data in member {info.file_name!r}")
        return data

    @staticmethod
    def ogg_name(name: str) -> str:
        """The name an EOG member *name* is extracted under as Ogg: ``.eog`` becomes ``.ogg``."""
        if name.lower().endswith(EOG_SUFFIX):
            return name[: -len(EOG_SUFFIX)] + OGG_SUFFIX
        return name + OGG_SUFFIX

    def extract(self, member: 'PCKInfo | str', path: str | os.PathLike, convert_eog: bool = False) -> str:
        """Extract *member* to a new file at *path*, returning the path written.

        With *convert_eog*, EOG audio is unwrapped to plain Ogg and written with
        its ``.eog`` suffix changed to ``.ogg`` (or ``.ogg`` appended).
        """
        data = self.read(member)
        path = os.fspath(path)
        if convert_eog and is_eog(data):
            data = unwrap_eog(data)
            directory, base = os.path.split(path)
            path = os.path.join(directory, self.ogg_name(base))
        with open(path, 'xb') as f:
            f.write(data)
        return path

    def extract_all(self, path: str | os.PathLike, glob: str | None = None, convert_eog: bool = False):
        """Extract all members to directory *path*.

        If *glob* is given, only members whose names match the pattern are
        extracted.  *convert_eog* unwraps EOG audio as in :meth:`extract`.
        Raises ValueError, before writing anything, if a selected member's name
        would place it outside *path*.
        """
        for info, filepath in plan_extraction(self.files, path, glob):
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            self.extract(info, filepath, convert_eog=convert_eog)

    # -- creation --------------------------------------------------------------

    def write(self, filepath: str | os.PathLike, arcname: str | None = None, wrap_ogg: bool = False):
        """Add the file at *filepath* to the pack under *arcname* (default: its basename).

        With *wrap_ogg*, a file whose name ends in ``.ogg`` and whose contents are
        an Ogg stream is wrapped as EOG and stored with ``.ogg`` changed to
        ``.eog``.
        """
        if self.fp is None:
            raise ValueError("I/O operation on closed ANIM pack")
        if self.mode != 'w':
            raise ValueError("write() requires mode='w'")

        filepath = os.fspath(filepath)
        name = arcname if arcname is not None else os.path.basename(filepath)
        with open(filepath, 'rb') as source:
            source_size = os.fstat(source.fileno()).st_size
            head = source.read(4)
        wrap = wrap_ogg and name.lower().endswith(OGG_SUFFIX) and head == b'OggS'
        if wrap:
            name = name[: -len(OGG_SUFFIX)] + EOG_SUFFIX
        if not name:
            raise ValueError("ANIM pack member names cannot be empty")
        try:
            raw_name = name.encode('cp932', 'surrogateescape')
        except UnicodeEncodeError:
            raise ValueError(f"ANIM pack member name {name!r} cannot be encoded as cp932") from None
        if b'\0' in raw_name:
            raise ValueError(f"ANIM pack member name {name!r} contains a NUL")
        if raw_name.lower() in self._folded:
            raise ValueError(f"Duplicate ANIM pack member name (ignoring case): {name!r}")
        self._folded.add(raw_name.lower())
        self._pending.append(_Pending(name, raw_name, filepath, source_size, wrap))
        logger.debug('staged %s: size=%#x wrap=%s', name, source_size, wrap)

    def write_all(self, path: str | os.PathLike, glob: str | None = None, prefix: str = '', wrap_ogg: bool = False):
        """Recursively add the files in directory *path* to the pack.

        *glob* matches the names files have on disk.  *wrap_ogg* is as in
        :meth:`write`.
        """
        if self.fp is None:
            raise ValueError("I/O operation on closed ANIM pack")
        output = os.fstat(self.fp.fileno())
        for entry in sorted(pathlib.Path(path).iterdir()):
            if entry.is_dir():
                self.write_all(entry, glob=glob, prefix=f'{prefix}{entry.name}/', wrap_ogg=wrap_ogg)
            elif entry.is_file():
                if os.path.samestat(output, entry.stat()):
                    continue
                arcname = prefix + entry.name
                if glob and not fnmatch.fnmatch(arcname, glob):
                    continue
                self.write(entry, arcname=arcname, wrap_ogg=wrap_ogg)

    def _member_data(self, member: _Pending) -> bytes:
        with open(member.source, 'rb') as f:
            data = f.read()
        if len(data) != member.source_size:
            raise ValueError(f"{member.source} changed size while the pack was being written")
        return wrap_ogg(data) if member.wrap else data

    def _finalize(self):
        assert self.fp is not None
        pending = sorted(self._pending, key=lambda p: _sort_key(p.raw_name))
        if len(pending) > MAX_U32:
            raise ValueError(f"ANIM packs hold at most {MAX_U32} members")
        names = b''.join(p.raw_name + b'\0' for p in pending)
        offset = COUNT_SIZE + ENTRY_SIZE * len(pending) + len(names)
        sizes = [p.source_size + (EOG_HEADER_SIZE if p.wrap else 0) for p in pending]

        index = bytearray(_COUNT.build(len(pending)))
        for size in sizes:
            index += _ENTRY.build({'reserved': 0, 'offset': offset, 'size': size})
            offset += size
            if offset > MAX_U32:
                raise ValueError("ANIM packs cannot exceed 4 GiB")
        self.fp.write(index)
        self.fp.write(names)

        for p, size in zip(pending, sizes, strict=True):
            if p.wrap:
                data = self._member_data(p)
                assert len(data) == size
                self.fp.write(data)
                continue
            with open(p.source, 'rb') as f:
                remaining = size
                while remaining:
                    chunk = f.read(min(remaining, _CHUNK_SIZE))
                    if not chunk:
                        raise ValueError(f"{p.source} changed size while the pack was being written")
                    remaining -= len(chunk)
                    self.fp.write(chunk)
        self.files = [PCKInfo(p.name, 0, size) for p, size in zip(pending, sizes, strict=True)]
