"""Reader and writer for YU-RIS YPF archives (``*.ypf``).

An archive is a 32-byte header (``YPF\\0``, engine version, entry count, end
of the index), an index of variable-length entries, and member data.  Each
entry holds a hash of the member's name, the name's length (inverted and
passed through a per-game swap table), the name XOR'd with a per-game key,
a file type, a compression flag, sizes, the data offset, and a checksum of the
stored data.  From version 478 on, names are hashed and data checksummed with
MurmurHash2 and offsets are 64-bit; before that, names use CRC-32 and data
Adler-32, with 32-bit offsets.

The index is sorted by name hash.  Because the hash covers the plaintext
name, reading needs neither the key nor the swap table: each entry's length is
the one whose decoded name matches the hash.  Writing needs all three
parameters the target game expects; :func:`archive_params` reads them from an
existing archive.
"""

import fnmatch
import logging
import os
import pathlib
import zlib
from collections.abc import Callable, Iterator
from typing import BinaryIO

from construct import Const, Int8ul, Int32ul, Int64ul, Padding, Struct

from tamago.formats.member_paths import plan_extraction
from tamago.formats.yuris.hashing import murmur2
from tamago.formats.yuris.ycg import is_ycg, png_to_ycg, ycg_to_png

logger = logging.getLogger(__name__)

YPF_MAGIC = b'YPF\0'
WIDE_VERSION = 478
DEFAULT_VERSION = 500
DEFAULT_KEY = 0xFF
MAX_U32 = 0xFFFFFFFF

_HEADER = Struct(
    'magic' / Const(YPF_MAGIC),
    'version' / Int32ul,
    'count' / Int32ul,
    'index_end' / Int32ul,
    Padding(16),
)
HEADER_SIZE = _HEADER.sizeof()
_ENTRY_HEAD = Struct('name_hash' / Int32ul, 'name_length' / Int8ul)
_TAIL_FIELDS = ('file_type' / Int8ul, 'packed' / Int8ul, 'size' / Int32ul, 'stored_size' / Int32ul)
_TAIL_NARROW = Struct(*_TAIL_FIELDS, 'offset' / Int32ul, 'checksum' / Int32ul)
_TAIL_WIDE = Struct(*_TAIL_FIELDS, 'offset' / Int64ul, 'checksum' / Int32ul)
_ENTRY_HEAD_SIZE = _ENTRY_HEAD.sizeof()

# Swap tables for the name length.  'a' is the standard one; 'b' and 'c' drop
# some of its pairs; 'd' is used by version-500 games with name key 0xC9.
_PAIRS_A = (
    (0x03, 0x48), (0x06, 0x35), (0x09, 0x0B), (0x0C, 0x10), (0x0D, 0x13), (0x11, 0x19),
    (0x15, 0x1B), (0x1C, 0x1E), (0x20, 0x23), (0x26, 0x29), (0x2C, 0x2F), (0x2E, 0x32),
)  # fmt: skip
LENGTH_TABLES: dict[str, tuple[tuple[int, int], ...]] = {
    'a': _PAIRS_A,
    'b': _PAIRS_A[2:],
    'c': tuple(p for p in _PAIRS_A if p not in ((0x03, 0x48), (0x06, 0x35), (0x0C, 0x10), (0x11, 0x19), (0x1C, 0x1E))),
    'd': (
        (0x03, 0x0A), (0x06, 0x35), (0x09, 0x0B), (0x0C, 0x10), (0x0D, 0x13), (0x11, 0x18),
        (0x14, 0x2E), (0x15, 0x1B), (0x1C, 0x1E), (0x20, 0x23), (0x26, 0x29), (0x2C, 0x2F),
    ),
}  # fmt: skip
DEFAULT_LENGTH_TABLE = 'a'
_TABLE_D_KEY = 0xC9


def _swap_map(pairs: tuple[tuple[int, int], ...]) -> bytes:
    table = bytearray(range(256))
    for a, b in pairs:
        table[a], table[b] = b, a
    return bytes(table)


_SWAP = {name: _swap_map(pairs) for name, pairs in LENGTH_TABLES.items()}

# File type codes.  Version 0xF7 inserts AVI at 5 and shifts the rest up.
TYPE_SCRIPT = 0
TYPE_YCG = 8
_EXTENSION_TYPES = {
    '.ybn': 0,
    '.bmp': 1,
    '.png': 2,
    '.jpg': 3,
    '.jpeg': 3,
    '.gif': 4,
    '.wav': 5,
    '.ogg': 6,
    '.psd': 7,
    '.psb': 9,
}
_PNG_MAGIC = b'\x89PNG\r\n\x1a\n'


def _is_wide(version: int) -> bool:
    return version >= WIDE_VERSION


def _name_hash(version: int) -> Callable[[bytes], int]:
    return murmur2 if _is_wide(version) else zlib.crc32


def _checksum(version: int) -> Callable[[bytes], int]:
    return murmur2 if _is_wide(version) else zlib.adler32


def file_type_for(version: int, name: str, data: bytes) -> int:
    """The file type code the engine of *version* expects for member *name* with contents *data*."""
    if is_ycg(data):
        return TYPE_YCG
    ext = os.path.splitext(name)[1].lower()
    if version == 0xF7:
        if ext == '.avi':
            return 5
        if ext in ('.wav', '.ogg', '.psd'):
            return _EXTENSION_TYPES[ext] + 1
    if ext not in _EXTENSION_TYPES:
        logger.debug('%s: no file type for %r; using 0', name, ext)
    return _EXTENSION_TYPES.get(ext, TYPE_SCRIPT)


class YPFInfo:
    """Metadata for a single member of a YPF archive."""

    __slots__ = ('file_name', 'file_type', 'packed', 'size', 'stored_size', 'offset', 'checksum', 'name_hash')

    def __init__(
        self,
        file_name: str = '',
        file_type: int = 0,
        packed: bool = False,
        size: int = 0,
        stored_size: int = 0,
        offset: int = 0,
        checksum: int = 0,
        name_hash: int = 0,
    ):
        self.file_name = file_name
        self.file_type = file_type
        self.packed = packed
        self.size = size
        self.stored_size = stored_size
        self.offset = offset
        self.checksum = checksum
        self.name_hash = name_hash

    def __repr__(self):
        return (
            f"YPFInfo(file_name={self.file_name!r}, file_type={self.file_type}, "
            f"packed={self.packed}, size={self.size})"
        )


class _Index:
    """The parsed index: entries plus what was learned about the archive's obfuscation."""

    def __init__(self, version: int):
        self.version = version
        self.entries: list[YPFInfo] = []
        self.key: int | None = None
        self.lengths: dict[int, int] = {}  # stored length byte -> real length

    def length_table(self) -> str | None:
        """The known swap table that fits every length seen, or None.

        When names only have lengths that several tables encode alike, table
        'd' is preferred for name key 0xC9 (every known game with one uses the
        other), and otherwise the first in :data:`LENGTH_TABLES` order.
        """
        fitting = [
            name
            for name, swap in _SWAP.items()
            if all(swap[~stored & 0xFF] == length for stored, length in self.lengths.items())
        ]
        if not fitting:
            return None
        if self.key == _TABLE_D_KEY and 'd' in fitting:
            return 'd'
        return fitting[0]


def _keys_to_try(raw: bytes, known: int | None, exhaustive: bool) -> Iterator[int]:
    if known is not None:
        yield known
        return
    # Names end in a three-letter extension, so the byte before it is a '.'.
    dot_key = raw[-4] ^ 0x2E if len(raw) >= 4 else None
    if dot_key is not None:
        yield dot_key
    if exhaustive:
        yield from (k for k in range(256) if k != dot_key)


def _match_entry(
    index: bytes, pos: int, name_hash: int, stored: int, tail_size: int, state: _Index
) -> tuple[int, int] | None:
    """Find the (length, key) whose decoded name at *pos* hashes to *name_hash*."""
    hash_name = _name_hash(state.version)
    room = len(index) - pos - tail_size
    likely = list(dict.fromkeys(swap[~stored & 0xFF] for swap in _SWAP.values()))
    passes = [
        (likely, False),
        (likely, True),
        (range(1, 256), False),
    ]
    if state.key is not None:
        passes = [(likely, False), (range(1, 256), False)]
    for lengths, exhaustive in passes:
        for length in lengths:
            if not 0 < length <= room:
                continue
            raw = index[pos : pos + length]
            for key in _keys_to_try(raw, state.key, exhaustive):
                if hash_name(bytes(b ^ key for b in raw)) == name_hash:
                    return length, key
    return None


def _parse_index(fp: BinaryIO, file_size: int) -> _Index:
    head = fp.read(HEADER_SIZE)
    if len(head) < HEADER_SIZE or head[:4] != YPF_MAGIC:
        raise ValueError(f"{getattr(fp, 'name', 'file')} is not a YPF archive")
    header = _HEADER.parse(head)
    if not HEADER_SIZE <= header.index_end <= file_size:
        raise ValueError(f"YPF index end {header.index_end:#x} lies outside the file")
    index = fp.read(header.index_end - HEADER_SIZE)

    state = _Index(header.version)
    tail = _TAIL_WIDE if _is_wide(header.version) else _TAIL_NARROW
    tail_size = tail.sizeof()
    pos = 0
    for n in range(header.count):
        if pos + _ENTRY_HEAD_SIZE > len(index):
            raise ValueError(f"YPF index is truncated at entry {n}")
        head = _ENTRY_HEAD.parse(index[pos:])
        pos += _ENTRY_HEAD_SIZE
        match = _match_entry(index, pos, head.name_hash, head.name_length, tail_size, state)
        if match is None:
            raise ValueError(f"YPF index entry {n} is corrupt: no name length matches its hash")
        length, key = match
        state.key = key
        state.lengths[head.name_length] = length
        raw = bytes(b ^ key for b in index[pos : pos + length])
        pos += length
        fields = tail.parse(index[pos:])
        pos += tail_size
        if fields.packed not in (0, 1) or fields.offset + fields.stored_size > file_size:
            raise ValueError(f"YPF index entry {n} is corrupt: its data lies outside the file")
        state.entries.append(
            YPFInfo(
                raw.decode('cp932', 'surrogateescape'),
                fields.file_type,
                bool(fields.packed),
                fields.size,
                fields.stored_size,
                fields.offset,
                fields.checksum,
                head.name_hash,
            )
        )
    return state


def archive_params(path: str | os.PathLike) -> dict:
    """Return the ``version``, name ``key`` and ``length_table`` of the YPF archive at *path*.

    These are the parameters :class:`YPFFile` needs to write an archive the
    same game accepts.  ``length_table`` is None if the names fit no known
    table; when several fit, the first in :data:`LENGTH_TABLES` order wins.
    ``key`` is None for an archive with no members.
    """
    with YPFFile(path) as ypf:
        return {'version': ypf.version, 'key': ypf.key, 'length_table': ypf.length_table}


class _Pending:
    """A member staged for writing."""

    __slots__ = ('name', 'raw_name', 'source')

    def __init__(self, name: str, raw_name: bytes, source: str):
        self.name = name
        self.raw_name = raw_name
        self.source = source


class YPFFile:
    """Read or create YU-RIS YPF archives.

    In ``mode='w'``, *version*, *key* (the name XOR byte) and *length_table*
    (a key of :data:`LENGTH_TABLES`) must match what the game expects.
    *compress* chooses which members are zlib-compressed, each only if that
    makes it smaller: None follows the engine's packer (every member before
    version 478, scripts only from then on), True every member, False none.
    With *encode_ycg*, PNG files named ``*.png`` are converted to YCG.
    Members are read from their source files when the archive is closed.
    """

    def __init__(
        self,
        file: str | os.PathLike,
        mode: str = 'r',
        *,
        version: int = DEFAULT_VERSION,
        key: int = DEFAULT_KEY,
        length_table: str = DEFAULT_LENGTH_TABLE,
        compress: bool | None = None,
        encode_ycg: bool = False,
    ):
        self.fp: BinaryIO | None = None
        if mode not in ('r', 'w'):
            raise ValueError(f"Invalid mode: {mode!r} (expected 'r' or 'w')")
        self.filename = os.fspath(file)
        self.mode = mode
        self.files: list[YPFInfo] = []
        self._by_name: dict[str, YPFInfo] = {}
        self._pending: list[_Pending] = []
        self.version = version
        self.key: int | None = key
        self.length_table: str | None = length_table
        self.compress = compress
        self.encode_ycg = encode_ycg

        if mode == 'r':
            self._open_for_read()
        else:
            if not isinstance(version, int) or not 0 < version <= MAX_U32:
                raise ValueError(f"Invalid YPF version: {version!r}")
            if not isinstance(key, int) or not 0 <= key <= 0xFF:
                raise ValueError(f"YPF name key must be a byte value, got {key!r}")
            if length_table not in LENGTH_TABLES:
                raise ValueError(
                    f"Unknown YPF length table {length_table!r} (expected one of {', '.join(LENGTH_TABLES)})"
                )
            self.fp = open(self.filename, 'wb')

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __del__(self):
        self.close()

    def close(self):
        """Close the archive, finalizing it if in write mode."""
        if getattr(self, 'fp', None) is None:
            return
        try:
            if self.mode == 'w':
                self._finalize()
        finally:
            fp = self.fp
            self.fp = None
            assert fp is not None
            fp.close()

    # -- reading ---------------------------------------------------------------

    def _open_for_read(self):
        fp = open(self.filename, 'rb')
        try:
            index = _parse_index(fp, os.fstat(fp.fileno()).st_size)
            self.version = index.version
            self.key = index.key
            self.length_table = index.length_table()
            self.files = index.entries
            self._by_name = {info.file_name: info for info in self.files}
            self.fp = fp
        except Exception:
            fp.close()
            raise

    def namelist(self) -> list[str]:
        """Return the member names, in index order."""
        return [info.file_name for info in self.files]

    def getinfo(self, name: str) -> YPFInfo:
        """Return the :class:`YPFInfo` for member *name*."""
        try:
            return self._by_name[name]
        except KeyError:
            raise KeyError(f"No member named {name!r}") from None

    def _resolve(self, member: 'YPFInfo | str') -> YPFInfo:
        if self.fp is None:
            raise ValueError("I/O operation on closed YPF archive")
        if self.mode != 'r':
            raise ValueError("reading requires mode='r'")
        return member if isinstance(member, YPFInfo) else self.getinfo(member)

    def read_stored(self, member: 'YPFInfo | str') -> bytes:
        """Return the bytes of *member* as stored (compressed, if it is packed)."""
        info = self._resolve(member)
        assert self.fp is not None
        self.fp.seek(info.offset)
        data = self.fp.read(info.stored_size)
        if len(data) != info.stored_size:
            raise ValueError(f"Unexpected end of YPF data in member {info.file_name!r}")
        return data

    def read(self, member: 'YPFInfo | str') -> bytes:
        """Return the contents of *member*, a :class:`YPFInfo` or a name."""
        info = self._resolve(member)
        data = self.read_stored(info)
        if info.packed:
            try:
                data = zlib.decompress(data)
            except zlib.error as e:
                raise ValueError(f"YPF member {info.file_name!r} is corrupt: {e}") from None
        if len(data) != info.size:
            raise ValueError(f"YPF member {info.file_name!r} is {len(data)} bytes, expected {info.size}")
        return data

    def testzip(self) -> str | None:
        """Check every member's stored data against its checksum; return the first bad name, or None."""
        check = _checksum(self.version)
        for info in self.files:
            if check(self.read_stored(info)) != info.checksum:
                return info.file_name
        return None

    def extract(self, member: 'YPFInfo | str', path: str | os.PathLike, convert_ycg: bool = False) -> str:
        """Extract *member* to a new file at *path*, returning the path written.

        With *convert_ycg*, a YCG image is written as PNG (under the same name,
        which is already ``.png`` in the games that use YCG).
        """
        data = self.read(member)
        if convert_ycg and is_ycg(data):
            data = ycg_to_png(data)
        path = os.fspath(path)
        with open(path, 'xb') as f:
            f.write(data)
        return path

    def extract_all(self, path: str | os.PathLike, glob: str | None = None, convert_ycg: bool = False):
        """Extract all members to directory *path*.

        If *glob* is given, only members whose names (with backslashes) match it
        are extracted.  Raises ValueError, before writing anything, if a
        selected member's name would place it outside *path*.
        """
        plan = plan_extraction(self.files, path, glob)
        os.makedirs(path, exist_ok=True)
        for info, filepath in plan:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            self.extract(info, filepath, convert_ycg=convert_ycg)

    # -- creation --------------------------------------------------------------

    def write(self, filepath: str | os.PathLike, arcname: str | None = None):
        """Add the file at *filepath* under *arcname* (default: its basename).

        Forward slashes in *arcname* become the engine's backslashes.
        """
        if self.fp is None:
            raise ValueError("I/O operation on closed YPF archive")
        if self.mode != 'w':
            raise ValueError("write() requires mode='w'")
        filepath = os.fspath(filepath)
        name = (arcname if arcname is not None else os.path.basename(filepath)).replace('/', '\\')
        try:
            raw_name = name.encode('cp932')
        except UnicodeEncodeError:
            raise ValueError(f"YPF member name {name!r} cannot be encoded as cp932") from None
        if not 0 < len(raw_name) <= 255:
            raise ValueError(f"YPF member names must be 1 to 255 bytes long: {name!r}")
        if name in self._by_name:
            raise ValueError(f"Duplicate YPF member name: {name!r}")
        self._by_name[name] = YPFInfo(name)
        self._pending.append(_Pending(name, raw_name, filepath))

    def write_all(self, path: str | os.PathLike, glob: str | None = None, prefix: str = ''):
        """Recursively add the files in directory *path*.

        *glob* matches each file's path relative to *path*, with ``/`` separators.
        """
        if self.fp is None:
            raise ValueError("I/O operation on closed YPF archive")
        output = os.fstat(self.fp.fileno())
        for entry in sorted(pathlib.Path(path).iterdir()):
            if entry.is_dir():
                self.write_all(entry, glob=glob, prefix=f'{prefix}{entry.name}/')
            elif entry.is_file():
                if os.path.samestat(output, entry.stat()):
                    continue
                arcname = prefix + entry.name
                if glob and not fnmatch.fnmatch(arcname, glob):
                    continue
                self.write(entry, arcname=arcname)

    def _wants_compression(self, name: str) -> bool:
        if self.compress is not None:
            return self.compress
        return not _is_wide(self.version) or name.lower().endswith('.ybn')

    def _member_data(self, p: _Pending) -> bytes:
        with open(p.source, 'rb') as f:
            data = f.read()
        if self.encode_ycg and p.name.lower().endswith('.png') and data.startswith(_PNG_MAGIC):
            data = png_to_ycg(data)
        return data

    def _finalize(self):
        assert self.fp is not None
        version, key = self.version, self.key
        assert key is not None and self.length_table is not None
        wide = _is_wide(version)
        tail = _TAIL_WIDE if wide else _TAIL_NARROW
        swap = _SWAP[self.length_table]
        hash_name, check = _name_hash(version), _checksum(version)

        pending = sorted(self._pending, key=lambda p: p.raw_name)
        if len(pending) > MAX_U32:
            raise ValueError(f"YPF archives hold at most {MAX_U32} members")
        index_end = HEADER_SIZE + sum(_ENTRY_HEAD_SIZE + len(p.raw_name) + tail.sizeof() for p in pending)
        if index_end > MAX_U32:
            raise ValueError("YPF index is too large")

        # Data first (one member in memory at a time), then the index over the gap left for it.
        self.fp.seek(index_end)
        offset = index_end
        infos = []
        for p in pending:
            data = self._member_data(p)
            if len(data) > MAX_U32:
                raise ValueError(f"YPF members are limited to 4 GiB: {p.name!r}")
            stored, packed = data, False
            if self._wants_compression(p.name):
                compressed = zlib.compress(data, 9)
                if len(compressed) < len(data):
                    stored, packed = compressed, True
            if not wide and offset + len(stored) > MAX_U32:
                raise ValueError(f"YPF archives before version {WIDE_VERSION} cannot exceed 4 GiB")
            self.fp.write(stored)
            infos.append(
                (
                    p,
                    YPFInfo(
                        p.name,
                        file_type_for(version, p.name, data),
                        packed,
                        len(data),
                        len(stored),
                        offset,
                        check(stored),
                        hash_name(p.raw_name),
                    ),
                )
            )
            offset += len(stored)

        index = bytearray(_HEADER.build({'version': version, 'count': len(infos), 'index_end': index_end}))
        for p, info in sorted(infos, key=lambda pi: (pi[1].name_hash, pi[0].raw_name)):
            index += _ENTRY_HEAD.build({'name_hash': info.name_hash, 'name_length': ~swap[len(p.raw_name)] & 0xFF})
            index += bytes(b ^ key for b in p.raw_name)
            index += tail.build(
                {
                    'file_type': info.file_type,
                    'packed': int(info.packed),
                    'size': info.size,
                    'stored_size': info.stored_size,
                    'offset': info.offset,
                    'checksum': info.checksum,
                }
            )
        assert len(index) == index_end
        self.fp.seek(0)
        self.fp.write(index)
        self.files = [info for _p, info in infos]
