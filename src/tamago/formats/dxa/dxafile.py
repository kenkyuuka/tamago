"""Reader and writer for DxLib DXA archives, versions 1 to 4.

A DXA archive is a header, member data, then an index of three tables: names,
file records, and directory records.  The whole file, header included, is XORed
with a 12-byte key derived from a password, indexed by absolute file position.
Members may be compressed with DxLib's LZ variant (see :mod:`.lz`).

For versions 1 to 4 the key can be recovered from known plaintext in the header,
so archives open without their password.
"""

import codecs
import fnmatch
import functools
import logging
import os
import pathlib
from collections.abc import Iterator
from typing import BinaryIO

from construct import Const, Int16ul, Int32ul, Int64ul, Struct

from tamago.formats.dxa import lz
from tamago.formats.member_paths import plan_extraction

logger = logging.getLogger(__name__)

DXA_MAGIC = b'DX'
KEY_SIZE = 12
DEFAULT_KEY = bytes.fromhex('55AA2055550655AA55D57C66')
PLAIN_KEY = bytes(KEY_SIZE)
SUPPORTED_VERSIONS = range(1, 5)
WRITE_VERSION = 4
CODEPAGE = 932

FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_ARCHIVE = 0x20
NOT_PACKED = 0xFFFFFFFF
NO_PARENT = 0xFFFFFFFF
MAX_U32 = 0xFFFFFFFF

# Far above any real index, which takes roughly 100 bytes per file.
MAX_INDEX_SIZE = 1 << 28

# FILETIME counts 100 ns ticks from 1601-01-01; the Unix epoch is this many ticks later.
_FILETIME_UNIX_EPOCH = 116444736000000000

_CHUNK_SIZE = 1 << 20

_HEADER_V1 = Struct(
    'magic' / Const(DXA_MAGIC),
    'version' / Int16ul,
    'index_size' / Int32ul,
    'data_start' / Int32ul,
    'index_offset' / Int32ul,
    'file_table' / Int32ul,
    'dir_table' / Int32ul,
)
_HEADER_V4 = Struct(*_HEADER_V1.subcons, 'codepage' / Int32ul)

_FILE_RECORD_V1 = Struct(
    'name_offset' / Int32ul,
    'attributes' / Int32ul,
    'create_time' / Int64ul,
    'access_time' / Int64ul,
    'write_time' / Int64ul,
    'address' / Int32ul,
    'size' / Int32ul,
)
_FILE_RECORD_V2 = Struct(*_FILE_RECORD_V1.subcons, 'packed_size' / Int32ul)

_DIR_RECORD = Struct(
    'own_record' / Int32ul,
    'parent' / Int32ul,
    'count' / Int32ul,
    'first_record' / Int32ul,
)

_NAME_HEADER = Struct('units' / Int16ul, 'parity' / Int16ul)


def _header_struct(version: int) -> Struct:
    return _HEADER_V4 if version >= 4 else _HEADER_V1


def _file_record_struct(version: int) -> Struct:
    return _FILE_RECORD_V2 if version >= 2 else _FILE_RECORD_V1


# -- keys ----------------------------------------------------------------------


def _rotr(b: int, n: int) -> int:
    return ((b >> n) | (b << (8 - n))) & 0xFF


def _rotl(b: int, n: int) -> int:
    return _rotr(b, 8 - n)


def _password_block(password: 'str | bytes') -> bytes:
    raw = password.encode('cp932') if isinstance(password, str) else bytes(password)
    if not raw:
        return b'\xaa' * KEY_SIZE
    return (raw * (KEY_SIZE // len(raw) + 1))[:KEY_SIZE]


def derive_key(password: 'str | bytes') -> bytes:
    """Return the 12-byte XOR key DxLib derives from *password* (``''`` for the default key)."""
    k = bytearray(_password_block(password))
    k[0] ^= 0xFF
    k[1] = _rotr(k[1], 4)
    k[2] ^= 0x8A
    k[3] = ~_rotr(k[3], 4) & 0xFF
    k[4] ^= 0xFF
    k[5] ^= 0xAC
    k[6] ^= 0xFF
    k[7] = ~_rotr(k[7], 3) & 0xFF
    k[8] = _rotl(k[8], 3)
    k[9] ^= 0x7F
    k[10] = _rotr(k[10], 4) ^ 0xD6
    k[11] ^= 0xCC
    return bytes(k)


def password_from_key(key: bytes) -> 'str | None':
    """Return the shortest password that derives *key*, or None if it is not text.

    Only the first 12 bytes of a password affect the key, so a longer password
    comes back truncated, which derives the same key.
    """
    b = bytearray(key)
    b[0] ^= 0xFF
    b[1] = _rotl(b[1], 4)
    b[2] ^= 0x8A
    b[3] = _rotl(~b[3] & 0xFF, 4)
    b[4] ^= 0xFF
    b[5] ^= 0xAC
    b[6] ^= 0xFF
    b[7] = _rotl(~b[7] & 0xFF, 3)
    b[8] = _rotr(b[8], 3)
    b[9] ^= 0x7F
    b[10] = _rotl(b[10] ^ 0xD6, 4)
    b[11] ^= 0xCC
    block = bytes(b)
    if block == b'\xaa' * KEY_SIZE:
        return ''
    for period in range(1, KEY_SIZE + 1):
        if _password_block(block[:period]) == block:
            try:
                text = block[:period].decode('cp932')
            except UnicodeDecodeError:
                continue
            if text.isprintable():
                return text
    return None


@functools.lru_cache(maxsize=256)
def _xor_table(k: int) -> bytes:
    return bytes(i ^ k for i in range(256))


def crypt(data: bytes, pos: int, key: bytes) -> bytes:
    """XOR *data*, which sits at absolute file position *pos*, with *key*.

    The operation is its own inverse.
    """
    if not any(key):
        return bytes(data)
    buf = bytearray(data)
    n = len(key)
    for j, k in enumerate(key):
        if k:
            start = (j - pos) % n
            buf[start::n] = buf[start::n].translate(_xor_table(k))
    return bytes(buf)


def _guess_keys(head: bytes, file_size: int) -> Iterator[bytes]:
    """Yield candidate keys recovered from known plaintext in an encrypted header.

    Assumes the conventional layout: data right after the header and the index
    running to the end of the file.
    """
    if len(head) < _HEADER_V4.sizeof():
        return
    for version in (4, 3, 2, 1):
        header_size = _header_struct(version).sizeof()
        known = bytearray(KEY_SIZE)
        known[0:4] = DXA_MAGIC + version.to_bytes(2, 'little')
        known[8:12] = header_size.to_bytes(4, 'little')
        key = bytearray(a ^ b for a, b in zip(head[:KEY_SIZE], known, strict=True))
        index_offset = int.from_bytes(crypt(head[12:16], 12, bytes(key)), 'little')
        if not header_size <= index_offset < file_size:
            continue
        index_size = file_size - index_offset
        key[4:8] = bytes(a ^ b for a, b in zip(head[4:8], index_size.to_bytes(4, 'little'), strict=True))
        yield bytes(key)


# -- member metadata -----------------------------------------------------------


def _filetime(ns: int) -> int:
    return max(0, ns // 100 + _FILETIME_UNIX_EPOCH)


class DXAInfo:
    """Metadata for a single file in a DXA archive."""

    __slots__ = (
        'file_name',
        'offset',
        'size',
        'packed_size',
        'attributes',
        'create_time',
        'access_time',
        'write_time',
    )

    def __init__(
        self,
        file_name: str = '',
        offset: int = 0,
        size: int = 0,
        packed_size: 'int | None' = None,
        attributes: int = FILE_ATTRIBUTE_ARCHIVE,
        create_time: int = 0,
        access_time: int = 0,
        write_time: int = 0,
    ):
        self.file_name = file_name
        self.offset = offset
        self.size = size
        self.packed_size = packed_size
        self.attributes = attributes
        self.create_time = create_time
        self.access_time = access_time
        self.write_time = write_time

    @property
    def stored_size(self) -> int:
        """Number of bytes the member occupies in the archive."""
        return self.size if self.packed_size is None else self.packed_size

    def __repr__(self):
        return f"DXAInfo(file_name={self.file_name!r}, size={self.size!r}, packed_size={self.packed_size!r})"


class _Dir:
    """A directory being assembled for writing."""

    def __init__(self, name: str = ''):
        self.name = name
        self.children: dict[str, DXAInfo | _Dir] = {}


def _upper_ascii(name: str) -> str:
    return ''.join(c.upper() if c.isascii() else c for c in name)


def _name_record(name: str, codec: str) -> bytes:
    raw = name.encode(codec, 'surrogateescape')
    upper = _upper_ascii(name).encode(codec, 'surrogateescape')
    units = (len(raw) + 4) // 4 if raw else 0
    return (
        _NAME_HEADER.build({'units': units, 'parity': sum(upper) & 0xFFFF})
        + upper.ljust(units * 4, b'\0')
        + raw.ljust(units * 4, b'\0')
    )


def _codec_for(codepage: int) -> str:
    name = 'utf-8' if codepage == 65001 else f'cp{codepage}'
    try:
        return codecs.lookup(name).name
    except LookupError:
        raise ValueError(f"DXA archive uses unsupported code page {codepage}") from None


# -- archive -------------------------------------------------------------------


class DXAFile:
    """Read or create DxLib DXA archives.

    Use ``mode='r'`` (default) to read a version 1 to 4 archive.  Without a
    *password* the key is found automatically: the default key, no encryption,
    or a key recovered from the header.

    Use ``mode='w'`` to create a version 4 archive encrypted with *password*
    (default: the default key).  With *compress*, members are LZ-compressed when
    that makes them smaller.
    """

    def __init__(
        self,
        file: str | os.PathLike,
        mode: str = 'r',
        password: 'str | None' = None,
        compress: bool = False,
    ):
        self.fp: BinaryIO | None = None

        if mode not in ('r', 'w'):
            raise ValueError(f"Invalid mode: {mode!r} (expected 'r' or 'w')")

        self.filename = os.fspath(file)
        self.mode = mode
        self.compress = compress
        self.files: list[DXAInfo] = []
        self._by_name: dict[str, DXAInfo] = {}
        self._size = 0

        if mode == 'r':
            self.version = 0
            self.key = b''
            self.codec = 'cp932'
            self._open_for_read(password)
            self.password = password if password is not None else password_from_key(self.key)
        else:
            self.version = WRITE_VERSION
            self.password = password or ''
            self.key = derive_key(self.password)
            self.codec = _codec_for(CODEPAGE)
            self._root = _Dir()
            self.fp = open(self.filename, 'wb')
            self._data_start = _HEADER_V4.sizeof()
            self.fp.write(b'\0' * self._data_start)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
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

    def _open_for_read(self, password: 'str | None'):
        fp = open(self.filename, 'rb')
        try:
            self._size = os.fstat(fp.fileno()).st_size
            head = fp.read(_HEADER_V4.sizeof())
            if len(head) < _HEADER_V1.sizeof():
                raise ValueError(f"{self.filename} is too short to be a DXA archive")

            if password is not None:
                candidates: Iterator[bytes] | list[bytes] = [derive_key(password)]
            else:
                candidates = self._candidate_keys(head)

            error = None
            for key in candidates:
                try:
                    self._read_index(fp, head, key)
                except ValueError as e:
                    error = error or e
                    continue
                self.key = key
                self.fp = fp
                return
            if password is not None:
                raise ValueError(f"{self.filename} could not be read with the given password: {error}")
            raise ValueError(f"{self.filename} is not a DXA archive, or is an unsupported version: {error}")
        except Exception:
            fp.close()
            raise

    def _candidate_keys(self, head: bytes) -> Iterator[bytes]:
        for key in (DEFAULT_KEY, PLAIN_KEY):
            plain = crypt(head[:4], 0, key)
            if plain[:2] == DXA_MAGIC:
                version = int.from_bytes(plain[2:4], 'little')
                if version not in SUPPORTED_VERSIONS:
                    raise ValueError(f"Unsupported DXA version {version} in {self.filename}")
                yield key
        yield from _guess_keys(head, self._size)

    def _read_index(self, fp: BinaryIO, head: bytes, key: bytes):
        plain = crypt(head, 0, key)
        version = int.from_bytes(plain[2:4], 'little')
        if plain[:2] != DXA_MAGIC or version not in SUPPORTED_VERSIONS:
            raise ValueError("bad signature")
        header_struct = _header_struct(version)
        if len(plain) < header_struct.sizeof():
            raise ValueError("truncated header")
        header = header_struct.parse(plain)

        if not header_struct.sizeof() <= header.data_start <= header.index_offset:
            raise ValueError(f"data offset {header.data_start:#x} is outside the file")
        if header.index_size > MAX_INDEX_SIZE or header.index_offset + header.index_size > self._size:
            raise ValueError(f"index at {header.index_offset:#x} (size {header.index_size:#x}) is outside the file")
        if not header.file_table <= header.dir_table < header.index_size:
            raise ValueError("index tables are outside the index")

        codec = _codec_for(header.get('codepage', CODEPAGE))
        fp.seek(header.index_offset)
        index = crypt(fp.read(header.index_size), header.index_offset, key)
        files = _IndexReader(index, header, version, codec, self._size).read()

        self.version = version
        self.codec = codec
        self._data_start = header.data_start
        self.files = files
        self._by_name = {info.file_name: info for info in files}

    def _resolve(self, member: 'DXAInfo | str') -> DXAInfo:
        if self.fp is None:
            raise ValueError("I/O operation on closed DXA archive")
        if self.mode != 'r':
            raise ValueError("reading requires mode='r'")
        if isinstance(member, DXAInfo):
            return member
        try:
            return self._by_name[member]
        except KeyError:
            raise KeyError(f"No member named {member!r}") from None

    def _iter_chunks(self, info: DXAInfo) -> Iterator[bytes]:
        if self.fp is None:
            raise ValueError("I/O operation on closed DXA archive")
        if info.packed_size is not None:
            self.fp.seek(info.offset)
            packed = crypt(self.fp.read(info.packed_size), info.offset, self.key)
            data = lz.decompress(packed)
            if len(data) != info.size:
                raise ValueError(
                    f"DXA member {info.file_name!r} decompressed to {len(data)} bytes, expected {info.size}"
                )
            yield data
            return
        pos = info.offset
        end = info.offset + info.size
        while pos < end:
            self.fp.seek(pos)
            chunk = self.fp.read(min(end - pos, _CHUNK_SIZE))
            if not chunk:
                raise ValueError(f"Unexpected end of DXA data in member {info.file_name!r}")
            yield crypt(chunk, pos, self.key)
            pos += len(chunk)

    def read(self, member: 'DXAInfo | str') -> bytes:
        """Return the contents of *member*, a :class:`DXAInfo` or a file name."""
        return b''.join(self._iter_chunks(self._resolve(member)))

    def extract(self, member: 'DXAInfo | str', path: str | os.PathLike):
        """Extract *member* to a new file at *path*."""
        chunks = self._iter_chunks(self._resolve(member))
        first = next(chunks, b'')
        with open(path, 'xb') as f:
            f.write(first)
            for chunk in chunks:
                f.write(chunk)

    def extract_all(self, path: str | os.PathLike, glob: str | None = None):
        """Extract all members to directory *path*.

        If *glob* is given, only members whose names match the pattern are
        extracted.  Raises ValueError, before writing anything, if a selected
        member's name would place it outside *path*.
        """
        for info, filepath in plan_extraction(self.files, path, glob):
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            self.extract(info, filepath)

    # -- creation --------------------------------------------------------------

    def _insert(self, name: str, info: DXAInfo):
        """Place *info* in the directory tree at path *name*."""
        parts = name.replace('\\', '/').split('/')
        node = self._root
        for i, part in enumerate(parts):
            try:
                part.encode(self.codec)
            except UnicodeEncodeError:
                raise ValueError(f"DXA member name {name!r} cannot be encoded as {self.codec}") from None
            key = _upper_ascii(part)
            existing = node.children.get(key)
            if i == len(parts) - 1:
                if existing is not None:
                    raise ValueError(f"Duplicate DXA member name: {name!r}")
                node.children[key] = info
            elif existing is None:
                node.children[key] = node = _Dir(part)
            elif isinstance(existing, _Dir):
                node = existing
            else:
                raise ValueError(f"DXA member {name!r} needs {part!r} to be a directory, but it is a file")

    def write(self, filepath: str | os.PathLike, arcname: str | None = None):
        """Add the file at *filepath* to the archive.

        *arcname* is the name stored in the archive, with ``/`` or ``\\``
        separating directories.  It defaults to the basename of *filepath*.
        """
        if self.fp is None:
            raise ValueError("I/O operation on closed DXA archive")
        if self.mode != 'w':
            raise ValueError("write() requires mode='w'")

        filepath = os.fspath(filepath)
        name = arcname if arcname is not None else os.path.basename(filepath)
        # Taken before reading, which can update the access time.
        st = os.stat(filepath)
        info = DXAInfo(
            name,
            create_time=_filetime(getattr(st, 'st_birthtime_ns', st.st_ctime_ns)),
            access_time=_filetime(st.st_atime_ns),
            write_time=_filetime(st.st_mtime_ns),
        )
        self._insert(name, info)

        offset = self.fp.tell()
        info.offset = offset
        with open(filepath, 'rb') as source:
            if self.compress:
                data = source.read()
                info.size = len(data)
                packed = lz.compress(data)
                if len(packed) < len(data):
                    info.packed_size = len(packed)
                    data = packed
                self.fp.write(crypt(data, offset, self.key))
            else:
                pos = offset
                while chunk := source.read(_CHUNK_SIZE):
                    self.fp.write(crypt(chunk, pos, self.key))
                    pos += len(chunk)
                info.size = pos - offset
        if self.fp.tell() > MAX_U32:
            raise ValueError("DXA archives cannot exceed 4 GiB")
        self.files.append(info)
        logger.debug('packed %s: offset=%#x size=%#x packed=%s', name, offset, info.size, info.packed_size)

    def write_all(self, path: str | os.PathLike, glob: str | None = None, prefix: str = ''):
        """Recursively add the files in directory *path* to the archive."""
        if self.fp is None:
            raise ValueError("I/O operation on closed DXA archive")
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

    def _finalize(self):
        """Write the index after the data, then the header."""
        if self.fp is None:
            raise ValueError("I/O operation on closed DXA archive")
        names = bytearray(_name_record('', self.codec))
        records: list[dict] = []
        dirs: list[dict] = []
        record_size = _FILE_RECORD_V2.sizeof()

        def add_record(name: str, **fields) -> int:
            name_offset = len(names)
            names.extend(_name_record(name, self.codec))
            fields.setdefault('create_time', 0)
            fields.setdefault('access_time', 0)
            fields.setdefault('write_time', 0)
            records.append({'name_offset': name_offset, **fields})
            return len(records) - 1

        def place_dir(node: _Dir, own_record: int, parent: int):
            dir_index = len(dirs)
            dirs.append({})
            first = len(records)
            children = sorted(node.children.items(), key=lambda kv: kv[0].encode(self.codec, 'surrogateescape'))
            subdirs = []
            for _key, child in children:
                if isinstance(child, _Dir):
                    index = add_record(
                        child.name, attributes=FILE_ATTRIBUTE_DIRECTORY, address=0, size=0, packed_size=NOT_PACKED
                    )
                    subdirs.append((index, child))
                else:
                    add_record(
                        child.file_name.replace('\\', '/').split('/')[-1],
                        attributes=child.attributes,
                        create_time=child.create_time,
                        access_time=child.access_time,
                        write_time=child.write_time,
                        address=child.offset - self._data_start,
                        size=child.size,
                        packed_size=NOT_PACKED if child.packed_size is None else child.packed_size,
                    )
            dirs[dir_index] = {
                'own_record': own_record * record_size,
                'parent': parent,
                'count': len(children),
                'first_record': first * record_size,
            }
            for index, child in subdirs:
                records[index]['address'] = len(dirs) * _DIR_RECORD.sizeof()
                place_dir(child, index, dir_index * _DIR_RECORD.sizeof())

        # The root's record uses the empty name already at offset 0.
        records.append(
            {
                'name_offset': 0,
                'attributes': FILE_ATTRIBUTE_DIRECTORY,
                'create_time': 0,
                'access_time': 0,
                'write_time': 0,
                'address': 0,
                'size': 0,
                'packed_size': NOT_PACKED,
            }
        )
        place_dir(self._root, 0, NO_PARENT)

        file_table = b''.join(_FILE_RECORD_V2.build(r) for r in records)
        dir_table = b''.join(_DIR_RECORD.build(d) for d in dirs)
        index = bytes(names) + file_table + dir_table

        index_offset = self.fp.tell()
        if index_offset + len(index) > MAX_U32:
            raise ValueError("DXA archives cannot exceed 4 GiB")
        self.fp.write(crypt(index, index_offset, self.key))
        header = _HEADER_V4.build(
            {
                'version': WRITE_VERSION,
                'index_size': len(index),
                'data_start': self._data_start,
                'index_offset': index_offset,
                'file_table': len(names),
                'dir_table': len(names) + len(file_table),
                'codepage': CODEPAGE,
            }
        )
        self.fp.seek(0)
        self.fp.write(crypt(header, 0, self.key))


class _IndexReader:
    """Walk the directory tree of a decrypted index."""

    def __init__(self, index: bytes, header, version: int, codec: str, file_size: int):
        self.index = index
        self.header = header
        self.codec = codec
        self.file_size = file_size
        self.record = _file_record_struct(version)
        self.files: list[DXAInfo] = []

    def _parse(self, struct: Struct, offset: int):
        if offset < 0 or offset + struct.sizeof() > len(self.index):
            raise ValueError(f"DXA index record at {offset:#x} is outside the index")
        return struct.parse(self.index[offset : offset + struct.sizeof()])

    def _name(self, name_offset: int) -> str:
        if name_offset + _NAME_HEADER.sizeof() > self.header.file_table:
            raise ValueError(f"DXA name record at {name_offset:#x} is outside the name table")
        units = _NAME_HEADER.parse(self.index[name_offset : name_offset + 4]).units
        start = name_offset + 4 + units * 4
        end = min(start + units * 4, self.header.file_table)
        raw = self.index[start:end].split(b'\0', 1)[0]
        return raw.decode(self.codec, 'surrogateescape')

    def read(self) -> list[DXAInfo]:
        stack = [(0, '')]
        visited: set[int] = set()
        while stack:
            dir_offset, path = stack.pop()
            if dir_offset in visited:
                raise ValueError("DXA index has a directory loop")
            visited.add(dir_offset)
            d = self._parse(_DIR_RECORD, self.header.dir_table + dir_offset)
            if d.count > len(self.index) // self.record.sizeof():
                raise ValueError(f"DXA directory claims {d.count} entries, more than the index holds")
            subdirs = []
            for i in range(d.count):
                r = self._parse(self.record, self.header.file_table + d.first_record + i * self.record.sizeof())
                name = path + self._name(r.name_offset)
                if r.attributes & FILE_ATTRIBUTE_DIRECTORY:
                    subdirs.append((r.address, name + '/'))
                    continue
                packed = r.get('packed_size', NOT_PACKED)
                info = DXAInfo(
                    name,
                    offset=self.header.data_start + r.address,
                    size=r.size,
                    packed_size=None if packed == NOT_PACKED else packed,
                    attributes=r.attributes,
                    create_time=r.create_time,
                    access_time=r.access_time,
                    write_time=r.write_time,
                )
                if info.offset + info.stored_size > self.file_size:
                    raise ValueError(f"DXA member {name!r} extends past the end of the file")
                self.files.append(info)
            # Depth-first, in index order.
            stack.extend(reversed(subdirs))
        return self.files


def is_dxa(path: str | os.PathLike) -> bool:
    """Return True if *path* is a DXA archive this module can read."""
    try:
        with DXAFile(path):
            return True
    except (OSError, ValueError):
        return False
