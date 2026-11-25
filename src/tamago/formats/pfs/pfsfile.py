"""Reader and writer for the Artemis Engine's ``.pfs`` resource archives.

An archive is a three-byte magic (``pf2``, ``pf6`` or ``pf8``: the digit is
the version), a little-endian u32 index size, the index, and the members'
data packed back to back to the end of the file.  Each index entry is a
length-prefixed name (``\\`` separates directories), a reserved field, and the
member's absolute u32 offset and size.  ``pf6`` and ``pf8`` indexes end with
a table locating every entry's offset field; ``pf2`` entries carry a 12-byte
constant block instead.  ``pf8`` members are XORed with the SHA-1 digest of
the whole index, restarting at the first key byte for every member.

Games may ship patch archives beside ``root.pfs`` (``root.pfs.000``,
``root.pfs.001``, ...); each is a complete archive of its own.

The index is sorted by name bytes, but the games store data in another
order.  Since the key hashes every offset, extraction writes a manifest
(:data:`MANIFEST_NAME`) recording the data order, version and name encoding,
and :meth:`PFSFile.write_all` follows it, rebuilding an unmodified archive
byte for byte.
"""

import fnmatch
import hashlib
import io
import json
import logging
import os
import pathlib
from typing import BinaryIO

from construct import Bytes, Const, ConstructError, Int32ul, Int64ul, PascalString, StreamError, Struct

from tamago.formats.member_paths import member_path, plan_extraction

logger = logging.getLogger(__name__)

MANIFEST_NAME = '_pfs_manifest.json'
MANIFEST_FORMAT = 'pfs'

VERSIONS = (2, 6, 8)
ENCRYPTED_VERSIONS = (8,)
DEFAULT_VERSION = 8
ENCODINGS = ('cp932', 'utf-8')
DEFAULT_ENCODING = 'cp932'

HEADER_SIZE = 7
# Entries start right after the header and a pf6/pf8 index's entry count; the
# offset table counts from here.
ENTRIES_START = HEADER_SIZE + 4
KEY_SIZE = 20
MAX_U32 = 0xFFFFFFFF
# How much member data is processed at a time.
CHUNK_SIZE = KEY_SIZE * 0x10000

Header = Struct('magic' / Bytes(3), 'index_size' / Int32ul)
Entry = Struct(
    'name' / PascalString(Int32ul, 'latin-1'),
    'reserved' / Int32ul,
    'offset' / Int32ul,
    'size' / Int32ul,
)
PF2_BLOCK = b'\x10' + bytes(11)
Pf2Entry = Struct(
    'name' / PascalString(Int32ul, 'latin-1'),
    'block' / Bytes(12),
    'offset' / Int32ul,
    'size' / Int32ul,
)
Pf2Head = Struct('reserved' / Const(0, Int32ul), 'count' / Int32ul)


def xor_key(data: bytes | memoryview, key: bytes, start: int = 0) -> bytes:
    """XOR *data* with *key* repeated, as if *data* began at byte *start* of a member."""
    n = len(data)
    if n == 0:
        return b''
    phase = start % len(key)
    reps = (phase + n + len(key) - 1) // len(key)
    mask = (key * reps)[phase : phase + n]
    return (int.from_bytes(data, 'little') ^ int.from_bytes(mask, 'little')).to_bytes(n, 'little')


class PFSInfo:
    """Metadata for one member of a PFS archive."""

    __slots__ = ('file_name', 'raw_name', 'offset', 'size')

    def __init__(self, file_name: str, raw_name: bytes, offset: int, size: int):
        self.file_name = file_name
        self.raw_name = raw_name
        self.offset = offset
        self.size = size

    def __repr__(self):
        return f"PFSInfo(file_name={self.file_name!r}, offset={self.offset:#x}, size={self.size})"


def _parse_version(magic: bytes) -> int:
    if magic[:2] != b'pf' or not magic[2:3].isdigit():
        raise ValueError(f"not a PFS archive (magic {magic!r})")
    version = magic[2] - ord('0')
    if version not in VERSIONS:
        raise ValueError(f"unsupported PFS version {version} (supported: {', '.join(map(str, VERSIONS))})")
    return version


def _detect_encoding(raw_names: list[bytes]) -> str:
    """UTF-8 if every name is valid UTF-8 and some name is not ASCII, else cp932.

    cp932 names with Japanese characters are almost never valid UTF-8, while
    UTF-8 names often decode as cp932 without error (as mojibake).
    """
    if all(name.isascii() for name in raw_names):
        return DEFAULT_ENCODING
    try:
        for name in raw_names:
            name.decode('utf-8')
    except UnicodeDecodeError:
        return 'cp932'
    return 'utf-8'


def _read_index(fp: BinaryIO, file_size: int) -> tuple[int, bytes, list[tuple[bytes, int, int]]]:
    """Parse the archive open as *fp*: return its version, raw index and ``(name, offset, size)`` entries."""
    head = fp.read(HEADER_SIZE)
    if len(head) < HEADER_SIZE:
        raise ValueError("File too small to be a PFS archive")
    header = Header.parse(head)
    version = _parse_version(header.magic)
    data_start = HEADER_SIZE + header.index_size
    if data_start > file_size:
        raise ValueError(f"PFS index of {header.index_size} bytes does not fit in the file")
    index = fp.read(header.index_size)
    stream = io.BytesIO(index)

    entries = []
    start = 0
    try:
        if version == 2:
            count = Pf2Head.parse_stream(stream).count
            entry_struct = Pf2Entry
        else:
            count = Int32ul.parse_stream(stream)
            entry_struct = Entry
        for _ in range(count):
            start = stream.tell()
            entry = entry_struct.parse_stream(stream)
            raw_name = entry.name.encode('latin-1')
            if entry.offset < data_start or entry.offset + entry.size > file_size:
                raise ValueError(f"PFS member {raw_name!r} lies outside the archive's data")
            entries.append((raw_name, entry.offset, entry.size))
    except StreamError:
        raise ValueError(f"PFS index entry at {HEADER_SIZE + start:#x} runs past the index") from None
    except ConstructError as e:
        raise ValueError(f"Malformed PFS index: {e}") from None
    return version, index, entries


def is_pfs(path: str | os.PathLike) -> bool:
    """Return True if the file at *path* is a PFS archive whose index parses cleanly."""
    try:
        with open(path, 'rb') as fp:
            _read_index(fp, os.fstat(fp.fileno()).st_size)
    except (OSError, ValueError):
        return False
    return True


def _encode_index(version: int, entries: list[tuple[bytes, int, int]]) -> bytes:
    """Build the index for ``(raw_name, offset, size)`` *entries*, in the order given."""
    out = bytearray()
    if version == 2:
        out += Pf2Head.build({'count': len(entries)})
        for name, offset, size in entries:
            out += Pf2Entry.build({'name': name.decode('latin-1'), 'block': PF2_BLOCK, 'offset': offset, 'size': size})
        return bytes(out)
    out += Int32ul.build(len(entries))
    table = []
    for name, offset, size in entries:
        built = Entry.build({'name': name.decode('latin-1'), 'reserved': 0, 'offset': offset, 'size': size})
        # The offset field's position, counting from the first entry.
        table.append(HEADER_SIZE + len(out) + len(built) - 8 - ENTRIES_START)
        out += built
    table_pos = len(out)
    out += Int32ul.build(len(entries) + 1)
    out += b''.join(Int64ul.build(t) for t in table) + Int64ul.build(0)
    out += Int32ul.build(table_pos)
    return bytes(out)


def _index_size(version: int, raw_names: list[bytes]) -> int:
    if version == 2:
        return 8 + sum(4 + len(name) + 12 + 8 for name in raw_names)
    return 4 + sum(4 + len(name) + 12 for name in raw_names) + 4 + 8 * (len(raw_names) + 1) + 4


class _Pending:
    __slots__ = ('source', 'raw_name', 'size')

    def __init__(self, source: str, raw_name: bytes):
        self.source = source
        self.raw_name = raw_name
        self.size = 0


class PFSFile:
    """Read or create an Artemis PFS archive.

    Use ``mode='r'`` (default) to read an existing archive, or ``mode='w'``
    to create one; it is written when the archive is closed.  In write mode,
    *version* (2, 6 or 8) and *encoding* (``'cp932'`` or ``'utf-8'``, for
    member names) default to the manifest's when :meth:`write_all` finds
    one, or else to version 8 and cp932.
    """

    def __init__(
        self,
        file: str | os.PathLike,
        mode: str = 'r',
        version: int | None = None,
        encoding: str | None = None,
    ):
        self.fp: BinaryIO | None = None
        if mode not in ('r', 'w'):
            raise ValueError(f"Invalid mode: {mode!r} (expected 'r' or 'w')")
        if version is not None and version not in VERSIONS:
            raise ValueError(f"Unsupported PFS version {version} (supported: {', '.join(map(str, VERSIONS))})")
        if encoding is not None and encoding not in ENCODINGS:
            raise ValueError(f"Unsupported PFS name encoding {encoding!r} (supported: {', '.join(ENCODINGS)})")
        self.filename = os.fspath(file)
        self.mode = mode
        self.files: list[PFSInfo] = []
        self.key: bytes | None = None
        self._pending: list[_Pending] = []
        self._version_given = version is not None
        self._encoding_given = encoding is not None
        self.version = version if version is not None else DEFAULT_VERSION
        self.encoding = encoding if encoding is not None else DEFAULT_ENCODING

        if mode == 'r':
            fp = open(self.filename, 'rb')
            try:
                self._load(fp)
            except Exception:
                fp.close()
                raise
            self.fp = fp
        else:
            self.fp = open(self.filename, 'wb')

    def _load(self, fp: BinaryIO):
        self.version, index, entries = _read_index(fp, os.fstat(fp.fileno()).st_size)
        self.encoding = _detect_encoding([name for name, _offset, _size in entries])
        for raw_name, offset, size in entries:
            try:
                name = raw_name.decode(self.encoding)
            except UnicodeDecodeError:
                raise ValueError(f"PFS member name {raw_name!r} cannot be decoded as {self.encoding}") from None
            self.files.append(PFSInfo(name, raw_name, offset, size))
        if self.version in ENCRYPTED_VERSIONS:
            self.key = hashlib.sha1(index, usedforsecurity=False).digest()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None and self.mode == 'w':
            # Don't write a partial archive after a failure.
            self._pending.clear()
            fp, self.fp = self.fp, None
            if fp is not None:
                fp.close()
            return
        self.close()

    def __del__(self):
        self.close()

    def close(self):
        """Close the archive, writing it out if in write mode."""
        fp = getattr(self, 'fp', None)
        if fp is None:
            return
        try:
            if self.mode == 'w':
                self._finalize()
        finally:
            self.fp = None
            fp.close()

    # -- reading ---------------------------------------------------------------

    def _check_readable(self):
        if self.fp is None:
            raise ValueError("I/O operation on closed PFS archive")
        if self.mode != 'r':
            raise ValueError("reading requires mode='r'")

    def namelist(self) -> list[str]:
        return [info.file_name for info in self.files]

    def getinfo(self, name: str) -> PFSInfo:
        for info in self.files:
            if info.file_name == name:
                return info
        raise KeyError(f"No member named {name!r}")

    def _chunks(self, info: PFSInfo):
        """Yield the decrypted contents of *info* a piece at a time."""
        assert self.fp is not None
        self.fp.seek(info.offset)
        pos = 0
        while pos < info.size:
            chunk = self.fp.read(min(CHUNK_SIZE, info.size - pos))
            if not chunk:
                raise ValueError(f"PFS member {info.file_name!r} is truncated")
            yield xor_key(chunk, self.key, pos) if self.key else chunk
            pos += len(chunk)

    def read(self, member: 'PFSInfo | str') -> bytes:
        """Return the contents of *member* (a :class:`PFSInfo` or a name), decrypted."""
        self._check_readable()
        info = member if isinstance(member, PFSInfo) else self.getinfo(member)
        return b''.join(self._chunks(info))

    def extract(self, member: 'PFSInfo | str', path: str | os.PathLike) -> str:
        """Write the contents of *member* to a new file at *path*, returning the path written."""
        self._check_readable()
        info = member if isinstance(member, PFSInfo) else self.getinfo(member)
        path = os.fspath(path)
        with open(path, 'xb') as f:
            for chunk in self._chunks(info):
                f.write(chunk)
        return path

    def extract_all(self, path: str | os.PathLike, glob: str | None = None):
        """Extract members to directory *path*, with a manifest of their data order.

        If *glob* is given, only members whose names match it are extracted
        (and listed in the manifest).  Raises ValueError, before writing
        anything, if a selected member's name would place it outside *path*.
        """
        self._check_readable()
        plan = plan_extraction(self.files, path, glob)
        manifest_path = os.path.join(os.path.abspath(path), MANIFEST_NAME)
        for info, filepath in plan:
            if os.path.normcase(filepath) == os.path.normcase(manifest_path):
                raise ValueError(f"Member {info.file_name!r} would overwrite the manifest {MANIFEST_NAME}")
        os.makedirs(path, exist_ok=True)
        for info, filepath in plan:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            self.extract(info, filepath)
        members = [self._manifest_entry(info) for info, _filepath in sorted(plan, key=lambda p: p[0].offset)]
        manifest = {'format': MANIFEST_FORMAT, 'version': self.version, 'encoding': self.encoding, 'members': members}
        with open(manifest_path, 'x', encoding='utf-8') as f:
            json.dump(manifest, f, ensure_ascii=False, indent=1)
            f.write('\n')

    def _manifest_entry(self, info: PFSInfo) -> dict:
        entry: dict = {'name': info.file_name}
        try:
            exact = info.file_name.encode(self.encoding) == info.raw_name
        except UnicodeEncodeError:
            exact = False
        if not exact:
            entry['name_hex'] = info.raw_name.hex()
        return entry

    # -- creation --------------------------------------------------------------

    def _check_writable(self):
        if self.fp is None:
            raise ValueError("I/O operation on closed PFS archive")
        if self.mode != 'w':
            raise ValueError("writing requires mode='w'")

    def _encode_name(self, name: str) -> bytes:
        try:
            return name.replace('/', '\\').encode(self.encoding)
        except UnicodeEncodeError:
            raise ValueError(f"PFS member name {name!r} cannot be encoded as {self.encoding}") from None

    def write(self, filepath: str | os.PathLike, arcname: str | None = None, raw_name: bytes | None = None):
        """Add the file at *filepath* as a member, its data after that of those already added.

        The member is named *arcname* (default: the file's base name), with
        ``/`` turned into ``\\``, or stored with the exact name bytes
        *raw_name*.  The index is sorted by name bytes whatever the order of
        addition.
        """
        self._check_writable()
        filepath = os.fspath(filepath)
        if raw_name is None:
            raw_name = self._encode_name(arcname if arcname is not None else os.path.basename(filepath))
        if not raw_name or b'\0' in raw_name:
            raise ValueError(f"PFS member name {raw_name!r} must be non-empty, without NULs")
        if any(p.raw_name == raw_name for p in self._pending):
            raise ValueError(f"PFS member name {raw_name!r} is added more than once")
        self._pending.append(_Pending(filepath, raw_name))

    def write_all(self, path: str | os.PathLike, glob: str | None = None):
        """Add the files under directory *path*, following its manifest if it has one.

        Members listed in the manifest keep their recorded names and data
        order, and the manifest's version and encoding apply unless given to
        the constructor.  Other files are named by their path relative to
        *path* (with ``\\`` separators); their data follows, sorted by name
        bytes.  *glob* matches member names.
        """
        self._check_writable()
        assert self.fp is not None
        root = pathlib.Path(path)
        output = os.fstat(self.fp.fileno())
        manifest_path = root / MANIFEST_NAME
        listed_paths: set[str] = set()
        listed: list[tuple[bytes, str]] = []

        if manifest_path.is_file():
            manifest = self._read_manifest(manifest_path)
            if not self._version_given:
                self.version = manifest['version']
            if not self._encoding_given:
                self.encoding = manifest['encoding']
            for entry in manifest['members']:
                source = member_path(root, entry['name'])
                listed_paths.add(os.path.normcase(source))
                if glob and not fnmatch.fnmatch(entry['name'], glob):
                    continue
                if not os.path.isfile(source):
                    raise ValueError(f"The manifest lists {entry['name']!r}, which is missing from {root}")
                raw = entry['raw_name'] if entry['raw_name'] is not None else self._encode_name(entry['name'])
                listed.append((raw, source))

        others: list[tuple[bytes, str]] = []
        for dirpath, dirs, files in os.walk(root):
            dirs.sort()
            for file_name in files:
                source = os.path.join(dirpath, file_name)
                name = pathlib.Path(source).relative_to(root).as_posix()
                if name == MANIFEST_NAME or os.path.normcase(os.path.abspath(source)) in listed_paths:
                    continue
                if os.path.samestat(output, os.stat(source)):
                    continue
                pfs_name = name.replace('/', '\\')
                if glob and not fnmatch.fnmatch(pfs_name, glob):
                    continue
                others.append((self._encode_name(pfs_name), source))
        others.sort()

        for raw, source in listed + others:
            self.write(source, raw_name=raw)

    @staticmethod
    def _read_manifest(manifest_path: pathlib.Path) -> dict:
        try:
            with open(manifest_path, encoding='utf-8') as f:
                manifest = json.load(f)
            if manifest.get('format') != MANIFEST_FORMAT:
                raise ValueError(f"not a {MANIFEST_FORMAT} manifest")
            version, encoding = manifest['version'], manifest['encoding']
            if version not in VERSIONS or encoding not in ENCODINGS:
                raise ValueError(f"unsupported version {version!r} or encoding {encoding!r}")
            members = []
            for m in manifest['members']:
                name = m['name']
                if not isinstance(name, str):
                    raise ValueError(f"bad member entry {m!r}")
                raw = bytes.fromhex(m['name_hex']) if 'name_hex' in m else None
                members.append({'name': name, 'raw_name': raw})
        except (OSError, KeyError, TypeError, ValueError, AttributeError) as e:
            raise ValueError(f"Invalid PFS manifest {manifest_path}: {e}") from None
        return {'version': version, 'encoding': encoding, 'members': members}

    def _finalize(self):
        """Write the index, then the member data, encrypted for ``pf8``.

        The key hashes the finished index, so every size is taken first;
        members are then copied a chunk at a time.
        """
        assert self.fp is not None
        fp = self.fp
        for p in self._pending:
            p.size = os.path.getsize(p.source)
        index_size = _index_size(self.version, [p.raw_name for p in self._pending])
        offsets = {}
        offset = HEADER_SIZE + index_size
        for p in self._pending:
            offsets[p.raw_name] = offset
            offset += p.size
        if offset > MAX_U32 + 1:
            raise ValueError("PFS archives cannot exceed 4 GiB")

        ordered = sorted(self._pending, key=lambda p: p.raw_name)
        index = _encode_index(self.version, [(p.raw_name, offsets[p.raw_name], p.size) for p in ordered])
        assert len(index) == index_size
        key = hashlib.sha1(index, usedforsecurity=False).digest() if self.version in ENCRYPTED_VERSIONS else None
        fp.write(Header.build({'magic': b'pf%d' % self.version, 'index_size': index_size}))
        fp.write(index)

        for p in self._pending:
            pos = 0
            with open(p.source, 'rb') as f:
                while pos < p.size:
                    chunk = f.read(min(CHUNK_SIZE, p.size - pos))
                    if not chunk:
                        raise ValueError(f"{p.source} shrank while the archive was being written")
                    fp.write(xor_key(chunk, key, pos) if key else chunk)
                    pos += len(chunk)
            logger.debug('wrote %r at %#x: size=%d', p.raw_name, offsets[p.raw_name], p.size)
