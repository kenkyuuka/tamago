"""Reader and writer for Ren'Py RPA archives.

An RPA archive is a flat bundle of files with a compressed index:

- RPA-3.0: a text header holding the index offset and an XOR key, file data,
  then the index.  Offsets and lengths in the index are XORed with the key.
- RPA-2.0: as RPA-3.0, without the key.
- RPA-1.0: no header.  The index is a separate ``.rpi`` file beside the ``.rpa``
  data file.

The index is a zlib-compressed pickle mapping each file name to a list of
``(offset, length)`` or ``(offset, length, prefix)`` entries.  *prefix* holds
the first bytes of the file, which are stored in the index instead of the data
area, and the stored *length* counts them.

Archives are untrusted input and a pickle can run arbitrary code when loaded, so
the index is only ever loaded through :class:`_IndexUnpickler`.
"""

import fnmatch
import io
import logging
import os
import pathlib
import pickle
import re
import shutil
import zlib
from collections.abc import Iterator
from typing import BinaryIO, NamedTuple

logger = logging.getLogger(__name__)

RPA_MAGIC = b'RPA-'
RPA3_MAGIC = b'RPA-3.0 '
RPA2_MAGIC = b'RPA-2.0 '

RPA3_HEADER_SIZE = 34
RPA2_HEADER_SIZE = 25

# The key the Ren'Py archiver has always used.
DEFAULT_KEY = 0x42424242
MAX_KEY = 0xFFFFFFFF

# Far above any real index, which takes roughly 100 bytes per file.
MAX_INDEX_SIZE = 1 << 30

_CHUNK_SIZE = 1 << 20
_DRIVE_RE = re.compile(r'^[A-Za-z]:')


def _latin1_encode(text: str, encoding: 'str | bytes') -> bytes:
    """Stand-in for ``_codecs.encode``, which Python 3 uses to pickle bytes at protocol 2."""
    if isinstance(encoding, bytes):
        encoding = encoding.decode('ascii')
    if not isinstance(text, str) or encoding.lower().replace('-', '') != 'latin1':
        raise pickle.UnpicklingError(f"unexpected encoding {encoding!r} in RPA index")
    return text.encode('latin-1')


def _empty_bytes() -> bytes:
    """Stand-in for ``bytes``, which Python 3 calls to pickle ``b''`` at protocol 2."""
    return b''


class _IndexUnpickler(pickle.Unpickler):
    """Unpickler for RPA indexes, which refuses every global but two harmless stand-ins.

    Resolving a global is the only route by which a pickle reaches code it can
    call, so an index cannot run anything beyond the functions returned here.
    """

    def find_class(self, module, name):
        if (module, name) == ('_codecs', 'encode'):
            return _latin1_encode
        if (module, name) in (('__builtin__', 'bytes'), ('builtins', 'bytes')):
            return _empty_bytes
        raise pickle.UnpicklingError(f"forbidden global {module}.{name} in RPA index")


def _load_index(compressed: bytes) -> dict:
    """Decompress and unpickle an index, raising ValueError if it is not a valid one."""
    decompressor = zlib.decompressobj()
    try:
        raw = decompressor.decompress(compressed, MAX_INDEX_SIZE + 1)
    except zlib.error as e:
        raise ValueError(f"Corrupt RPA index: {e}") from e
    if len(raw) > MAX_INDEX_SIZE:
        raise ValueError(f"RPA index is larger than the {MAX_INDEX_SIZE} byte limit")
    if not decompressor.eof:
        raise ValueError("Corrupt RPA index: truncated zlib stream")

    # Python 2 wrote names and prefixes as 8-bit strings.  Loading them as bytes
    # keeps prefixes intact, where decoding them as text would not.
    try:
        index = _IndexUnpickler(io.BytesIO(raw), encoding='bytes').load()
    except Exception as e:
        raise ValueError(f"Invalid RPA index: {e}") from e
    if not isinstance(index, dict):
        raise ValueError(f"Invalid RPA index: expected a dict, found {type(index).__name__}")
    return index


class RPASegment(NamedTuple):
    """One run of a member's data: *prefix* bytes, then *length* bytes at *offset*."""

    offset: int
    length: int
    prefix: bytes


class RPAInfo:
    """Metadata for a single member of an RPA archive."""

    __slots__ = (
        'file_name',
        'segments',
    )

    def __init__(self, file_name: str = '', segments: 'list[RPASegment] | None' = None):
        self.file_name = file_name
        self.segments = segments if segments is not None else []

    @property
    def size(self) -> int:
        """Size of the member's contents in bytes."""
        return sum(len(s.prefix) + s.length for s in self.segments)

    def __repr__(self):
        return f"RPAInfo(file_name={self.file_name!r}, size={self.size!r})"


def _decode_prefix(value: object, name: str) -> bytes:
    if value is None:
        return b''
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode('latin-1', 'strict')
    raise ValueError(f"Invalid RPA index entry for {name!r}: bad prefix type {type(value).__name__}")


def _decode_entry(name: str, entry: object, key: int) -> RPASegment:
    if not isinstance(entry, (tuple, list)) or len(entry) not in (2, 3):
        raise ValueError(f"Invalid RPA index entry for {name!r}: {entry!r}")
    stored_offset, stored_length = entry[0], entry[1]
    if not isinstance(stored_offset, int) or not isinstance(stored_length, int):
        raise ValueError(f"Invalid RPA index entry for {name!r}: {entry!r}")
    try:
        prefix = _decode_prefix(entry[2], name) if len(entry) == 3 else b''
    except UnicodeEncodeError as e:
        raise ValueError(f"Invalid RPA index entry for {name!r}: {e}") from e

    offset = stored_offset ^ key
    length = (stored_length ^ key) - len(prefix)
    if offset < 0 or length < 0:
        raise ValueError(f"Invalid RPA index entry for {name!r}: offset {offset}, length {length}")
    return RPASegment(offset, length, prefix)


def _decode_members(index: dict, key: int) -> list[RPAInfo]:
    members = []
    for raw_name, entries in index.items():
        if isinstance(raw_name, bytes):
            name = raw_name.decode('utf-8', 'surrogateescape')
        elif isinstance(raw_name, str):
            name = raw_name
        else:
            raise ValueError(f"Invalid RPA index: member name {raw_name!r} is not a string")
        if not isinstance(entries, (tuple, list)) or not entries:
            raise ValueError(f"Invalid RPA index entry for {name!r}: {entries!r}")
        members.append(RPAInfo(name, [_decode_entry(name, entry, key) for entry in entries]))
    return members


def _safe_parts(name: str) -> list[str] | None:
    """Split member *name* into path components, or return None if it could escape the output directory."""
    normalized = name.replace('\\', '/')
    if normalized.startswith('/') or _DRIVE_RE.match(normalized) or '\0' in normalized:
        return None
    parts = [part for part in normalized.split('/') if part not in ('', '.')]
    if not parts or '..' in parts:
        return None
    return parts


class RPAFile:
    """Read or create Ren'Py RPA archives.

    Use ``mode='r'`` (default) to read an existing archive of any version, or
    ``mode='w'`` to create a new RPA-3.0 archive obfuscated with *key*.

    To read an RPA-1.0 archive, pass either its ``.rpi`` index or its ``.rpa``
    data file.
    """

    def __init__(self, file: str | os.PathLike, mode: str = 'r', key: int = DEFAULT_KEY):
        self.fp: BinaryIO | None = None

        if mode not in ('r', 'w'):
            raise ValueError(f"Invalid mode: {mode!r} (expected 'r' or 'w')")
        if not 0 <= key <= MAX_KEY:
            raise ValueError(f"Invalid key: {key:#x} (expected 32 bits)")

        self.filename = os.fspath(file)
        self.mode = mode
        self.key = key
        self.files: list[RPAInfo] = []
        self._by_name: dict[str, RPAInfo] = {}
        self._data_size = 0

        if mode == 'r':
            self._open_for_read()
        else:
            self.fp = open(self.filename, 'wb')
            self.fp.write(b'\0' * RPA3_HEADER_SIZE)

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

    def _open_for_read(self):
        with open(self.filename, 'rb') as f:
            head = f.read(RPA3_HEADER_SIZE)

        if head.startswith(RPA3_MAGIC):
            self._read_with_header(RPA3_HEADER_SIZE, has_key=True)
        elif head.startswith(RPA2_MAGIC):
            self._read_with_header(RPA2_HEADER_SIZE, has_key=False)
        elif head.startswith(RPA_MAGIC):
            version = head.split(b' ', 1)[0].decode('ascii', 'replace')
            raise ValueError(f"Unsupported RPA version: {version}")
        else:
            self._read_rpa1()

    def _read_with_header(self, header_size: int, has_key: bool):
        fp = open(self.filename, 'rb')
        self.fp = fp
        try:
            header = fp.read(header_size)
            try:
                index_offset = int(header[8:24], 16)
                key = int(header[25:33], 16) if has_key else 0
            except ValueError as e:
                raise ValueError(f"Invalid RPA header: {header!r}") from e

            self._data_size = os.fstat(fp.fileno()).st_size
            if not header_size <= index_offset < self._data_size:
                raise ValueError(f"RPA index offset {index_offset:#x} is outside the file")

            fp.seek(index_offset)
            self._set_members(_decode_members(_load_index(fp.read()), key))
        except Exception:
            self.fp = None
            fp.close()
            raise

    def _read_rpa1(self):
        path = pathlib.Path(self.filename)
        if path.suffix.lower() == '.rpi':
            index_path, data_path = path, path.with_suffix('.rpa')
        else:
            index_path, data_path = path.with_suffix('.rpi'), path
            if not index_path.is_file():
                raise ValueError(f"{self.filename} is not a recognised RPA archive")

        index = _load_index(index_path.read_bytes())
        members = _decode_members(index, 0)
        if not data_path.is_file():
            raise ValueError(f"RPA data file {data_path} is missing for index {index_path}")
        self.fp = open(data_path, 'rb')
        self._data_size = os.fstat(self.fp.fileno()).st_size
        self._set_members(members)

    def _set_members(self, members: list[RPAInfo]):
        self.files = members
        self._by_name = {member.file_name: member for member in members}

    def _resolve(self, member: 'RPAInfo | str') -> RPAInfo:
        if self.fp is None:
            raise ValueError("I/O operation on closed RPA archive")
        if self.mode != 'r':
            raise ValueError("reading requires mode='r'")
        if isinstance(member, RPAInfo):
            return member
        try:
            return self._by_name[member]
        except KeyError:
            raise KeyError(f"No member named {member!r}") from None

    def _iter_chunks(self, member: RPAInfo) -> Iterator[bytes]:
        """Yield the contents of *member*, having first checked that it all lies inside the file."""
        if self.fp is None:
            raise ValueError("I/O operation on closed RPA archive")
        for segment in member.segments:
            if segment.offset + segment.length > self._data_size:
                raise ValueError(
                    f"RPA member {member.file_name!r} extends past the end of the file "
                    f"(offset {segment.offset:#x}, length {segment.length:#x})"
                )
        for segment in member.segments:
            if segment.prefix:
                yield segment.prefix
            self.fp.seek(segment.offset)
            remaining = segment.length
            while remaining:
                chunk = self.fp.read(min(remaining, _CHUNK_SIZE))
                if not chunk:
                    raise ValueError(f"Unexpected end of RPA data in member {member.file_name!r}")
                remaining -= len(chunk)
                yield chunk

    def read(self, member: 'RPAInfo | str') -> bytes:
        """Return the contents of *member*, an :class:`RPAInfo` or a file name."""
        return b''.join(self._iter_chunks(self._resolve(member)))

    def extract(self, member: 'RPAInfo | str', path: str | os.PathLike):
        """Extract *member* to a new file at *path*, without holding it all in memory."""
        info = self._resolve(member)
        chunks = self._iter_chunks(info)
        # Run the bounds check before creating the output file.
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
        selected = []
        for info in self.files:
            if glob and not fnmatch.fnmatch(info.file_name, glob):
                continue
            parts = _safe_parts(info.file_name)
            if parts is None:
                raise ValueError(f"Refusing to extract RPA member with unsafe name: {info.file_name!r}")
            selected.append((info, parts))

        for info, parts in selected:
            filepath = os.path.abspath(os.path.join(path, *parts))
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            self.extract(info, filepath)

    # -- creation --------------------------------------------------------------

    def write(self, filepath: str | os.PathLike, arcname: str | None = None):
        """Add the file at *filepath* to the archive.

        *arcname* is the name stored in the archive.  It defaults to the
        basename of *filepath*.
        """
        if self.fp is None:
            raise ValueError("I/O operation on closed RPA archive")
        if self.mode != 'w':
            raise ValueError("write() requires mode='w'")

        filepath = os.fspath(filepath)
        name = (arcname if arcname is not None else os.path.basename(filepath)).replace('\\', '/')
        if name in self._by_name:
            raise ValueError(f"Duplicate RPA member name: {name!r}")

        offset = self.fp.tell()
        with open(filepath, 'rb') as source:
            shutil.copyfileobj(source, self.fp, _CHUNK_SIZE)
        length = self.fp.tell() - offset

        info = RPAInfo(name, [RPASegment(offset, length, b'')])
        self.files.append(info)
        self._by_name[name] = info
        logger.debug('packed %s: offset=%#x size=%#x', name, offset, length)

    def write_all(self, path: str | os.PathLike, glob: str | None = None, prefix: str = ''):
        """Recursively add the files in directory *path* to the archive."""
        if self.fp is None:
            raise ValueError("I/O operation on closed RPA archive")
        output = os.fstat(self.fp.fileno())
        for entry in sorted(pathlib.Path(path).iterdir()):
            if entry.is_dir():
                self.write_all(entry, glob=glob, prefix=f'{prefix}{entry.name}/')
            elif entry.is_file():
                # Never pack the archive into itself: the copy would never reach the end of the file.
                if os.path.samestat(output, entry.stat()):
                    continue
                arcname = prefix + entry.name
                if glob and not fnmatch.fnmatch(arcname, glob):
                    continue
                self.write(entry, arcname=arcname)

    def _finalize(self):
        """Write the index, then fill in the header reserved when the archive was opened."""
        if self.fp is None:
            raise ValueError("I/O operation on closed RPA archive")
        # Two-element entries at protocol 2 pickle without any globals, so every
        # Ren'Py version can load them, Python 2 builds included.
        index = {
            info.file_name: [(s.offset ^ self.key, s.length ^ self.key) for s in info.segments] for info in self.files
        }
        index_offset = self.fp.tell()
        self.fp.write(zlib.compress(pickle.dumps(index, 2)))
        self.fp.seek(0)
        self.fp.write(b'%s%016x %08x\n' % (RPA3_MAGIC, index_offset, self.key))
