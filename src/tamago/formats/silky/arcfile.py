"""Reader and writer for Silky's ``.arc`` resource archives (length-prefixed names).

Used by Silky's Sakura's games (``Script.arc``, ``data.arc``, ``layer.arc``,
...), this is a relative of the AI6WIN archive (:mod:`tamago.formats.ai6win`)
with variable-length index entries.  An archive is a little-endian u32 index
size, then entries until that many bytes are consumed, then the members' data
packed back to back in index order.  Each entry is a u8 name length, the cp932
name obfuscated by subtracting ``len - i`` from byte ``i``, and three
**big-endian** u32s: stored size, unpacked size and absolute offset.  A member
is compressed with Okumura's LZSS exactly when the two sizes differ.

There is no signature, so archives are recognised by their structure
(:func:`is_silky_arc`).  Extraction writes a manifest (:data:`MANIFEST_NAME`)
recording the members' order and compression, and any name bytes cp932 cannot
reproduce; :meth:`ARCFile.write_all` follows it, rebuilding an unmodified
archive byte for byte.
"""

import fnmatch
import io
import json
import logging
import os
import pathlib
import shutil
import struct
from typing import BinaryIO

from construct import GreedyBytes, Int8ub, Int32ub, Prefixed, StreamError, Struct

from tamago.formats.ai6win import lzss
from tamago.formats.member_paths import member_path, plan_extraction

logger = logging.getLogger(__name__)

MANIFEST_NAME = '_silky_manifest.json'
MANIFEST_FORMAT = 'silky'

MAX_NAME_SIZE = 0xFF
Entry = Struct(
    'name' / Prefixed(Int8ub, GreedyBytes),
    'size' / Int32ub,
    'unpacked_size' / Int32ub,
    'offset' / Int32ub,
)
HEADER_SIZE = 4
MAX_U32 = 0xFFFFFFFF

# Member types the games' packer compressed; everything else (audio, AKB
# images) was stored.
COMPRESSED_EXTENSIONS = frozenset(('.mes', '.lib', '.bin', '.area', '.brt'))


def should_compress(name: str) -> bool:
    """Return True if a member called *name* is compressed by default."""
    return os.path.splitext(name)[1].lower() in COMPRESSED_EXTENSIONS


def decode_name(stored: bytes) -> bytes:
    """Return the plain name bytes for the obfuscated name *stored*."""
    n = len(stored)
    return bytes((c + n - i) & 0xFF for i, c in enumerate(stored))


def encode_name(name: bytes) -> bytes:
    """Return the obfuscated form of the name bytes *name*."""
    if not name or b'\0' in name:
        raise ValueError(f"Silky's member name {name!r} must be non-empty, without NULs")
    n = len(name)
    if n > MAX_NAME_SIZE:
        raise ValueError(f"Silky's member name {name!r} must be at most {MAX_NAME_SIZE} bytes")
    return bytes((c - n + i) & 0xFF for i, c in enumerate(name))


class ARCInfo:
    """Metadata for one member of a Silky's archive."""

    __slots__ = ('file_name', 'raw_name', 'offset', 'size', 'unpacked_size')

    def __init__(self, file_name: str, raw_name: bytes, offset: int, size: int, unpacked_size: int):
        self.file_name = file_name
        self.raw_name = raw_name
        self.offset = offset
        self.size = size
        self.unpacked_size = unpacked_size

    @property
    def compressed(self) -> bool:
        return self.size != self.unpacked_size

    def __repr__(self):
        return (
            f"ARCInfo(file_name={self.file_name!r}, offset={self.offset:#x}, "
            f"size={self.size}, unpacked_size={self.unpacked_size})"
        )


def _read_index(fp: BinaryIO, file_size: int) -> list[ARCInfo]:
    """Parse the index of the archive open as *fp*, raising ValueError if it is not one."""
    head = fp.read(HEADER_SIZE)
    if len(head) < HEADER_SIZE:
        raise ValueError("File too small to be a Silky's archive")
    (index_size,) = struct.unpack('<I', head)
    data_start = HEADER_SIZE + index_size
    if data_start > file_size:
        raise ValueError(f"Silky's index of {index_size} bytes does not fit in the file")
    index = io.BytesIO(fp.read(index_size))

    infos = []
    while index.tell() < index_size:
        start = index.tell()
        try:
            entry = Entry.parse_stream(index)
        except StreamError:
            raise ValueError(f"Silky's index entry at {HEADER_SIZE + start:#x} runs past the index") from None
        if not entry.name:
            raise ValueError(f"Silky's index entry at {HEADER_SIZE + start:#x} has an empty name")
        raw_name = decode_name(entry.name)
        try:
            name = raw_name.decode('cp932')
        except UnicodeDecodeError:
            raise ValueError(f"Silky's member name is not cp932: {raw_name!r}") from None
        if entry.offset < data_start or entry.offset + entry.size > file_size:
            raise ValueError(f"Silky's member {name!r} lies outside the archive's data")
        infos.append(ARCInfo(name, raw_name, entry.offset, entry.size, entry.unpacked_size))
    return infos


def is_silky_arc(path: str | os.PathLike) -> bool:
    """Return True if the file at *path* has the structure of a Silky's archive.

    Besides parsing cleanly, the index must describe at least one member, with
    names free of control characters, and the data must start right after it.
    """
    try:
        with open(path, 'rb') as fp:
            infos = _read_index(fp, os.fstat(fp.fileno()).st_size)
            data_start = fp.tell()
    except (OSError, ValueError):
        return False
    if not infos or min(info.offset for info in infos) != data_start:
        return False
    return not any(c < ' ' or c == '\x7f' for info in infos for c in info.file_name)


class _Pending:
    __slots__ = ('source', 'raw_name', 'compress')

    def __init__(self, source: str, raw_name: bytes, compress: bool):
        self.source = source
        self.raw_name = raw_name
        self.compress = compress


class ARCFile:
    """Read or create a Silky's archive.

    Use ``mode='r'`` (default) to read an existing archive, or ``mode='w'``
    to create one; it is written when the archive is closed.  In write mode,
    *compress* forces every member to be compressed (True) or stored (False);
    by default each member follows the manifest, or else its extension
    (:data:`COMPRESSED_EXTENSIONS`).
    """

    def __init__(self, file: str | os.PathLike, mode: str = 'r', compress: bool | None = None):
        self.fp: BinaryIO | None = None
        if mode not in ('r', 'w'):
            raise ValueError(f"Invalid mode: {mode!r} (expected 'r' or 'w')")
        self.filename = os.fspath(file)
        self.mode = mode
        self.compress = compress
        self.files: list[ARCInfo] = []
        self._pending: list[_Pending] = []

        if mode == 'r':
            fp = open(self.filename, 'rb')
            try:
                self.files = _read_index(fp, os.fstat(fp.fileno()).st_size)
            except Exception:
                fp.close()
                raise
            self.fp = fp
        else:
            self.fp = open(self.filename, 'wb')

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
        fp = self.fp
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
            raise ValueError("I/O operation on closed Silky's archive")
        if self.mode != 'r':
            raise ValueError("reading requires mode='r'")

    def namelist(self) -> list[str]:
        return [info.file_name for info in self.files]

    def getinfo(self, name: str) -> ARCInfo:
        for info in self.files:
            if info.file_name == name:
                return info
        raise KeyError(f"No member named {name!r}")

    def read(self, member: 'ARCInfo | str') -> bytes:
        """Return the contents of *member* (an :class:`ARCInfo` or a name), decompressed."""
        self._check_readable()
        assert self.fp is not None
        info = member if isinstance(member, ARCInfo) else self.getinfo(member)
        self.fp.seek(info.offset)
        data = self.fp.read(info.size)
        if info.compressed:
            return lzss.decompress(data, info.unpacked_size)
        return data

    def extract(self, member: 'ARCInfo | str', path: str | os.PathLike) -> str:
        """Write the contents of *member* to a new file at *path*, returning the path written."""
        data = self.read(member)
        path = os.fspath(path)
        with open(path, 'xb') as f:
            f.write(data)
        return path

    def extract_all(self, path: str | os.PathLike, glob: str | None = None):
        """Extract members to directory *path*, with a manifest of their order and compression.

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
        members = []
        for info, filepath in plan:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, 'xb') as f:
                f.write(self.read(info))
            members.append(self._manifest_entry(info))
        with open(manifest_path, 'x', encoding='utf-8') as f:
            json.dump({'format': MANIFEST_FORMAT, 'members': members}, f, ensure_ascii=False, indent=1)
            f.write('\n')

    @staticmethod
    def _manifest_entry(info: ARCInfo) -> dict:
        entry: dict = {'name': info.file_name, 'compressed': info.compressed}
        try:
            exact = info.file_name.encode('cp932') == info.raw_name
        except UnicodeEncodeError:
            exact = False
        if not exact:
            entry['name_hex'] = info.raw_name.hex()
        return entry

    # -- creation --------------------------------------------------------------

    def _check_writable(self):
        if self.fp is None:
            raise ValueError("I/O operation on closed Silky's archive")
        if self.mode != 'w':
            raise ValueError("writing requires mode='w'")

    def write(
        self,
        filepath: str | os.PathLike,
        arcname: str | None = None,
        compress: bool | None = None,
        raw_name: bytes | None = None,
    ):
        """Add the file at *filepath* as a member, after those already added.

        The member is named *arcname* (default: the file's base name), or
        stored with the exact name bytes *raw_name*.  It is compressed if
        *compress* is True; the archive's own *compress* setting overrides
        this, and if neither is given the member's extension decides.
        """
        self._check_writable()
        filepath = os.fspath(filepath)
        if raw_name is None:
            name = arcname if arcname is not None else os.path.basename(filepath)
            try:
                raw_name = name.encode('cp932')
            except UnicodeEncodeError:
                raise ValueError(f"Silky's member name {name!r} cannot be encoded as cp932") from None
        encode_name(raw_name)  # validate now rather than when the archive is closed
        if self.compress is not None:
            compress = self.compress
        elif compress is None:
            compress = should_compress(raw_name.decode('cp932', 'replace'))
        self._pending.append(_Pending(filepath, raw_name, compress))

    def write_all(self, path: str | os.PathLike, glob: str | None = None):
        """Add the files under directory *path*, following its manifest if it has one.

        Members listed in the manifest keep their recorded names, order and
        compression.  Other files are named by their path relative to *path*
        (with ``/`` separators).  The games' indexes are sorted by name bytes,
        so if the manifest's order is sorted (or there is no manifest), every
        member is written in that order and new files take their sorted
        places; otherwise new files follow the listed ones, sorted.  *glob*
        matches member names.
        """
        self._check_writable()
        assert self.fp is not None
        root = pathlib.Path(path)
        output = os.fstat(self.fp.fileno())
        manifest_path = root / MANIFEST_NAME
        listed_paths: set[str] = set()
        listed: list[tuple[bytes, str, bool | None]] = []

        if manifest_path.is_file():
            for entry in self._read_manifest(manifest_path):
                source = member_path(root, entry['name'])
                listed_paths.add(os.path.normcase(source))
                if glob and not fnmatch.fnmatch(entry['name'], glob):
                    continue
                if not os.path.isfile(source):
                    raise ValueError(f"The manifest lists {entry['name']!r}, which is missing from {root}")
                listed.append((entry['raw_name'], source, entry['compressed']))

        others: list[tuple[bytes, str, bool | None]] = []
        for dirpath, dirs, files in os.walk(root):
            dirs.sort()
            for file_name in files:
                source = os.path.join(dirpath, file_name)
                name = pathlib.Path(source).relative_to(root).as_posix()
                if name == MANIFEST_NAME or os.path.normcase(os.path.abspath(source)) in listed_paths:
                    continue
                if os.path.samestat(output, os.stat(source)):
                    continue
                if glob and not fnmatch.fnmatch(name, glob):
                    continue
                try:
                    raw = name.encode('cp932')
                except UnicodeEncodeError:
                    raise ValueError(f"Silky's member name {name!r} cannot be encoded as cp932") from None
                others.append((raw, source, None))
        others.sort()

        raw_names = [raw for raw, _source, _compress in listed]
        if raw_names == sorted(raw_names):
            members = sorted(listed + others, key=lambda m: m[0])
        else:
            members = listed + others
        for raw, source, compress in members:
            self.write(source, compress=compress, raw_name=raw)

    @staticmethod
    def _read_manifest(manifest_path: pathlib.Path) -> list[dict]:
        try:
            with open(manifest_path, encoding='utf-8') as f:
                manifest = json.load(f)
            if manifest.get('format') != MANIFEST_FORMAT:
                raise ValueError(f"not a {MANIFEST_FORMAT} manifest")
            members = []
            for m in manifest['members']:
                name = m['name']
                if not isinstance(name, str) or not isinstance(m['compressed'], bool):
                    raise ValueError(f"bad member entry {m!r}")
                raw = bytes.fromhex(m['name_hex']) if 'name_hex' in m else name.encode('cp932')
                members.append({'name': name, 'raw_name': raw, 'compressed': m['compressed']})
        except (OSError, KeyError, TypeError, ValueError, AttributeError) as e:
            raise ValueError(f"Invalid Silky's manifest {manifest_path}: {e}") from None
        return members

    def _finalize(self):
        """Write the index and member data.

        Stored members are copied straight from their files, so large voice
        archives are never held in memory; compressed members are processed
        one at a time.
        """
        assert self.fp is not None
        fp = self.fp
        index_size = sum(1 + len(p.raw_name) + 12 for p in self._pending)
        data_start = HEADER_SIZE + index_size
        fp.write(struct.pack('<I', index_size))
        fp.write(bytes(index_size))

        entries = []
        offset = data_start
        for p in self._pending:
            if p.compress:
                with open(p.source, 'rb') as f:
                    data = f.read()
                packed = lzss.compress(data)
                # Equal sizes would read back as a stored member.
                stored = packed if len(packed) != len(data) else data
                fp.write(stored)
                size, unpacked_size = len(stored), len(data)
            else:
                with open(p.source, 'rb') as f:
                    shutil.copyfileobj(f, fp)
                size = unpacked_size = fp.tell() - offset
            if offset + size > MAX_U32:
                raise ValueError("Silky's archives cannot exceed 4 GiB")
            entries.append(
                Entry.build(
                    {'name': encode_name(p.raw_name), 'size': size, 'unpacked_size': unpacked_size, 'offset': offset}
                )
            )
            logger.debug('wrote %r at %#x: size=%d unpacked=%d', p.raw_name, offset, size, unpacked_size)
            offset += size

        fp.seek(HEADER_SIZE)
        fp.write(b''.join(entries))
