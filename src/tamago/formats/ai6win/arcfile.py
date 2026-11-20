"""Reader and writer for AI6WIN ``.arc`` resource archives (elf, Silky's).

An archive is a little-endian u32 member count, a table of fixed 0x110-byte
entries, and the members' data packed back to back in index order.  Each entry
holds a 260-byte cp932 name, obfuscated by adding ``len + 1 - i`` to byte
``i``, then three **big-endian** u32s: stored size, unpacked size and absolute
offset.  A member is LZSS-compressed exactly when the two sizes differ.

There is no signature, so archives are recognised by their structure
(:func:`is_ai6win_arc`).  The games' indexes are not sorted, so extraction
writes a manifest (:data:`MANIFEST_NAME`) recording the order, each member's
compression and any name bytes that cp932 cannot reproduce;
:meth:`ARCFile.write_all` follows it, rebuilding the original archive byte for
byte.
"""

import fnmatch
import json
import logging
import os
import pathlib
import shutil
import struct
from typing import BinaryIO

from construct import Bytes, Int32ub, Struct

from tamago.formats.ai6win import lzss
from tamago.formats.member_paths import member_path, plan_extraction

logger = logging.getLogger(__name__)

MANIFEST_NAME = '_ai6win_manifest.json'
MANIFEST_FORMAT = 'ai6win'

NAME_SIZE = 0x104
Entry = Struct(
    'name' / Bytes(NAME_SIZE),
    'size' / Int32ub,
    'unpacked_size' / Int32ub,
    'offset' / Int32ub,
)
ENTRY_SIZE = Entry.sizeof()
HEADER_SIZE = 4
MAX_U32 = 0xFFFFFFFF

# Member types the games' packer compressed; everything else (audio, video,
# AKB images) was stored.
COMPRESSED_EXTENSIONS = frozenset(('.mes', '.lib', '.area', '.ax', '.bin', '.mov'))


def should_compress(name: str) -> bool:
    """Return True if a member called *name* is compressed by default."""
    return os.path.splitext(name)[1].lower() in COMPRESSED_EXTENSIONS


def decode_name(field: bytes) -> bytes:
    """Return the plain name bytes held in an obfuscated name *field*."""
    end = field.find(b'\0')
    if end < 0:
        end = len(field)
    key = end + 1
    return bytes((c - key + i) & 0xFF for i, c in enumerate(field[:end]))


def encode_name(name: bytes) -> bytes:
    """Return the NUL-padded, obfuscated name field for the name bytes *name*."""
    if not name or b'\0' in name:
        raise ValueError(f"AI6WIN member name {name!r} must be non-empty, without NULs")
    if len(name) >= NAME_SIZE:
        raise ValueError(f"AI6WIN member name {name!r} must be at most {NAME_SIZE - 1} bytes")
    key = len(name) + 1
    stored = bytes((c + key - i) & 0xFF for i, c in enumerate(name))
    if b'\0' in stored:
        # The reader would take the zero byte for the end of the name.
        raise ValueError(f"AI6WIN member name {name!r} cannot be stored: it obfuscates to a NUL byte")
    return stored.ljust(NAME_SIZE, b'\0')


class ARCInfo:
    """Metadata for one member of an AI6WIN archive."""

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
        raise ValueError("File too small to be an AI6WIN archive")
    (count,) = struct.unpack('<I', head)
    index_end = HEADER_SIZE + count * ENTRY_SIZE
    if index_end > file_size:
        raise ValueError(f"AI6WIN index of {count} entries does not fit in the file")
    index = fp.read(index_end - HEADER_SIZE)

    infos = []
    for i in range(count):
        entry = Entry.parse(index[i * ENTRY_SIZE : (i + 1) * ENTRY_SIZE])
        raw_name = decode_name(entry.name)
        if not raw_name:
            raise ValueError(f"AI6WIN entry {i} has an empty name")
        try:
            name = raw_name.decode('cp932')
        except UnicodeDecodeError:
            raise ValueError(f"AI6WIN entry {i} has a name that is not cp932: {raw_name!r}") from None
        if entry.offset < index_end or entry.offset + entry.size > file_size:
            raise ValueError(f"AI6WIN member {name!r} lies outside the archive's data")
        infos.append(ARCInfo(name, raw_name, entry.offset, entry.size, entry.unpacked_size))
    return infos


def is_ai6win_arc(path: str | os.PathLike) -> bool:
    """Return True if the file at *path* has the structure of an AI6WIN archive."""
    try:
        with open(path, 'rb') as fp:
            infos = _read_index(fp, os.fstat(fp.fileno()).st_size)
    except (OSError, ValueError):
        return False
    # Names are file names: control characters mean this is something else.
    return bool(infos) and not any(c < ' ' or c == '\x7f' for info in infos for c in info.file_name)


class _Pending:
    __slots__ = ('source', 'raw_name', 'compress')

    def __init__(self, source: str, raw_name: bytes, compress: bool):
        self.source = source
        self.raw_name = raw_name
        self.compress = compress


class ARCFile:
    """Read or create an AI6WIN archive.

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
            raise ValueError("I/O operation on closed AI6WIN archive")
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

    def extract(self, member: 'ARCInfo | str', path: str | os.PathLike):
        """Write the contents of *member* to a new file at *path*."""
        data = self.read(member)
        with open(path, 'xb') as f:
            f.write(data)

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
            self.extract(info, filepath)
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
            raise ValueError("I/O operation on closed AI6WIN archive")
        if self.mode != 'w':
            raise ValueError("writing requires mode='w'")

    def write(
        self,
        filepath: str | os.PathLike,
        arcname: str | None = None,
        compress: bool | None = None,
        raw_name: bytes | None = None,
    ):
        """Add the file at *filepath* as a member.

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
                raise ValueError(f"AI6WIN member name {name!r} cannot be encoded as cp932") from None
        encode_name(raw_name)  # validate now rather than when the archive is closed
        if self.compress is not None:
            compress = self.compress
        elif compress is None:
            compress = should_compress(raw_name.decode('cp932', 'replace'))
        self._pending.append(_Pending(filepath, raw_name, compress))

    def write_all(self, path: str | os.PathLike, glob: str | None = None):
        """Add the files under directory *path*, following its manifest if it has one.

        Members listed in the manifest come first, in its order, with their
        recorded names and compression.  Other files follow, sorted by their
        path relative to *path*, which (with ``/`` separators) becomes their
        name.  *glob* matches member names.
        """
        self._check_writable()
        assert self.fp is not None
        root = pathlib.Path(path)
        output = os.fstat(self.fp.fileno())
        manifest_path = root / MANIFEST_NAME
        listed: set[str] = set()

        if manifest_path.is_file():
            for entry in self._read_manifest(manifest_path):
                source = member_path(root, entry['name'])
                listed.add(os.path.normcase(source))
                if glob and not fnmatch.fnmatch(entry['name'], glob):
                    continue
                if not os.path.isfile(source):
                    raise ValueError(f"The manifest lists {entry['name']!r}, which is missing from {root}")
                self.write(source, compress=entry['compressed'], raw_name=entry['raw_name'])

        others = []
        for dirpath, dirs, files in os.walk(root):
            dirs.sort()
            for file_name in files:
                source = os.path.join(dirpath, file_name)
                name = pathlib.Path(source).relative_to(root).as_posix()
                if name == MANIFEST_NAME or os.path.normcase(os.path.abspath(source)) in listed:
                    continue
                if os.path.samestat(output, os.stat(source)):
                    continue
                if glob and not fnmatch.fnmatch(name, glob):
                    continue
                others.append((name, source))
        for name, source in sorted(others):
            self.write(source, arcname=name)

    @staticmethod
    def _read_manifest(manifest_path: pathlib.Path) -> list[dict]:
        try:
            with open(manifest_path, encoding='utf-8') as f:
                manifest = json.load(f)
            if manifest.get('format') != MANIFEST_FORMAT:
                raise ValueError(f"not an {MANIFEST_FORMAT} manifest")
            members = []
            for m in manifest['members']:
                name = m['name']
                if not isinstance(name, str) or not isinstance(m['compressed'], bool):
                    raise ValueError(f"bad member entry {m!r}")
                raw = bytes.fromhex(m['name_hex']) if 'name_hex' in m else name.encode('cp932')
                members.append({'name': name, 'raw_name': raw, 'compressed': m['compressed']})
        except (OSError, KeyError, TypeError, ValueError, AttributeError) as e:
            raise ValueError(f"Invalid AI6WIN manifest {manifest_path}: {e}") from None
        return members

    def _finalize(self):
        """Write the index and member data.

        Stored members are copied straight from their files, so large audio
        archives are never held in memory; compressed members are compressed
        one at a time.
        """
        assert self.fp is not None
        fp = self.fp
        count = len(self._pending)
        index_end = HEADER_SIZE + count * ENTRY_SIZE
        fp.write(struct.pack('<I', count))
        fp.write(bytes(count * ENTRY_SIZE))

        entries = []
        offset = index_end
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
                raise ValueError("AI6WIN archives cannot exceed 4 GiB")
            entries.append(
                Entry.build(
                    {'name': encode_name(p.raw_name), 'size': size, 'unpacked_size': unpacked_size, 'offset': offset}
                )
            )
            logger.debug('wrote %r at %#x: size=%d unpacked=%d', p.raw_name, offset, size, unpacked_size)
            offset += size

        fp.seek(HEADER_SIZE)
        fp.write(b''.join(entries))
