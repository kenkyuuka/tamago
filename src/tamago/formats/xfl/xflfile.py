"""Reader and writer for Liar-soft / RScript XFL resource archives.

An XFL archive is a flat, uncompressed bundle:

- A 12-byte header (see :data:`XFLHeader`): magic ``LB\\x01\\x00``, the index
  size in bytes, and the entry count.
- *count* fixed-size 40-byte index entries (see :data:`XFLEntry`): a
  NUL-padded CP932 name and the member's offset and size.
- Member data, concatenated in index order, starting right after the index.
  Offsets are relative to the start of the data.

A member named ``X.xfl`` that is itself an XFL archive is a nested archive,
which the engine addresses as directory ``X``.  Nested archives are presented
as directories here: their members appear as ``X/name`` and are extracted to
``X/`` and rebuilt from it.

The engine finds members by binary search with ``lstrcmpiA``, so the writer
sorts every index with :func:`~tamago.formats.xfl.collation.lstrcmpi_key`.
"""

import fnmatch
import logging
import os
import pathlib
import shutil
from typing import BinaryIO

from construct import Bytes, Const, Int32ul, Struct

from tamago.formats.xfl.collation import lstrcmpi_key

logger = logging.getLogger(__name__)

XFL_MAGIC = b'LB\x01\x00'
NESTED_EXTENSION = '.xfl'
NAME_SIZE = 32
MAX_NAME_BYTES = NAME_SIZE
MAX_U32 = 0xFFFFFFFF

XFLHeader = Struct(
    "magic" / Const(XFL_MAGIC),
    "index_size" / Int32ul,
    "count" / Int32ul,
)

XFLEntry = Struct(
    "name" / Bytes(NAME_SIZE),
    "offset" / Int32ul,
    "size" / Int32ul,
)

HEADER_SIZE = XFLHeader.sizeof()
ENTRY_SIZE = XFLEntry.sizeof()


def encode_name(name: str) -> bytes:
    """Encode a single member name for the index, validating it."""
    try:
        encoded = name.encode('cp932')
    except UnicodeEncodeError as e:
        raise ValueError(f"Member name {name!r} cannot be encoded as CP932") from e
    if not encoded or b'\x00' in encoded:
        raise ValueError(f"Invalid member name {name!r}")
    if len(encoded) > MAX_NAME_BYTES:
        raise ValueError(f"Member name {name!r} is too long ({len(encoded)} bytes, max {MAX_NAME_BYTES})")
    return encoded


def _warn_if_unterminated(name: str, encoded: bytes):
    # A name filling the whole field has no NUL terminator.  Such names occur
    # in shipped archives, but the engine's lstrcmpiA lookup reads past the
    # field, so the member cannot be found in-game.
    if len(encoded) == NAME_SIZE:
        logger.warning(
            'Member name %r fills all %d bytes (no NUL terminator); the engine cannot look it up', name, NAME_SIZE
        )


class XFLInfo:
    """Metadata for a single member of an XFL archive."""

    __slots__ = ('file_name', 'offset', 'size')

    def __init__(self, file_name: str = '', offset: int = 0, size: int = 0):
        self.file_name = file_name
        self.offset = offset
        self.size = size

    def __repr__(self):
        return f"XFLInfo(file_name={self.file_name!r}, offset={self.offset!r}, size={self.size!r})"


class _Node:
    """A level of the archive tree being written.

    Children are keyed by case-folded name (the engine compares names
    case-insensitively) and hold the stored name and either a source file
    path or a nested node.
    """

    def __init__(self):
        self.children: dict[str, tuple[str, str | _Node]] = {}

    def size(self) -> int:
        return HEADER_SIZE + ENTRY_SIZE * len(self.children) + sum(_size(c) for _, c in self.children.values())


def _size(child: 'str | _Node') -> int:
    return child.size() if isinstance(child, _Node) else os.path.getsize(child)


class XFLFile:
    """Read or create XFL archives.

    Reading::

        with XFLFile('voice.xfl') as xfl:
            for info in xfl.files:
                print(info.file_name)
            xfl.extract_all('/output/dir')

    Writing::

        with XFLFile('voice.xfl', mode='w') as xfl:
            xfl.write_all('/source/dir')

    Subdirectories of the source become nested ``.xfl`` archives.
    """

    fp: BinaryIO | None = None

    def __init__(self, file, mode='r'):
        if isinstance(file, os.PathLike):
            file = os.fspath(file)

        if mode not in ('r', 'w'):
            raise ValueError(f"Invalid mode: {mode!r} (expected 'r' or 'w')")

        self.filename = file
        self.mode = mode
        self.files: list[XFLInfo] = []
        # Directory names of nested archives, in index order (including empty ones).
        self.archives: list[str] = []

        if mode == 'r':
            self.fp = open(file, 'rb')
            try:
                self.fp.seek(0, 2)
                self._read_index(0, self.fp.tell(), '')
            except Exception:
                fp = self.fp
                self.fp = None
                fp.close()
                raise
        else:
            self.fp = open(file, 'wb')
            self._root = _Node()

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
                self._write_node(self._root)
        finally:
            fp = self.fp
            self.fp = None
            fp.close()

    def _open_fp(self) -> BinaryIO:
        if self.fp is None:
            raise ValueError("I/O operation on closed XFL archive")
        return self.fp

    # -- reading ---------------------------------------------------------------

    def _parse_index(self, base: int, end: int) -> list[tuple[str, int, int]]:
        """Parse the index of the archive occupying ``[base, end)``.

        Returns (name, absolute offset, size) tuples.  Raises ``ValueError``
        if the archive is malformed.
        """
        fp = self._open_fp()
        fp.seek(base)
        raw = fp.read(HEADER_SIZE)
        if len(raw) < HEADER_SIZE or base + HEADER_SIZE > end:
            raise ValueError("File too small to be an XFL archive")
        if raw[: len(XFL_MAGIC)] != XFL_MAGIC:
            raise ValueError("Not an XFL archive (bad magic)")
        header = XFLHeader.parse(raw)

        # The engine ignores index_size and starts the data right after the index.
        data_base = base + HEADER_SIZE + ENTRY_SIZE * header.count
        if data_base > end:
            raise ValueError("Truncated XFL index")
        if header.index_size != ENTRY_SIZE * header.count:
            logger.warning('XFL index_size %d does not match count %d; using count', header.index_size, header.count)

        raw = fp.read(ENTRY_SIZE * header.count)
        entries = []
        for i in range(header.count):
            entry = XFLEntry.parse(raw[i * ENTRY_SIZE : (i + 1) * ENTRY_SIZE])
            name = entry.name.split(b'\x00', 1)[0].decode('cp932')
            offset = data_base + entry.offset
            if offset + entry.size > end:
                raise ValueError(f"XFL member {name!r} extends past the end of the archive")
            entries.append((name, offset, entry.size))
        return entries

    def _read_index(self, base: int, end: int, prefix: str):
        for name, offset, size in self._parse_index(base, end):
            if name.lower().endswith(NESTED_EXTENSION):
                dirname = prefix + name[: -len(NESTED_EXTENSION)]
                try:
                    nested = self._parse_index(offset, offset + size)
                except ValueError:
                    nested = None
                if nested is not None:
                    self.archives.append(dirname)
                    self._read_index(offset, offset + size, dirname + '/')
                    continue
            self.files.append(XFLInfo(prefix + name, offset, size))

    def _find(self, member: 'XFLInfo | str') -> XFLInfo:
        if isinstance(member, XFLInfo):
            return member
        for f in self.files:
            if f.file_name == member:
                return f
        raise KeyError(f"No member named {member!r}")

    def read(self, member: 'XFLInfo | str') -> bytes:
        """Read the contents of *member* (an :class:`XFLInfo` or a name)."""
        fp = self._open_fp()
        member = self._find(member)
        fp.seek(member.offset)
        return fp.read(member.size)

    def extract(self, member: 'XFLInfo | str', path: str | os.PathLike):
        """Extract *member* to a file at *path*."""
        data = self.read(member)
        with open(path, 'xb') as f:
            f.write(data)

    def extract_all(self, path: str | os.PathLike, glob: str | None = None):
        """Extract all members to directory *path*.

        Nested archives are extracted as subdirectories.  If *glob* is given,
        only members whose names match the pattern are extracted.
        """
        root = os.path.abspath(path)

        def target(name: str) -> str:
            # Names come from the archive; refuse any that resolve outside the output directory.
            resolved = os.path.abspath(os.path.join(root, *name.split('/')))
            if os.path.commonpath([root, resolved]) != root or resolved == root:
                raise ValueError(f"Member {name!r} would be extracted outside {root!r}")
            return resolved

        if glob is None:
            for dirname in self.archives:
                os.makedirs(target(dirname), exist_ok=True)
        for f in self.files:
            if glob and not fnmatch.fnmatch(f.file_name, glob):
                continue
            filepath = target(f.file_name)
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            self.extract(f, filepath)

    # -- creation --------------------------------------------------------------

    def _check_writable(self):
        if self.fp is None:
            raise ValueError("I/O operation on closed XFL archive")
        if self.mode != 'w':
            raise ValueError("write() requires mode='w'")

    def _node_for(self, dirs: list[str]) -> _Node:
        """Return the tree node for nested directory path *dirs*, creating it if needed."""
        node = self._root
        for dirname in dirs:
            name = dirname + NESTED_EXTENSION
            encoded = encode_name(name)
            existing = node.children.get(name.lower())
            if existing is None:
                _warn_if_unterminated(name, encoded)
                child = _Node()
                node.children[name.lower()] = (name, child)
            elif isinstance(existing[1], _Node):
                child = existing[1]
            else:
                raise ValueError(f"Nested archive {dirname!r} collides with a member named {existing[0]!r}")
            node = child
        return node

    def write(self, filepath: str | os.PathLike, arcname: str | None = None):
        """Queue *filepath* for inclusion in the archive.

        *arcname* defaults to the basename of *filepath*.  Directory
        components (``/`` or ``\\``) place the member in nested archives.
        Names are compared case-insensitively, as the engine does.
        """
        self._check_writable()
        filepath = os.fspath(filepath)
        if arcname is None:
            arcname = os.path.basename(filepath)
        parts = arcname.replace('\\', '/').split('/')
        if any(not p for p in parts):
            raise ValueError(f"Invalid member name {arcname!r}")
        name = parts[-1]
        encoded = encode_name(name)

        node = self._node_for(parts[:-1])
        existing = node.children.get(name.lower())
        if existing is not None:
            if isinstance(existing[1], _Node):
                raise ValueError(f"Member {arcname!r} collides with nested archive {existing[0]!r}")
            raise ValueError(f"duplicate member name {arcname!r}")
        _warn_if_unterminated(arcname, encoded)
        node.children[name.lower()] = (name, filepath)

    def write_all(self, path: str | os.PathLike, glob: str | None = None, prefix: str = ''):
        """Recursively add files from directory *path* to the archive.

        Subdirectories become nested archives.  If *glob* is given, only files
        whose archive names match the pattern are added, and empty
        directories are skipped.
        """
        self._check_writable()
        path = pathlib.Path(path)
        if prefix and glob is None:
            self._node_for(prefix.rstrip('/').split('/'))
        for entry in sorted(path.iterdir()):
            if entry.is_dir():
                self.write_all(entry, glob=glob, prefix=prefix + entry.name + '/')
            elif entry.is_file():
                arcname = prefix + entry.name
                if glob and not fnmatch.fnmatch(arcname, glob):
                    continue
                self.write(entry, arcname=arcname)

    def _write_node(self, node: _Node):
        """Write the archive for *node* at the current file position."""
        fp = self._open_fp()
        entries = sorted(node.children.values(), key=lambda e: lstrcmpi_key(e[0]))
        sizes = [_size(child) for _, child in entries]
        if sum(sizes) > MAX_U32:
            raise ValueError("XFL archive data exceeds 4 GiB")

        fp.write(XFLHeader.build({'index_size': ENTRY_SIZE * len(entries), 'count': len(entries)}))
        offset = 0
        for (name, _child), size in zip(entries, sizes, strict=True):
            raw_name = encode_name(name).ljust(NAME_SIZE, b'\x00')
            fp.write(XFLEntry.build({'name': raw_name, 'offset': offset, 'size': size}))
            offset += size
        for (_name, child), size in zip(entries, sizes, strict=True):
            if isinstance(child, _Node):
                self._write_node(child)
            else:
                with open(child, 'rb') as f:
                    shutil.copyfileobj(f, fp)
                    if f.tell() != size:
                        raise ValueError(f"{child} changed size while writing the archive")
