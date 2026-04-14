"""Reader and writer for μ-GameOperationSystem DET resource archives.

A DET archive consists of three companion files:

- ``.det`` — the data file containing packed file contents, followed by
  a 4-byte trailer.
- ``.nme`` — null-terminated file names (Shift-JIS encoded), followed by
  a 4-byte trailer.
- ``.atm`` or ``.at2`` — the index, with 0x10- or 0x14-byte entries
  (see :data:`ATMEntry`, :data:`AT2Entry`), followed by a 4-byte trailer.

Some games use the ``.atm`` extension for files that are actually in AT2
format.  The :func:`parse_index` function handles this automatically.
"""

import fnmatch
import logging
import os
import pathlib

from construct import Bytes, GreedyRange, Int32sl, Int32ul, Struct, Terminated

logger = logging.getLogger(__name__)

ATMEntry = Struct(
    "name_offset" / Int32sl,
    "data_offset" / Int32ul,
    "packed_size" / Int32ul,
    "unknown" / Bytes(4),
)

AT2Entry = Struct(
    "name_offset" / Int32sl,
    "data_offset" / Int32ul,
    "packed_size" / Int32ul,
    "unknown" / Bytes(4),
    "unpacked_size" / Int32ul,
)

ATMIndex = Struct(
    "entries" / GreedyRange(ATMEntry),
    "trailer" / Bytes(4),
    Terminated,
)

AT2Index = Struct(
    "entries" / GreedyRange(AT2Entry),
    "trailer" / Bytes(4),
    Terminated,
)

# LZ77 compression constants

CTRL_BYTE = 0xFF
MAX_DISTANCE = 64
MIN_MATCH = 3
MAX_MATCH = 6


class DETInfo:
    """Metadata for a single entry in a DET archive."""

    __slots__ = (
        'file_name',
        'offset',
        'packed_size',
        'unpacked_size',
    )

    def __init__(self):
        self.file_name = ''
        self.offset = 0
        self.packed_size = 0
        self.unpacked_size = 0

    def __repr__(self):
        return (
            f"DETInfo(file_name={self.file_name!r}, offset={self.offset!r},"
            f" packed_size={self.packed_size!r}, unpacked_size={self.unpacked_size!r})"
        )


def decompress(data: bytes) -> bytes:
    """Decompress LZ77-compressed *data*.

    The uGOS LZ77 scheme uses 0xFF as a control prefix.  A non-0xFF byte is
    a literal; 0xFF 0xFF is an escaped literal 0xFF; 0xFF followed by any
    other byte is a back-reference into recent output (high 6 bits encode
    distance, low 2 bits encode length - 3).
    """
    src = 0
    src_end = len(data)
    out = bytearray()

    while src < src_end:
        ctl = data[src]
        src += 1
        if ctl != CTRL_BYTE:
            out.append(ctl)
        else:
            if src >= src_end:
                break
            ctl = data[src]
            src += 1
            if ctl == CTRL_BYTE:
                out.append(0xFF)
            else:
                distance = (ctl >> 2) + 1
                count = (ctl & 3) + MIN_MATCH
                start = len(out) - distance
                # Copy byte-at-a-time: overlapping references produce RLE.
                for i in range(count):
                    out.append(out[start + i])

    return bytes(out)


def store(data: bytes) -> bytes:
    """Wrap *data* in LZ77 framing without searching for back-references.

    Every byte is emitted as a literal, with 0xFF escaped as 0xFF 0xFF.
    The result decompresses to the original data but is slightly larger
    (one extra byte per 0xFF in the input).
    """
    return data.replace(b'\xff', b'\xff\xff')


def compress(data: bytes) -> bytes:
    """Compress *data* using the uGOS LZ77 scheme.

    Returns the compressed byte string.  The result may be larger than the
    input for high-entropy data (every literal 0xFF costs an extra byte).

    The uGOS LZ77 scheme uses 0xFF as a control prefix.  A non-0xFF byte is
    a literal; 0xFF 0xFF is an escaped literal 0xFF; 0xFF followed by any
    other byte is a back-reference into recent output (high 6 bits encode
    distance, low 2 bits encode length - 3).
    """
    src = 0
    src_end = len(data)
    out = bytearray()

    while src < src_end:
        best_dist = 0
        best_len = 0

        # Search distances 1..64 (the range encodable in the control byte).
        max_dist = min(MAX_DISTANCE, src)
        max_match = min(MAX_MATCH, src_end - src)
        for dist in range(1, max_dist + 1):
            match_len = 0
            for j in range(max_match):
                if data[src - dist + j] != data[src + j]:
                    break
                match_len += 1
            if match_len >= MIN_MATCH and match_len > best_len:
                best_len = match_len
                best_dist = dist

        if best_len >= MIN_MATCH:
            # Emit back-reference: 0xFF + control byte.
            # Control byte 0xFF is reserved for the literal escape, so if
            # (dist=64, len=6) would produce ctl=0xFF, shorten the match.
            ctl = ((best_dist - 1) << 2) | (best_len - MIN_MATCH)
            if ctl == CTRL_BYTE:
                best_len -= 1
                ctl = ((best_dist - 1) << 2) | (best_len - MIN_MATCH)
            out.append(CTRL_BYTE)
            out.append(ctl)
            src += best_len
        else:
            b = data[src]
            if b == CTRL_BYTE:
                out.append(CTRL_BYTE)
                out.append(CTRL_BYTE)
            else:
                out.append(b)
            src += 1

    return bytes(out)


def validate_index(parsed, nme_size: int, det_size: int) -> None:
    """Validate a parsed index against companion file sizes.

    *parsed* is the result of parsing an index file with :data:`ATMIndex` or
    :data:`AT2Index`.  *nme_size* and *det_size* are the sizes of the
    companion ``.nme`` and ``.det`` files.

    Raises :class:`ValueError` if any entry has offsets or sizes that are
    inconsistent with the companion file sizes.
    """
    if not parsed.entries:
        raise ValueError("Index contains no entries")

    for i, rec in enumerate(parsed.entries):
        if rec.name_offset < 0 or rec.name_offset >= nme_size:
            raise ValueError(f"Entry {i}: name_offset {rec.name_offset} is outside .nme file ({nme_size} bytes)")

        if rec.data_offset + rec.packed_size > det_size:
            raise ValueError(
                f"Entry {i}: data extends beyond .det file"
                f" (offset {rec.data_offset:#x} + size {rec.packed_size:#x} > {det_size:#x})"
            )


def _build_entries(parsed, names: bytes, *, is_at2: bool) -> list[DETInfo]:
    """Convert a validated parsed index into a list of :class:`DETInfo`."""
    entries: list[DETInfo] = []
    for rec in parsed.entries:
        end = names.index(b'\x00', rec.name_offset)
        file_name = names[rec.name_offset : end].decode('shift_jis')

        info = DETInfo()
        info.file_name = file_name
        info.offset = rec.data_offset
        info.packed_size = rec.packed_size

        if is_at2:
            info.unpacked_size = rec.unpacked_size

        entries.append(info)
        logger.debug('%s: offset=%#x size=%#x', file_name, rec.data_offset, rec.packed_size)

    return entries


def parse_index(det_path: str | os.PathLike, index_format: str | None = None) -> list[DETInfo]:
    """Parse and validate the index for the DET archive at *det_path*.

    *index_format* may be ``'atm'``, ``'at2'``, or ``None`` (auto-detect).
    When ``'atm'`` is specified, only a ``.atm`` companion file is considered.
    Otherwise, both ``.at2`` and ``.atm`` are searched (preferring ``.at2``),
    and ``.atm`` files are retried as AT2 format if ATM parsing fails (some
    games ship ``.atm`` files that are actually AT2 format).

    Raises :class:`FileNotFoundError` if required companion files are missing,
    or :class:`ValueError` if the index cannot be parsed or validated.
    """
    det_path = pathlib.Path(det_path)
    nme_path = det_path.with_suffix('.nme')

    if not nme_path.exists():
        raise FileNotFoundError(f"Name file not found: {nme_path}")

    names = nme_path.read_bytes()
    det_size = os.path.getsize(det_path)

    if index_format == 'atm':
        candidates = [('.atm', ATMIndex, True)]
    elif index_format == 'at2':
        candidates = [('.at2', AT2Index, True)]
    else:
        # Auto-detect: prefer .at2, then try .atm as ATM, then .atm as AT2.
        candidates = [
            ('.at2', AT2Index, False),
            ('.atm', ATMIndex, False),
            ('.atm', AT2Index, False),
        ]

    last_error = None
    for suffix, index_struct, required in candidates:
        index_path = det_path.with_suffix(suffix)
        if not index_path.exists():
            if required:
                raise FileNotFoundError(f"Index file not found: {index_path}")
            continue

        try:
            with open(index_path, 'rb') as f:
                parsed = index_struct.parse_stream(f)
        except Exception as e:
            last_error = e
            continue

        try:
            validate_index(parsed, nme_size=len(names), det_size=det_size)
        except ValueError as e:
            last_error = e
            continue

        return _build_entries(parsed, names, is_at2=index_struct is AT2Index)

    if last_error is not None:
        raise ValueError(f"Failed to parse DET index: {last_error}") from last_error
    raise FileNotFoundError(f"Index file not found (tried .atm and .at2 alongside {det_path})")


class DETFile:
    """Class for reading and writing μ-GameOperationSystem DET archives.

    Reading::

        with DETFile('/path/to/archive.det') as det:
            for info in det.files:
                print(info.file_name)
            det.extract_all('/output/dir')

    Writing::

        with DETFile('/path/to/archive.det', mode='w', index_format='at2') as det:
            det.write('/path/to/file.ogg', arcname='bgm\\track01.ogg')
            det.write_all('/path/to/dir/')

    When reading, the companion ``.nme`` and ``.atm``/``.at2`` files are
    located automatically based on the ``.det`` path.
    """

    fp = None

    def __init__(self, file, mode='r', index_format=None, compressed=True):
        """Open or create a DET archive at *file*.

        *file* must be a path (string or ``PathLike``) to a ``.det`` file.

        *mode* is ``'r'`` (default) to read an existing archive or ``'w'`` to
        create a new one.  When reading, the companion ``.nme`` and index
        files must already exist alongside the ``.det`` file.

        *index_format* selects the index entry format: ``'at2'`` (0x14-byte
        entries with ``unpacked_size``) or ``'atm'`` (0x10-byte entries
        without it).  When reading, ``None`` (default) auto-detects from the
        companion file extension.  Required when creating (``mode='w'``).

        *compressed* controls whether file data is LZ77-compressed (default)
        or merely stored with 0xFF escaping.  Only affects writing.
        """
        if isinstance(file, os.PathLike):
            file = os.fspath(file)

        if mode not in ('r', 'w'):
            raise ValueError(f"Invalid mode: {mode!r} (expected 'r' or 'w')")

        if mode == 'w' and index_format is None:
            raise ValueError("index_format is required when creating an archive ('atm' or 'at2')")

        if index_format is not None and index_format not in ('atm', 'at2'):
            raise ValueError(f"Invalid index_format: {index_format!r} (expected 'atm' or 'at2')")

        self.filename = file
        self.mode = mode
        self.index_format = index_format
        self.compressed = compressed
        self.files: list[DETInfo] = []

        if mode == 'r':
            self.fp = open(file, 'rb')
            try:
                self.files = parse_index(file, index_format=index_format)
            except Exception:
                fp = self.fp
                self.fp = None
                fp.close()
                raise
        else:
            self.fp = open(file, 'wb')

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __del__(self):
        self.close()

    def close(self):
        """Close the archive.

        When in write mode, this finalizes the archive by writing the
        ``.nme`` and index files alongside the ``.det`` file.
        """
        if self.fp is None:
            return
        if self.mode == 'w':
            self._finalize()
        fp = self.fp
        self.fp = None
        fp.close()

    def read(self, member: DETInfo | str) -> bytes:
        """Read and decompress the contents of *member*.

        *member* can be a :class:`DETInfo` instance or a file name string.
        """
        if self.fp is None:
            raise ValueError("I/O operation on closed DET archive")

        if not isinstance(member, DETInfo):
            for f in self.files:
                if f.file_name == member:
                    member = f
                    break
            else:
                raise KeyError(f"No member named {member!r}")

        self.fp.seek(member.offset)
        raw = self.fp.read(member.packed_size)

        return decompress(raw)

    def extract(self, member: DETInfo | str, path: str | os.PathLike):
        """Extract *member* to a file at *path*."""
        data = self.read(member)
        with open(path, 'xb') as f:
            f.write(data)

    def extract_all(self, path: str | os.PathLike, glob: str | None = None):
        """Extract all members to directory *path*.

        If *glob* is given, only members whose names match the pattern are
        extracted.
        """
        for f in self.files:
            if glob and not fnmatch.fnmatch(f.file_name, glob):
                continue
            # Archive names may use backslash or forward slash separators.
            parts = f.file_name.replace('\\', '/').split('/')
            filepath = os.path.abspath(os.path.join(path, *parts))
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            self.extract(f, filepath)

    # -- creation -------------------------------------------------------------

    def write(self, filepath: str | os.PathLike, arcname: str | None = None):
        """Compress *filepath* and append it to the archive.

        *arcname* is the name stored in the archive.  It defaults to the
        basename of *filepath*.  Use backslashes for directory separators
        to match the engine convention (forward slashes are converted
        automatically).
        """
        if self.fp is None:
            raise ValueError("I/O operation on closed DET archive")
        if self.mode != 'w':
            raise ValueError("write() requires mode='w'")

        if isinstance(filepath, os.PathLike):
            filepath = os.fspath(filepath)

        if arcname is None:
            arcname = os.path.basename(filepath)
        # Normalize to backslash separators.
        arcname = arcname.replace('/', '\\')

        with open(filepath, 'rb') as f:
            raw = f.read()

        packed = compress(raw) if self.compressed else store(raw)

        info = DETInfo()
        info.file_name = arcname
        info.offset = self.fp.tell()
        info.packed_size = len(packed)
        info.unpacked_size = len(raw)

        self.fp.write(packed)
        self.files.append(info)
        logger.debug(
            'packed %s: offset=%#x packed=%#x unpacked=%#x',
            arcname,
            info.offset,
            info.packed_size,
            info.unpacked_size,
        )

    def write_all(self, path: str | os.PathLike, glob: str | None = None, prefix: str = ''):
        """Recursively add files from directory *path* to the archive.

        If *glob* is given, only files whose names match the pattern are
        added.  *prefix* is prepended to archive names (with a backslash
        separator).
        """
        if isinstance(path, str):
            path = pathlib.Path(path)

        for entry in sorted(path.iterdir()):
            if entry.is_dir():
                sub_prefix = prefix + entry.name + '\\'
                self.write_all(entry, glob=glob, prefix=sub_prefix)
            elif entry.is_file():
                arcname = prefix + entry.name
                if glob and not fnmatch.fnmatch(arcname, glob):
                    continue
                self.write(entry, arcname=arcname)

    def _finalize(self):
        """Write the .nme and index files alongside the .det file."""
        if self.fp is None:
            raise ValueError("I/O operation on closed DET archive")
        if not self.files:
            return
        # Seek to end in case the file position was moved by a prior operation.
        self.fp.seek(0, 2)
        # Trailer for the .det file (4 unknown bytes).
        self.fp.write(b'\x00\x00\x00\x00')

        det_path = pathlib.Path(self.filename)

        # Build .nme content: null-terminated Shift-JIS strings.
        nme_data = bytearray()
        name_offsets: list[int] = []
        for info in self.files:
            name_offsets.append(len(nme_data))
            nme_data.extend(info.file_name.encode('shift_jis'))
            nme_data.append(0)
        # Trailer for the .nme file (4 unknown bytes).
        nme_data.extend(b'\x00\x00\x00\x00')
        det_path.with_suffix('.nme').write_bytes(nme_data)

        # Build index.
        use_at2 = self.index_format == 'at2'
        index_struct = AT2Index if use_at2 else ATMIndex
        records = []
        for i, info in enumerate(self.files):
            rec = {
                'name_offset': name_offsets[i],
                'data_offset': info.offset,
                'packed_size': info.packed_size,
                'unknown': b'\x00\x00\x00\x00',
            }
            if use_at2:
                rec['unpacked_size'] = info.unpacked_size
            records.append(rec)

        suffix = '.at2' if use_at2 else '.atm'
        det_path.with_suffix(suffix).write_bytes(
            index_struct.build({'entries': records, 'trailer': b'\x00\x00\x00\x00'})
        )
