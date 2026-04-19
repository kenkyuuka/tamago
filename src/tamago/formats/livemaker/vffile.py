"""Reader and writer for LiveMaker VF resource archives.

A VF archive is a bundle of files with an obfuscated index and
potentially scrambled data chunks. It appears in three configurations:

- Embedded: appended to a PE executable. A 6-byte trailer
  ``[uint32 base_offset] [ascii 'lv']`` marks the archive start.
- Standalone: a ``.dat`` file whose index sits at offset 0, or a
  ``.dat`` paired with a ``.ext`` file containing only the index.
- Multi-part: a ``.dat``/``.ext`` pair plus numbered overflow files
  (``.001``, ``.002``, ...) forming one logical data stream.

The reader auto-detects the configuration from the path passed to
:class:`VFFile`. The writer emits bare standalone archives (no ``.ext``,
no overflow parts).
"""

import binascii
import contextlib
import datetime
import fnmatch
import io
import logging
import os
import pathlib
import typing
import zlib

from construct import Const, Int32ul, Struct

from tamago.formats.livemaker import crypto, dostime

logger = logging.getLogger(__name__)


# --- Format constants -------------------------------------------------------

VF_MAGIC = b'vf'
VERSION = 102
HEADER_SIZE = 10  # magic(2) + version(4) + num_files(4)
EXE_TRAILER_SIZE = 6  # base_offset(4) + 'lv'(2)
EXE_TRAILER_TAG = b'lv'
NAME_ENCODING = 'cp932'

# Flag values for the per-file flags byte.
FLAG_COMPRESSED = 0
FLAG_STORED = 1
FLAG_SCRAMBLED = 2
FLAG_SCRAMBLED_COMPRESSED = 3

# Mapping between (compressed, scrambled) and the stored flag byte.
_FLAGS_BY_OPTIONS: dict[tuple[bool, bool], int] = {
    (True, False): FLAG_COMPRESSED,
    (False, False): FLAG_STORED,
    (False, True): FLAG_SCRAMBLED,
    (True, True): FLAG_SCRAMBLED_COMPRESSED,
}
_OPTIONS_BY_FLAG: dict[int, tuple[bool, bool]] = {v: k for k, v in _FLAGS_BY_OPTIONS.items()}

# Extensions whose contents are typically stored compressed by the engine.
_COMPRESS_BY_DEFAULT = frozenset(('.lsb', '.lpb', '.lpm', '.txt'))
_SCRAMBLE_DEFAULT_CHUNK = 0x1000

VFHeader = Struct(
    "magic" / Const(VF_MAGIC),
    "version" / Int32ul,
    "num_files" / Int32ul,
)


# --- Metadata --------------------------------------------------------------


class VFInfo:
    """Metadata for a single entry in a VF archive."""

    __slots__ = (
        'compressed',
        'crc32',
        'file_name',
        'offset',
        'packed_size',
        'scrambled',
        'timestamp',
        'unknown_byte',
        'unpacked_size',
    )

    def __init__(self):
        self.file_name: str = ''
        self.offset: int = 0
        self.packed_size: int = 0
        self.unpacked_size: int = 0
        self.compressed: bool = False
        self.scrambled: bool = False
        self.timestamp: datetime.datetime | None = None
        self.crc32: int = 0
        self.unknown_byte: int = 0

    @property
    def flags(self) -> int:
        """The flag byte derived from ``compressed`` and ``scrambled``."""
        return _FLAGS_BY_OPTIONS[(self.compressed, self.scrambled)]

    def __repr__(self):
        return (
            f"VFInfo(file_name={self.file_name!r}, offset={self.offset!r},"
            f" packed_size={self.packed_size!r}, flags={self.flags!r})"
        )


# --- Helpers ---------------------------------------------------------------


def _probe_base_offset(fp) -> int:
    """Return the archive base offset, or ``0`` if no exe trailer is present.

    The caller is responsible for validating that the archive exists (the
    ``0`` return is also produced when the file is pure data that needs a
    companion ``.ext`` index).
    """
    fp.seek(0, os.SEEK_END)
    size = fp.tell()
    if size < EXE_TRAILER_SIZE:
        return 0
    fp.seek(size - EXE_TRAILER_SIZE)
    trailer = fp.read(EXE_TRAILER_SIZE)
    if trailer[-2:] != EXE_TRAILER_TAG:
        return 0
    base_offset = int.from_bytes(trailer[:4], 'little', signed=False)
    if base_offset >= size:
        return 0
    fp.seek(base_offset)
    if fp.read(2) != VF_MAGIC:
        return 0
    return base_offset


def _index_size(names: list[bytes]) -> int:
    """Return the total size in bytes of the index section for *names*."""
    n = len(names)
    return HEADER_SIZE + sum(4 + len(b) for b in names) + 8 * (n + 1) + n + 4 * n + 4 * n + n


def _encode_offsets(offsets: list[int]) -> bytes:
    """Encrypt and serialize *offsets* using the offset PRNG."""
    rnd = crypto.TpRandom()
    out = bytearray()
    for off in offsets:
        key = rnd.next_sign_extended()
        encoded = (off ^ key) & 0xFFFFFFFFFFFFFFFF
        out.extend(encoded.to_bytes(8, 'little', signed=False))
    return bytes(out)


def _encode_names(names: list[bytes]) -> bytes:
    """Encrypt and serialize the filename records."""
    rnd = crypto.TpRandom()
    out = bytearray()
    for name_bytes in names:
        out.extend(len(name_bytes).to_bytes(4, 'little', signed=False))
        out.extend(crypto.crypt_name(name_bytes, rnd))
    return bytes(out)


# --- Archive class ---------------------------------------------------------


class VFFile:
    """Read or create LiveMaker VF archives.

    Reading::

        with VFFile('/path/to/game.exe') as arc:
            for info in arc.files:
                print(info.file_name)
            arc.extract_all('/output/dir')

    Writing::

        with VFFile('/path/to/out.dat', mode='w') as arc:
            arc.write('file.lsb', arcname='script\\\\file.lsb')
            arc.write_all('/path/to/src/')

    When reading a standalone archive with a separate ``.ext`` index, or a
    multi-part archive with ``.001``, ``.002`` overflow files, companion
    files are opened automatically alongside the path passed to the
    constructor.
    """

    _output_fp = None

    def __init__(self, file, mode: str = 'r'):
        if isinstance(file, os.PathLike):
            file = os.fspath(file)

        if mode not in ('r', 'w'):
            raise ValueError(f"Invalid mode: {mode!r} (expected 'r' or 'w')")

        self.filename = file
        self.mode = mode
        self.files: list[VFInfo] = []

        self._base_offset: int = 0
        self._embedded: bool = False
        self._index_fp = None
        # Each region: (logical_start, logical_end, fp, file_offset)
        # ``logical`` is the offset inside the archive's data stream.
        # ``file_offset`` is added when seeking the backing file.
        self._data_fps: list[tuple[int, int, typing.BinaryIO, int]] = []
        self._owned_fps: list[typing.BinaryIO] = []
        self._pending: list[dict] = []
        # Track distinct Gale-fallback reasons already logged, so an archive
        # with thousands of .gal files doesn't produce thousands of identical
        # warnings.
        self._gal_fallback_warned: set[str] = set()

        if mode == 'r':
            try:
                self._open_read()
            except Exception:
                self._close_all()
                raise
        else:
            self._output_fp = open(file, 'wb')
            self._owned_fps.append(self._output_fp)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __del__(self):
        with contextlib.suppress(Exception):
            self.close()

    def close(self):
        """Close the archive, finalizing it if in write mode."""
        if self.mode == 'w' and self._output_fp is not None:
            try:
                self._finalize()
            finally:
                self._close_all()
        else:
            self._close_all()

    def _close_all(self):
        for fp in self._owned_fps:
            with contextlib.suppress(Exception):
                fp.close()
        self._owned_fps = []
        self._index_fp = None
        self._data_fps = []
        self._output_fp = None

    # -- reading -----------------------------------------------------------

    def _open_read(self):
        path = pathlib.Path(self.filename)
        main_fp = open(path, 'rb')
        self._owned_fps.append(main_fp)

        self._base_offset = _probe_base_offset(main_fp)

        if self._base_offset != 0:
            self._embedded = True
            self._index_fp = main_fp
            main_fp.seek(0, os.SEEK_END)
            size = main_fp.tell()
            # Data region starts at base_offset in the exe; logical 0 maps
            # to base_offset in the file.  index and data share the main_fp.
            self._data_fps = [(0, size - self._base_offset, main_fp, self._base_offset)]
            self._read_index()
            return

        main_fp.seek(0)
        if main_fp.read(2) == VF_MAGIC:
            self._index_fp = main_fp
        else:
            ext_path = path.with_suffix('.ext')
            if not ext_path.exists():
                raise ValueError(f"No VF header at offset 0 and no {ext_path.name} alongside {path.name}")
            ext_fp = open(ext_path, 'rb')
            self._owned_fps.append(ext_fp)
            if ext_fp.read(2) != VF_MAGIC:
                raise ValueError(f"Index file {ext_path.name} does not start with VF magic")
            self._index_fp = ext_fp

        # Build data file list.  Whether the main .dat holds the index at
        # offset 0 or pure data depends on the configuration detected above.
        # Either way, offsets recorded in the index are measured from the
        # start of the concatenated stream (main + .001 + .002 + ...), with
        # the main file's byte 0 mapping to cursor 0.
        data_paths: list[pathlib.Path] = [path]
        for i in range(1, 1000):
            ext = f'.{i:03d}'
            part = path.with_suffix(ext)
            if not part.exists():
                break
            data_paths.append(part)

        cursor = 0
        for p in data_paths:
            if p == path:
                fp = main_fp
            else:
                fp = open(p, 'rb')
                self._owned_fps.append(fp)
            fp.seek(0, os.SEEK_END)
            length = fp.tell()
            self._data_fps.append((cursor, cursor + length, fp, 0))
            cursor += length

        self._read_index()

    def _read_index(self):
        fp = self._index_fp
        fp.seek(self._base_offset)
        raw = fp.read(HEADER_SIZE)
        parsed = VFHeader.parse(raw)
        if parsed.version != VERSION:
            raise ValueError(f"Unsupported VF version {parsed.version} (expected {VERSION})")
        num_files = parsed.num_files

        rnd = crypto.TpRandom()
        names: list[str] = []
        for _ in range(num_files):
            name_length = int.from_bytes(fp.read(4), 'little', signed=False)
            if name_length == 0 or name_length > 0x1000:
                raise ValueError(f"Unreasonable name length {name_length}")
            raw_name = fp.read(name_length)
            if len(raw_name) != name_length:
                raise ValueError("Truncated filename")
            names.append(crypto.crypt_name(raw_name, rnd).decode(NAME_ENCODING))

        rnd.reset()
        offsets: list[int] = []
        for _ in range(num_files + 1):
            key = rnd.next_sign_extended()
            raw_offset = int.from_bytes(fp.read(8), 'little', signed=True)
            offsets.append(raw_offset ^ key)

        flags_raw = fp.read(num_files)
        timestamps_raw = fp.read(4 * num_files)
        crcs_raw = fp.read(4 * num_files)
        unknown_raw = fp.read(num_files)

        if (
            len(flags_raw) != num_files
            or len(timestamps_raw) != 4 * num_files
            or len(crcs_raw) != 4 * num_files
            or len(unknown_raw) != num_files
        ):
            raise ValueError("Truncated VF index")

        for i in range(num_files):
            info = VFInfo()
            info.file_name = names[i]
            info.offset = offsets[i]
            info.packed_size = offsets[i + 1] - offsets[i]
            info.compressed, info.scrambled = _OPTIONS_BY_FLAG.get(flags_raw[i], (False, False))
            ts_value = int.from_bytes(timestamps_raw[4 * i : 4 * i + 4], 'little', signed=False)
            try:
                info.timestamp = dostime.decode(ts_value)
            except ValueError:
                info.timestamp = None
            info.crc32 = int.from_bytes(crcs_raw[4 * i : 4 * i + 4], 'little', signed=False)
            info.unknown_byte = unknown_raw[i]
            self.files.append(info)

    def _read_raw(self, offset: int, size: int) -> bytes:
        if size <= 0:
            return b''
        out = bytearray()
        remaining = size
        cursor = offset
        for start, end, fp, file_offset in self._data_fps:
            if cursor >= end:
                continue
            if cursor < start:
                raise ValueError(f"Offset {cursor:#x} falls in a gap between data parts")
            local = cursor - start + file_offset
            chunk_len = min(remaining, end - cursor)
            fp.seek(local)
            chunk = fp.read(chunk_len)
            if len(chunk) != chunk_len:
                raise ValueError(f"Short read at offset {cursor:#x}")
            out.extend(chunk)
            remaining -= chunk_len
            cursor += chunk_len
            if remaining == 0:
                break
        if remaining > 0:
            raise ValueError(f"Read past end of archive data (offset {offset:#x}, size {size})")
        return bytes(out)

    def read(self, member: 'VFInfo | str') -> bytes:
        """Read and decode the contents of *member*.

        Applies unscrambling and decompression according to the entry's
        flags.  *member* can be a :class:`VFInfo` instance or a file name
        string.
        """
        if not self._data_fps:
            raise ValueError("I/O operation on closed VF archive")
        if not isinstance(member, VFInfo):
            for f in self.files:
                if f.file_name == member:
                    member = f
                    break
            else:
                raise KeyError(f"No member named {member!r}")

        data = self._read_raw(member.offset, member.packed_size)
        if member.scrambled:
            data = crypto.unscramble(data)
        if member.compressed:
            data = zlib.decompress(data)
        return data

    def extract(
        self,
        member: 'VFInfo | str',
        path: str | os.PathLike,
        convert_gal: bool = False,
    ):
        """Extract *member* to a file at *path*.

        When ``convert_gal`` is true and the member is a Gale image, the
        decoded bitmap is saved as PNG (with the output path's extension
        replaced).  If Pillow is unavailable or decoding fails, the file
        is written as the raw ``.gal`` bytes instead.
        """
        if not isinstance(member, VFInfo):
            for f in self.files:
                if f.file_name == member:
                    member = f
                    break
            else:
                raise KeyError(f"No member named {member!r}")

        if convert_gal and member.file_name.lower().endswith('.gal'):
            from tamago.formats.livemaker import gale

            try:
                img = gale.open_gal(io.BytesIO(self.read(member)))
            except (ImportError, NotImplementedError, ValueError) as exc:
                reason = f"{type(exc).__name__}: {exc}"
                if reason not in self._gal_fallback_warned:
                    self._gal_fallback_warned.add(reason)
                    logger.warning("Cannot convert Gale images; keeping .gal files (%s)", reason)
            else:
                png_path = os.fspath(path)
                png_path = os.path.splitext(png_path)[0] + '.png'
                img.save(png_path, 'PNG')
                return

        data = self.read(member)
        with open(path, 'xb') as fp:
            fp.write(data)

    def extract_all(
        self,
        path: str | os.PathLike,
        glob: str | None = None,
        convert_gal: bool = False,
    ):
        """Extract all members to directory *path*.

        LiveMaker archive names use backslash separators; these are
        converted to the platform's native separator on disk.  If *glob*
        is given, only entries whose names match the pattern are extracted.
        When ``convert_gal`` is true, ``.gal`` images are converted to PNG
        on the way out.
        """
        for f in self.files:
            if glob and not fnmatch.fnmatch(f.file_name, glob):
                continue
            parts = f.file_name.replace('\\', '/').split('/')
            filepath = os.path.abspath(os.path.join(path, *parts))
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            self.extract(f, filepath, convert_gal=convert_gal)

    # -- writing -----------------------------------------------------------

    def write(
        self,
        filepath: str | os.PathLike,
        arcname: str | None = None,
        *,
        compress: bool | None = None,
        scramble: bool = False,
        timestamp: datetime.datetime | None = None,
    ):
        """Queue *filepath* for inclusion in the archive.

        *arcname* defaults to the basename of *filepath*; forward slashes
        are converted to the engine's backslash convention.  *compress*
        selects zlib compression (defaulting to ``True`` for script-like
        files and ``False`` otherwise).  *scramble* applies the chunk
        reorder obfuscation.  *timestamp* overrides the file's mtime.
        """
        if self.mode != 'w':
            raise ValueError("write() requires mode='w'")
        if self._output_fp is None:
            raise ValueError("I/O operation on closed VF archive")

        if isinstance(filepath, os.PathLike):
            filepath = os.fspath(filepath)
        if arcname is None:
            arcname = os.path.basename(filepath)
        arcname = arcname.replace('/', '\\')

        if compress is None:
            ext = os.path.splitext(arcname)[1].lower()
            compress = ext in _COMPRESS_BY_DEFAULT

        self._pending.append(
            {
                'filepath': filepath,
                'arcname': arcname,
                'compress': bool(compress),
                'scramble': bool(scramble),
                'timestamp': timestamp,
            }
        )

    def write_all(
        self,
        path: str | os.PathLike,
        glob: str | None = None,
        prefix: str = '',
        *,
        compress: bool | None = None,
        scramble: bool = False,
    ):
        """Recursively add files from directory *path* to the archive.

        Archive names use backslash separators, following the engine
        convention.  *prefix* is prepended (with a trailing backslash) to
        every name produced by this call.
        """
        if isinstance(path, str):
            path = pathlib.Path(path)
        elif isinstance(path, os.PathLike):
            path = pathlib.Path(os.fspath(path))

        for entry in sorted(path.iterdir()):
            if entry.is_dir():
                sub_prefix = prefix + entry.name + '\\'
                self.write_all(entry, glob=glob, prefix=sub_prefix, compress=compress, scramble=scramble)
            elif entry.is_file():
                arcname = prefix + entry.name
                if glob and not fnmatch.fnmatch(arcname, glob):
                    continue
                self.write(entry, arcname=arcname, compress=compress, scramble=scramble)

    def _finalize(self):
        fp = self._output_fp
        if fp is None:
            return

        # Prepare per-entry payloads and metadata.
        entries: list[VFInfo] = []
        payloads: list[bytes] = []
        name_bytes_list: list[bytes] = []

        for item in self._pending:
            with open(item['filepath'], 'rb') as src:
                raw = src.read()
            ts = item['timestamp']
            if ts is None:
                mtime = os.path.getmtime(item['filepath'])
                ts = datetime.datetime.fromtimestamp(mtime)  # noqa: DTZ006

            stored = raw
            if item['compress']:
                stored = zlib.compress(stored)
            if item['scramble']:
                stored = crypto.scramble(stored, _SCRAMBLE_DEFAULT_CHUNK, raw_seed=0)

            info = VFInfo()
            info.file_name = item['arcname']
            info.compressed = item['compress']
            info.scrambled = item['scramble']
            info.timestamp = ts
            info.crc32 = binascii.crc32(stored) & 0xFFFFFFFF
            info.packed_size = len(stored)
            info.unpacked_size = len(raw)
            entries.append(info)
            payloads.append(stored)
            name_bytes_list.append(info.file_name.encode(NAME_ENCODING))

        # Compute the deterministic index size and derive absolute offsets.
        idx_size = _index_size(name_bytes_list)
        offsets = [idx_size]
        for p in payloads:
            offsets.append(offsets[-1] + len(p))

        # Serialize the index.
        header = VFHeader.build({'version': VERSION, 'num_files': len(entries)})
        names_section = _encode_names(name_bytes_list)
        offsets_section = _encode_offsets(offsets)
        flags_section = bytes(info.flags for info in entries)
        timestamps_section = b''.join(dostime.encode(info.timestamp).to_bytes(4, 'little') for info in entries)
        crcs_section = b''.join(info.crc32.to_bytes(4, 'little') for info in entries)
        unknown_section = bytes(len(entries))

        index = b''.join(
            [
                header,
                names_section,
                offsets_section,
                flags_section,
                timestamps_section,
                crcs_section,
                unknown_section,
            ]
        )
        if len(index) != idx_size:
            raise RuntimeError(f"Index size mismatch: computed {idx_size}, serialized {len(index)}")

        fp.seek(0)
        fp.write(index)
        for payload in payloads:
            fp.write(payload)
        fp.flush()

        # Record final offsets on entries for callers that want them.
        for info, off in zip(entries, offsets[:-1], strict=True):
            info.offset = off
        self.files = entries
