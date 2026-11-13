"""Reader and writer for "MD" archives (``.med``), as used by Fudegaki Soft games.

An MD archive is a 16-byte header, a table of fixed-size entries, then member
data back to back.  The fourth header byte is a type digit: ``'0'`` archives hold
scripts, whose entries carry an extra running counter and whose bodies are
encrypted by subtracting a per-game keyword.  Other types (images, audio) are
stored plainly.

The keyword is not stored anywhere, but the ``_VIEW`` script always begins with
the same text, so it can be recovered from the archive itself.

Image archives hold PRS images and music archives hold WADY audio; extraction
can convert these to PNG and WAV.
"""

import fnmatch
import logging
import os
import pathlib
import shutil
import tempfile
from collections.abc import Iterator
from typing import BinaryIO

from construct import Bytes, Const, Int16ul, Int32ul, Struct

from tamago.formats.med.prs import decode_prs, is_prs
from tamago.formats.med.wady import decode_wady, is_wady
from tamago.formats.member_paths import plan_extraction

logger = logging.getLogger(__name__)

MED_MAGIC = b'MD'
SCRIPT_TYPE = '0'
AUDIO_TYPE = '6'
IMAGE_TYPE = '1'
DEFAULT_VARIANT = 'E'

SCRIPT_HEADER_SIZE = 0x10
# Every _VIEW script's body starts with this text.
VIEW_PREFIX = '_VIEW'
VIEW_PLAINTEXT = b'\x00#RULE_VIEWER\x00:VIEW_0\x00{\x00'

_HEADER = Struct(
    'magic' / Const(MED_MAGIC),
    'variant' / Bytes(1),
    'type' / Bytes(1),
    'entry_size' / Int16ul,
    'count' / Int16ul,
    'unused' / Bytes(8),
)
_SCRIPT_HEADER = Struct(
    'body_size' / Int32ul,
    'text_offset' / Int32ul,
    'unknown' / Int32ul,
    'counter_step' / Int32ul,
)

_CHUNK_SIZE = 1 << 20
MAX_U16 = 0xFFFF
MAX_U32 = 0xFFFFFFFF


def is_med_header(header: bytes) -> bool:
    """Return True if *header* looks like the start of an MD archive."""
    if len(header) < 8 or header[:2] != MED_MAGIC:
        return False
    variant, kind = header[2:3], header[3:4]
    if not (variant.isalpha() and variant.isupper() and kind.isdigit()):
        return False
    entry_size = int.from_bytes(header[4:6], 'little')
    return entry_size >= _min_entry_size(kind.decode())


def _min_entry_size(kind: str) -> int:
    # A one-character name and its NUL, then the trailing integers.
    return 2 + (12 if kind == SCRIPT_TYPE else 8)


def _add_keyword(data: bytes, keyword: bytes, sign: int) -> bytes:
    buf = bytearray(data)
    n = len(keyword)
    for j, k in enumerate(keyword):
        shift = (sign * k) & 0xFF
        if not shift:
            continue
        table = bytes((i + shift) & 0xFF for i in range(256))
        # Positions i >= 0x10 with i % n == j.
        start = SCRIPT_HEADER_SIZE + (j - SCRIPT_HEADER_SIZE) % n
        buf[start::n] = buf[start::n].translate(table)
    return bytes(buf)


def decrypt_script(data: bytes, keyword: bytes) -> bytes:
    """Decrypt a script: add the keyword to every byte from 0x10, indexed by position in *data*."""
    return _add_keyword(data, keyword, 1)


def encrypt_script(data: bytes, keyword: bytes) -> bytes:
    """Encrypt a script, the inverse of :func:`decrypt_script`."""
    return _add_keyword(data, keyword, -1)


def is_script(data: bytes) -> bool:
    """Return True if *data* has the header of an MD script."""
    return len(data) >= SCRIPT_HEADER_SIZE and int.from_bytes(data[:4], 'little') + SCRIPT_HEADER_SIZE == len(data)


def _view_is_plaintext(data: bytes) -> bool:
    return data[SCRIPT_HEADER_SIZE : SCRIPT_HEADER_SIZE + len(VIEW_PLAINTEXT)] == VIEW_PLAINTEXT


def _text_looks_valid(plain: bytes) -> bool:
    """Whether a decrypted script's text region ends in NUL and decodes as cp932."""
    text_offset = int.from_bytes(plain[4:8], 'little')
    text = plain[SCRIPT_HEADER_SIZE + text_offset :]
    if SCRIPT_HEADER_SIZE + text_offset > len(plain) or not text.endswith(b'\0'):
        return False
    try:
        text.decode('cp932')
    except UnicodeDecodeError:
        return False
    return True


def recover_keyword(view: bytes, scripts: list[bytes]) -> 'bytes | None':
    """Recover the script keyword from an encrypted ``_VIEW`` script.

    The known plaintext gives 24 keystream bytes.  Every keyword length they are
    consistent with is a candidate.  Each candidate is scored by how many of
    *scripts* decrypt to plausible text, and the shortest candidate with the best
    score wins, provided more than half the scripts pass.
    """
    start = SCRIPT_HEADER_SIZE
    known = view[start : start + len(VIEW_PLAINTEXT)]
    if len(known) < len(VIEW_PLAINTEXT):
        return None
    stream = bytes((p - c) & 0xFF for p, c in zip(VIEW_PLAINTEXT, known, strict=True))
    best: tuple[int, bytes] | None = None
    for n in range(1, len(stream) + 1):
        if any(stream[j] != stream[j + n] for j in range(len(stream) - n)):
            continue
        keyword = bytes(stream[(k - start) % n] for k in range(n))
        score = sum(_text_looks_valid(decrypt_script(s, keyword)) for s in scripts)
        if best is None or score > best[0]:
            best = (score, keyword)
    if best is None or best[0] * 2 <= len(scripts):
        return None
    return best[1]


class MEDInfo:
    """Metadata for a single member of an MD archive."""

    __slots__ = (
        'file_name',
        'offset',
        'size',
        'counter',
    )

    def __init__(self, file_name: str = '', offset: int = 0, size: int = 0, counter: 'int | None' = None):
        self.file_name = file_name
        self.offset = offset
        self.size = size
        self.counter = counter

    def __repr__(self):
        return f"MEDInfo(file_name={self.file_name!r}, size={self.size!r})"


class _Pending:
    """A member staged for writing."""

    __slots__ = ('name', 'raw_name', 'spool_offset', 'size', 'script', 'counter_step', 'head')

    def __init__(self, name, raw_name, spool_offset, size, script, counter_step, head):
        self.name = name
        self.raw_name = raw_name
        self.spool_offset = spool_offset
        self.size = size
        self.script = script
        self.counter_step = counter_step
        self.head = head


class MEDFile:
    """Read or create MD archives.

    In ``mode='r'`` (default), scripts in type '0' archives are decrypted with
    *keyword*, or with a keyword recovered from the archive when *keyword* is
    None.  Pass ``decrypt=False`` to read stored bytes instead.

    In ``mode='w'``, *signature* (such as ``'MDE1'``) is inferred from the
    contents unless given, and scripts are encrypted with *keyword* if one is
    given.  Without a keyword, scripts are stored as they are, which suits
    scripts extracted with ``decrypt=False``.
    """

    def __init__(
        self,
        file: str | os.PathLike,
        mode: str = 'r',
        keyword: 'str | None' = None,
        decrypt: bool = True,
        signature: 'str | None' = None,
    ):
        self.fp: BinaryIO | None = None

        if mode not in ('r', 'w'):
            raise ValueError(f"Invalid mode: {mode!r} (expected 'r' or 'w')")
        if signature is not None and (
            len(signature) != 4 or not is_med_header(signature.encode('ascii', 'replace') + b'\xff' * 4)
        ):
            raise ValueError(f"Invalid MD signature: {signature!r} (expected e.g. 'MDE1')")

        self.filename = os.fspath(file)
        self.mode = mode
        self.decrypt = decrypt
        self.keyword = keyword
        self.signature = signature
        self.files: list[MEDInfo] = []
        self._by_name: dict[str, MEDInfo] = {}
        self._keyword_bytes = keyword.encode('cp932') if keyword else None
        self._convert_warned: set[tuple[str, str]] = set()

        if mode == 'r':
            self._open_for_read()
        else:
            self._pending: list[_Pending] = []
            self._spool = tempfile.TemporaryFile()
            self.fp = open(self.filename, 'wb')

    @property
    def is_script_archive(self) -> bool:
        return self.signature is not None and self.signature[3:4] == SCRIPT_TYPE

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
            if self.mode == 'w':
                self._spool.close()

    # -- reading ---------------------------------------------------------------

    def _open_for_read(self):
        fp = open(self.filename, 'rb')
        try:
            size = os.fstat(fp.fileno()).st_size
            raw = fp.read(_HEADER.sizeof())
            if len(raw) < _HEADER.sizeof() or raw[:2] != MED_MAGIC or not raw[3:4].isdigit():
                raise ValueError(f"{self.filename} is not an MD archive (expected an 'MD' signature)")
            header = _HEADER.parse(raw)
            self.signature = raw[:4].decode('ascii')
            script_archive = self.is_script_archive
            tail = 12 if script_archive else 8
            if header.entry_size < _min_entry_size(header.type.decode()):
                raise ValueError(f"MD entry size {header.entry_size} is too small")

            index = fp.read(header.entry_size * header.count)
            if len(index) < header.entry_size * header.count:
                raise ValueError(f"MD index is truncated in {self.filename}")

            files = []
            for i in range(header.count):
                entry = index[i * header.entry_size : (i + 1) * header.entry_size]
                name_field = entry[: header.entry_size - tail]
                name = name_field.split(b'\0', 1)[0].decode('cp932', 'surrogateescape')
                counter = int.from_bytes(entry[-12:-8], 'little') if script_archive else None
                member_size = int.from_bytes(entry[-8:-4], 'little')
                offset = int.from_bytes(entry[-4:], 'little')
                if offset + member_size > size:
                    raise ValueError(f"MD member {name!r} extends past the end of the file")
                files.append(MEDInfo(name, offset, member_size, counter))
            self.fp = fp
            self.files = files
            self._by_name = {info.file_name: info for info in files}

            if script_archive and self.decrypt and self._keyword_bytes is None:
                self._recover_keyword()
        except Exception:
            self.fp = None
            fp.close()
            raise

    def _read_raw(self, info: MEDInfo) -> bytes:
        assert self.fp is not None
        self.fp.seek(info.offset)
        data = self.fp.read(info.size)
        if len(data) != info.size:
            raise ValueError(f"Unexpected end of MD data in member {info.file_name!r}")
        return data

    def _recover_keyword(self):
        scripts = [data for data in map(self._read_raw, self.files) if is_script(data)]
        for info in self.files:
            if info.file_name.startswith(VIEW_PREFIX):
                view = self._read_raw(info)
                if is_script(view):
                    keyword = recover_keyword(view, scripts)
                    if keyword is not None:
                        self._keyword_bytes = keyword
                        self.keyword = keyword.decode('cp932', 'replace')
                        logger.info('recovered script keyword %r', self.keyword)
                        return
        logger.warning('could not recover the script keyword of %s', self.filename)

    def _resolve(self, member: 'MEDInfo | str') -> MEDInfo:
        if self.fp is None:
            raise ValueError("I/O operation on closed MD archive")
        if self.mode != 'r':
            raise ValueError("reading requires mode='r'")
        if isinstance(member, MEDInfo):
            return member
        try:
            return self._by_name[member]
        except KeyError:
            raise KeyError(f"No member named {member!r}") from None

    def read(self, member: 'MEDInfo | str') -> bytes:
        """Return the contents of *member*, an :class:`MEDInfo` or a file name."""
        info = self._resolve(member)
        data = self._read_raw(info)
        if self.is_script_archive and self.decrypt and is_script(data):
            if self._keyword_bytes is None:
                raise ValueError(
                    f"The script keyword of {self.filename} is unknown: "
                    "pass a keyword, or decrypt=False for stored bytes"
                )
            data = decrypt_script(data, self._keyword_bytes)
        return data

    def extract(
        self,
        member: 'MEDInfo | str',
        path: str | os.PathLike,
        convert_prs: bool = False,
        convert_wady: bool = False,
    ):
        """Extract *member* to a new file at *path*.

        With *convert_prs*, a PRS image is written as PNG to *path* plus
        ``.png``; with *convert_wady*, WADY audio is written as WAV to *path*
        plus ``.wav``.  Members are recognised by their contents.  A member
        that cannot be converted is written as is, with a warning.
        """
        data = self.read(member)
        name = self._resolve(member).file_name
        if convert_prs and is_prs(data):
            if self._try_convert(name, 'PRS', lambda: decode_prs(data).save(os.fspath(path) + '.png', 'PNG')):
                return
        elif convert_wady and is_wady(data):
            if self._try_convert(name, 'WADY', lambda: decode_wady(data).save_wav(os.fspath(path) + '.wav')):
                return
        with open(path, 'xb') as f:
            f.write(data)

    def _try_convert(self, name: str, kind: str, convert) -> bool:
        """Run *convert*, returning False (and warning once per kind and error) if the data is invalid."""
        try:
            convert()
        except (ValueError, NotImplementedError) as exc:
            logger.debug('cannot convert %s %s: %s', kind, name, exc)
            key = (kind, type(exc).__name__)
            if key not in self._convert_warned:
                self._convert_warned.add(key)
                logger.warning(
                    'Cannot convert %s data in %s; keeping it as is (%s: %s). '
                    'Similar failures are logged at debug level',
                    kind,
                    name,
                    type(exc).__name__,
                    exc,
                )
            return False
        return True

    def extract_all(
        self,
        path: str | os.PathLike,
        glob: str | None = None,
        convert_prs: bool = False,
        convert_wady: bool = False,
    ):
        """Extract all members to directory *path*.

        If *glob* is given, only members whose names match the pattern are
        extracted.  *convert_prs* and *convert_wady* convert PRS images to PNG
        and WADY audio to WAV, as in :meth:`extract`.  Raises ValueError,
        before writing anything, if a selected member's name would place it
        outside *path*.
        """
        for info, filepath in plan_extraction(self.files, path, glob):
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            self.extract(info, filepath, convert_prs=convert_prs, convert_wady=convert_wady)

    # -- creation --------------------------------------------------------------

    def write(self, filepath: str | os.PathLike, arcname: str | None = None):
        """Add the file at *filepath* to the archive under *arcname* (default: its basename)."""
        if self.fp is None:
            raise ValueError("I/O operation on closed MD archive")
        if self.mode != 'w':
            raise ValueError("write() requires mode='w'")

        filepath = os.fspath(filepath)
        name = arcname if arcname is not None else os.path.basename(filepath)
        if not name:
            raise ValueError("MD member names cannot be empty")
        try:
            raw_name = name.encode('cp932')
        except UnicodeEncodeError:
            raise ValueError(f"MD member name {name!r} cannot be encoded as cp932") from None
        if b'\0' in raw_name:
            raise ValueError(f"MD member name {name!r} contains a NUL")
        if any(p.name == name for p in self._pending):
            raise ValueError(f"Duplicate MD member name: {name!r}")

        spool_offset = self._spool.seek(0, os.SEEK_END)
        with open(filepath, 'rb') as source:
            shutil.copyfileobj(source, self._spool, _CHUNK_SIZE)
        size = self._spool.tell() - spool_offset
        self._spool.seek(spool_offset)
        head = self._spool.read(SCRIPT_HEADER_SIZE + len(VIEW_PLAINTEXT))
        script = len(head) >= SCRIPT_HEADER_SIZE and int.from_bytes(head[:4], 'little') + SCRIPT_HEADER_SIZE == size
        counter_step = _SCRIPT_HEADER.parse(head).counter_step if script else 0

        if script and name.startswith(VIEW_PREFIX):
            plaintext = _view_is_plaintext(head)
            if plaintext and self._keyword_bytes is None:
                raise ValueError(
                    f"{name!r} is a decrypted script: pass the game's keyword so scripts are encrypted again"
                )
            if not plaintext and self._keyword_bytes is not None:
                raise ValueError(f"{name!r} is already encrypted: omit the keyword to store scripts as they are")

        self._pending.append(_Pending(name, raw_name, spool_offset, size, script, counter_step, head))
        logger.debug('staged %s: size=%#x script=%s', name, size, script)

    def write_all(self, path: str | os.PathLike, glob: str | None = None, prefix: str = ''):
        """Recursively add the files in directory *path* to the archive."""
        if self.fp is None:
            raise ValueError("I/O operation on closed MD archive")
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

    def _infer_signature(self) -> str:
        pending = self._pending
        if self._keyword_bytes is not None or (pending and all(p.script for p in pending)):
            kind = SCRIPT_TYPE
        elif pending and all(p.head.startswith(b'WADY') for p in pending):
            kind = AUDIO_TYPE
        else:
            kind = IMAGE_TYPE
        return f'MD{DEFAULT_VARIANT}{kind}'

    def _iter_member(self, member: _Pending, encrypt: bool) -> Iterator[bytes]:
        self._spool.seek(member.spool_offset)
        if encrypt:
            assert self._keyword_bytes is not None
            yield encrypt_script(self._spool.read(member.size), self._keyword_bytes)
            return
        remaining = member.size
        while remaining:
            chunk = self._spool.read(min(remaining, _CHUNK_SIZE))
            remaining -= len(chunk)
            yield chunk

    def _finalize(self):
        assert self.fp is not None
        if self.signature is None:
            self.signature = self._infer_signature()
        script_archive = self.is_script_archive
        if self._keyword_bytes is not None and not script_archive:
            raise ValueError(f"A keyword only applies to script archives, not {self.signature!r}")

        pending = self._pending
        if len(pending) > MAX_U16:
            raise ValueError(f"MD archives hold at most {MAX_U16} members")
        name_field = max((len(p.raw_name) for p in pending), default=0) + 1
        entry_size = name_field + (12 if script_archive else 8)
        if entry_size > MAX_U16:
            raise ValueError("MD member names are too long")

        index = bytearray()
        offset = _HEADER.sizeof() + entry_size * len(pending)
        counter = 0
        for p in pending:
            index += p.raw_name.ljust(name_field, b'\0')
            if script_archive:
                index += counter.to_bytes(4, 'little')
                counter = (counter + p.counter_step) & MAX_U32
            index += p.size.to_bytes(4, 'little') + offset.to_bytes(4, 'little')
            offset += p.size
            if offset > MAX_U32:
                raise ValueError("MD archives cannot exceed 4 GiB")

        signature = self.signature.encode('ascii')
        self.fp.write(
            _HEADER.build(
                {
                    'variant': signature[2:3],
                    'type': signature[3:4],
                    'entry_size': entry_size,
                    'count': len(pending),
                    'unused': bytes(8),
                }
            )
        )
        self.fp.write(index)
        encrypt = script_archive and self._keyword_bytes is not None
        for p in pending:
            for chunk in self._iter_member(p, encrypt and p.script):
                self.fp.write(chunk)
        self.files = [MEDInfo(p.name, 0, p.size) for p in pending]
