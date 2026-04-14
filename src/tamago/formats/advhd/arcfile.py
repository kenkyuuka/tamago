"""Reader and writer for AdvHD ARC resource archives (WillPlus V2).

An ARC archive is a flat file bundle with UTF-16LE filenames.  The format
consists of:

- An 8-byte header: ``[uint32 file_count] [uint32 index_size]``.
- *file_count* variable-length index entries (size, offset, UTF-16LE name).
- Concatenated file data starting at offset ``8 + index_size``.

Script files (``.ws2``, ``.json``) are stored with a byte-rotation cipher.
``.PSP`` files contain LZSS-compressed PSB data.
"""

import fnmatch
import logging
import os
import pathlib
import struct

logger = logging.getLogger(__name__)

HEADER_SIZE = 8
_UTF16_CHAR_SIZE = 2
_SCRIPT_EXTENSIONS = frozenset(('.ws2', '.json'))


def is_script_file(name: str) -> bool:
    """Return True if *name* has a script extension (``.ws2`` or ``.json``)."""
    return os.path.splitext(name)[1].lower() in _SCRIPT_EXTENSIONS


def decrypt_script(data: bytes) -> bytes:
    """Decrypt script data by rotating each byte right by 2 bits."""
    return bytes(((b >> 2) | (b << 6)) & 0xFF for b in data)


def encrypt_script(data: bytes) -> bytes:
    """Encrypt script data by rotating each byte left by 2 bits."""
    return bytes(((b << 2) | (b >> 6)) & 0xFF for b in data)


def decompress_psp(data: bytes) -> bytes:
    """Decompress LZSS-compressed PSP data.

    *data* begins with a 4-byte little-endian unpacked size, followed by the
    LZSS compressed stream.
    """
    unpacked_size = struct.unpack_from('<I', data, 0)[0]
    if unpacked_size == 0:
        return b''

    output = bytearray(unpacked_size)
    frame = bytearray(0x1000)
    frame_pos = 1
    dst = 0
    src = 4  # skip the unpacked_size header

    while dst < unpacked_size:
        ctl = data[src]
        src += 1
        for bit in range(8):
            if dst >= unpacked_size:
                break
            if ctl & (1 << bit):
                # Literal byte
                b = data[src]
                src += 1
                output[dst] = b
                dst += 1
                frame[frame_pos & 0xFFF] = b
                frame_pos += 1
            else:
                # Back-reference
                hi = data[src]
                lo = data[src + 1]
                src += 2
                ref_offset = (hi << 4) | (lo >> 4)
                length = (lo & 0x0F) + 2
                for _ in range(length):
                    if dst >= unpacked_size:
                        break
                    v = frame[ref_offset & 0xFFF]
                    output[dst] = v
                    dst += 1
                    frame[frame_pos & 0xFFF] = v
                    frame_pos += 1
                    ref_offset += 1

    return bytes(output)


class ARCInfo:
    """Metadata for a single entry in an ARC archive."""

    __slots__ = (
        'file_name',
        'offset',
        'size',
    )

    def __init__(self):
        self.file_name = ''
        self.offset = 0
        self.size = 0

    def __repr__(self):
        return f"ARCInfo(file_name={self.file_name!r}, offset={self.offset!r}, size={self.size!r})"


class ARCFile:
    """Read or create AdvHD ARC archives.

    Use ``mode='r'`` (default) to read an existing archive, or ``mode='w'``
    to create a new one.
    """

    def __init__(self, file, mode='r'):
        if isinstance(file, os.PathLike):
            file = os.fspath(file)

        self.fp = None

        if mode not in ('r', 'w'):
            raise ValueError(f"Invalid mode: {mode!r} (expected 'r' or 'w')")

        self.filename = file
        self.mode = mode
        self.files: list[ARCInfo] = []
        self._is_model = 'Model' in os.path.basename(file)

        if mode == 'r':
            self.fp = open(file, 'rb')
            try:
                self._read_index()
            except Exception:
                fp = self.fp
                self.fp = None
                fp.close()
                raise
        else:
            self.fp = open(file, 'wb')
            self._pending: list[tuple[str, str, bool]] = []  # (filepath, arcname, encrypt)

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
        if self.mode == 'w':
            self._finalize()
        fp = self.fp
        self.fp = None
        fp.close()

    # -- reading ---------------------------------------------------------------

    def _read_index(self):
        """Parse the index from the archive header."""
        raw = self.fp.read(HEADER_SIZE)
        if len(raw) < HEADER_SIZE:
            raise ValueError("File too small to be an ARC archive")
        file_count, index_size = struct.unpack('<II', raw)
        base_offset = HEADER_SIZE + index_size

        for _ in range(file_count):
            size, offset = struct.unpack('<II', self.fp.read(8))
            # Read UTF-16LE null-terminated name.
            name_bytes = b''
            while True:
                char = self.fp.read(_UTF16_CHAR_SIZE)
                if len(char) < _UTF16_CHAR_SIZE:
                    raise ValueError("Truncated ARC index")
                if char == b'\x00\x00':
                    break
                name_bytes += char
            name = name_bytes.decode('utf-16-le')

            info = ARCInfo()
            info.file_name = name
            info.offset = base_offset + offset
            info.size = size
            self.files.append(info)

        if self.fp.tell() != base_offset:
            raise ValueError("ARC index size mismatch")

    def read(self, member: 'ARCInfo | str', decrypt: bool = True) -> bytes:
        """Read the contents of *member*.

        *member* can be an :class:`ARCInfo` instance or a file name string.

        If *decrypt* is True, encrypted script files are decrypted automatically.
        """
        if self.fp is None:
            raise ValueError("I/O operation on closed ARC archive")

        if not isinstance(member, ARCInfo):
            for f in self.files:
                if f.file_name == member:
                    member = f
                    break
            else:
                raise KeyError(f"No member named {member!r}")

        self.fp.seek(member.offset)
        data = self.fp.read(member.size)

        if decrypt and not self._is_model and is_script_file(member.file_name):
            data = decrypt_script(data)
        return data

    def extract(self, member: 'ARCInfo | str', path: str | os.PathLike, decrypt: bool = True):
        """Extract *member* to a file at *path*."""
        data = self.read(member, decrypt=decrypt)
        with open(path, 'xb') as f:
            f.write(data)

    def extract_all(self, path: str | os.PathLike, glob: str | None = None, decrypt: bool = True):
        """Extract all members to directory *path*."""
        for f in self.files:
            if glob and not fnmatch.fnmatch(f.file_name, glob):
                continue
            parts = f.file_name.replace('\\', '/').split('/')
            filepath = os.path.abspath(os.path.join(path, *parts))
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            self.extract(f, filepath, decrypt=decrypt)

    # -- creation --------------------------------------------------------------

    def write(self, filepath: str | os.PathLike, arcname: str | None = None, encrypt: bool = True):
        """Queue *filepath* for inclusion in the archive.

        *arcname* is the name stored in the archive.  It defaults to the
        basename of *filepath*.

        If *encrypt* is True, script files (``.ws2``, ``.json``) are encrypted
        automatically before writing.
        """
        if self.fp is None:
            raise ValueError("I/O operation on closed ARC archive")
        if self.mode != 'w':
            raise ValueError("write() requires mode='w'")

        if isinstance(filepath, os.PathLike):
            filepath = os.fspath(filepath)

        if arcname is None:
            arcname = os.path.basename(filepath)

        self._pending.append((filepath, arcname, encrypt))

    def write_all(self, path: str | os.PathLike, glob: str | None = None, prefix: str = '', encrypt: bool = True):
        """Recursively add files from directory *path* to the archive."""
        if isinstance(path, str):
            path = pathlib.Path(path)

        for entry in sorted(path.iterdir()):
            if entry.is_dir():
                sub_prefix = prefix + entry.name + '/'
                self.write_all(entry, glob=glob, prefix=sub_prefix, encrypt=encrypt)
            elif entry.is_file():
                arcname = prefix + entry.name
                if glob and not fnmatch.fnmatch(arcname, glob):
                    continue
                self.write(entry, arcname=arcname, encrypt=encrypt)

    def _finalize(self):
        """Write the header, index, and file data."""
        if self.fp is None:
            raise ValueError("I/O operation on closed ARC archive")
        if not self._pending:
            return

        file_count = len(self._pending)

        # Compute index_size: each entry is 8 bytes + UTF-16LE name + 2-byte null terminator.
        index_entries: list[tuple[bytes, bytes]] = []  # (name_encoded, file_data)
        for filepath, arcname, do_encrypt in self._pending:
            name_encoded = arcname.encode('utf-16-le') + b'\x00\x00'
            with open(filepath, 'rb') as f:
                data = f.read()
            if do_encrypt and is_script_file(arcname):
                data = encrypt_script(data)
            index_entries.append((name_encoded, data))

        index_size = sum(8 + len(name) for name, _data in index_entries)

        # Write header.
        self.fp.write(struct.pack('<II', file_count, index_size))

        # Write index entries.
        offset = 0
        for name_encoded, data in index_entries:
            self.fp.write(struct.pack('<II', len(data), offset))
            self.fp.write(name_encoded)
            offset += len(data)

        # Write file data.
        for _name_encoded, data in index_entries:
            self.fp.write(data)
