"""Reader and writer for AGSD GSP resource archives.

A GSP archive is a flat, uncompressed bundle of files.  The format consists of:

- A 4-byte little-endian file count.
- *count* index entries of 64 bytes each (offset, size, null-padded filename).
- Concatenated file data.

There is no magic number; detection relies on the ``.gsp`` file extension.
"""

import fnmatch
import logging
import os
import pathlib
import struct

from tamago.formats.gsp import spt_crypto

logger = logging.getLogger(__name__)

ENTRY_SIZE = 64
FILENAME_SIZE = 56
HEADER_SIZE = 4


class GSPInfo:
    """Metadata for a single entry in a GSP archive."""

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
        return f"GSPInfo(file_name={self.file_name!r}, offset={self.offset!r}, size={self.size!r})"


class GSPFile:
    """Read or create GSP archives.

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
        self.files: list[GSPInfo] = []

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
            raise ValueError("File too small to be a GSP archive")
        (count,) = struct.unpack('<I', raw)

        for _ in range(count):
            entry_data = self.fp.read(ENTRY_SIZE)
            if len(entry_data) < ENTRY_SIZE:
                raise ValueError("Truncated GSP index")
            offset, size = struct.unpack_from('<II', entry_data, 0)
            name_bytes = entry_data[8:]
            name = name_bytes.split(b'\x00', 1)[0].decode('ascii')

            info = GSPInfo()
            info.file_name = name
            info.offset = offset
            info.size = size
            self.files.append(info)

    def read(self, member: 'GSPInfo | str', decrypt: bool = True) -> bytes:
        """Read the contents of *member*.

        *member* can be a :class:`GSPInfo` instance or a file name string.

        If *decrypt* is True, encrypted SPT/DAT files are decrypted
        automatically.  Non-encrypted files are returned unchanged.
        """
        if self.fp is None:
            raise ValueError("I/O operation on closed GSP archive")

        if not isinstance(member, GSPInfo):
            for f in self.files:
                if f.file_name == member:
                    member = f
                    break
            else:
                raise KeyError(f"No member named {member!r}")

        self.fp.seek(member.offset)
        data = self.fp.read(member.size)
        if decrypt and spt_crypto.is_encrypted(member.file_name):
            data = spt_crypto.decrypt(data)
        return data

    def extract(self, member: 'GSPInfo | str', path: str | os.PathLike, decrypt: bool = True):
        """Extract *member* to a file at *path*.

        If *decrypt* is True, encrypted SPT/DAT files are decrypted
        before writing.
        """
        data = self.read(member, decrypt=decrypt)
        with open(path, 'xb') as f:
            f.write(data)

    def extract_all(self, path: str | os.PathLike, glob: str | None = None, decrypt: bool = True):
        """Extract all members to directory *path*.

        If *glob* is given, only members whose names match the pattern are
        extracted.  If *decrypt* is True, encrypted SPT/DAT files are
        decrypted before writing.
        """
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

        If *encrypt* is True, SPT/DAT files are encrypted automatically
        before writing.  Non-encrypted file types are stored unchanged.
        """
        if self.fp is None:
            raise ValueError("I/O operation on closed GSP archive")
        if self.mode != 'w':
            raise ValueError("write() requires mode='w'")

        if isinstance(filepath, os.PathLike):
            filepath = os.fspath(filepath)

        if arcname is None:
            arcname = os.path.basename(filepath)

        name_bytes = arcname.encode('ascii')
        if len(name_bytes) > FILENAME_SIZE:
            raise ValueError(f"File name too long ({len(name_bytes)} > {FILENAME_SIZE}): {arcname!r}")

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
        """Write the index and file data."""
        if self.fp is None:
            raise ValueError("I/O operation on closed GSP archive")
        if not self._pending:
            return

        count = len(self._pending)
        data_offset = HEADER_SIZE + count * ENTRY_SIZE

        # Read all file contents, encrypting SPT/DAT files as needed.
        file_data = []
        for filepath, arcname, do_encrypt in self._pending:
            with open(filepath, 'rb') as f:
                data = f.read()
            if do_encrypt and spt_crypto.is_encrypted(arcname):
                data = spt_crypto.encrypt(data)
            file_data.append(data)

        # Write header.
        self.fp.write(struct.pack('<I', count))

        # Write index entries.
        offset = data_offset
        for i, (_filepath, arcname, _encrypt) in enumerate(self._pending):
            size = len(file_data[i])
            name_bytes = arcname.encode('ascii')
            padded_name = name_bytes + b'\x00' * (FILENAME_SIZE - len(name_bytes))
            self.fp.write(struct.pack('<II', offset, size))
            self.fp.write(padded_name)

            info = GSPInfo()
            info.file_name = arcname
            info.offset = offset
            info.size = size
            self.files.append(info)

            offset += size
            logger.debug('packed %s: offset=%#x size=%#x', arcname, info.offset, info.size)

        # Write file data.
        for data in file_data:
            self.fp.write(data)
