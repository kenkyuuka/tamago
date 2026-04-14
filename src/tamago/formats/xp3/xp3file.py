import errno
import fnmatch
import io
import logging
import os
import threading
import zlib

from construct import Container, Int64ul

from .models import (
    XP3_FLAG_ENCRYPTED,
    XP3_MAGIC,
    XP3CreateHeader,
    XP3FileTable,
    XP3IndexHeader,
    XP3Info,
)

logger = logging.getLogger(__name__)


class XP3File:
    """Class with methods to open, read, close, and list xp3 files.

    x = XP3File(file, mode="r", encryption=None)

    file: Either the path to the file, or a file-like object.
          If it is a path, the file will be opened and closed by XP3File.
    mode: The mode can be either read 'r' or exclusive create 'x'.
    compressed: whether the file table is compressed.
    encryption: None or an XP3Encryption class.

    """

    fp = None

    def __init__(self, file, mode="r", compressed=True, encryption=None, force_encrypt=False):
        """Open the XP3 file with mode read 'r' or exclusive create 'x'."""
        if mode not in ('r', 'x'):
            raise ValueError("XP3File requires mode 'r' or 'x'")

        self.mode = mode + 'b'
        self.compressed = compressed
        self.encryption = encryption
        self.force_encrypt = force_encrypt
        self.files = []
        self.HEADER_START = 0

        if isinstance(file, os.PathLike):
            file = os.fspath(file)
        if isinstance(file, str):
            self._filePassed = 0
            self.filename = file
            self.fp = open(file, self.mode)
        else:
            self._filePassed = 1
            self.fp = file
            self.filename = getattr(file, 'name', None)
        self._fileRefCnt = 1
        self._lock = threading.RLock()
        self._seekable = True
        self._writing = False

        try:
            if mode == 'r':
                self.read_files()
            else:
                self.fp.write(XP3CreateHeader.build({"real_info_offset": 0}))
        except Exception:
            fp = self.fp
            self.fp = None
            self._fpclose(fp)
            raise

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def __del__(self):
        """Call the "close()" method in case the user forgot."""
        self.close()

    def _fpclose(self, fp):
        assert self._fileRefCnt > 0
        self._fileRefCnt -= 1
        if not self._fileRefCnt and not self._filePassed:
            fp.close()

    def close(self):
        """Close the file."""
        if self.fp is None:
            return

        if self.mode == 'xb':
            self.write_info()

        fp = self.fp
        self.fp = None
        self._fpclose(fp)

    def write_info(self):
        self.fp.seek(0, 2)
        info_start = self.fp.tell()
        data = b"".join(f.get_info_bytes() for f in self.files)
        uncompressed_size = len(data)
        if self.compressed:
            data = zlib.compress(data)
        self.fp.write(
            XP3IndexHeader.build(
                {
                    "compressed": self.compressed,
                    "compressed_size": len(data) if self.compressed else None,
                    "uncompressed_size": uncompressed_size,
                }
            )
        )
        self.fp.write(data)
        self.fp.seek(0x20, 0)
        self.fp.write(Int64ul.build(info_start))

    def write(self, filepath, arcname=None, compressed=True):
        if isinstance(filepath, os.PathLike):
            filepath = os.fspath(filepath)
        if isinstance(filepath, str):
            if not arcname:
                arcname = os.path.basename(filepath)
            fp = open(filepath, 'rb')
        else:
            raise ValueError(f'Invalid filepath: {filepath!r}')

        file_size = os.fstat(fp.fileno()).st_size
        xi = XP3Info(
            file_name=arcname,
            original_size=file_size,
            flags=XP3_FLAG_ENCRYPTED if self.encryption else 0,
        )
        segment = Container(flags=0, offset=0, original_size=file_size, compressed_size=0)
        fp.seek(0, 0)

        # Read all data to compute adler hash on plaintext
        raw = fp.read()
        xi.key = zlib.adler32(raw)

        # Compress
        if compressed:
            segment.flags |= 1
            raw = zlib.compress(raw)

        # Encrypt (after compression)
        if self.encryption:
            raw = self.encryption.encrypt(raw, xi, segment)

        self.fp.seek(0, 2)
        segment.offset = self.fp.tell()
        self.fp.write(raw)
        segment.compressed_size = len(raw)
        xi.compressed_size = segment.compressed_size
        xi.segments = [segment]
        self.files.append(xi)

    def write_all(self, path, glob='*', prefix='', compressed=True):
        for p in path.glob(glob):
            if p.is_file:
                self.write(p, arcname=prefix + p.name, compressed=compressed)
            elif p.is_dir:
                self.write_all(p, prefix=p.name + '/', compressed=compressed)

    def read_files(self):
        self.HEADER_START = 0
        self.fp.seek(0, 0)
        magic = self.fp.read(11)
        if magic != XP3_MAGIC:
            raise ValueError("Invalid magic number. This does not appear to be an XP3 file.")
        info_offset = Int64ul.parse_stream(self.fp)

        self.fp.seek(self.HEADER_START, 0)
        self.fp.seek(info_offset, 1)

        if self.fp.read(1) == b'\x80':
            self.fp.seek(8, 1)
            info_offset = Int64ul.parse_stream(self.fp)
            self.fp.seek(self.HEADER_START + info_offset, 0)
        else:
            self.fp.seek(-1, 1)

        header = XP3IndexHeader.parse_stream(self.fp)
        if header.compressed:
            table_bytes = zlib.decompress(self.fp.read(header.compressed_size))
        else:
            table_bytes = self.fp.read(header.uncompressed_size)

        files = {}
        elifs = {}

        for section in XP3FileTable.parse(table_bytes):
            logger.debug('Section: %r', section.tag)
            if section.tag == b'eliF':
                elifs[section.data.file_hash] = section.data.file_name
                logger.debug('Hash: %r; Name: %r', section.data.file_hash, section.data.file_name)
            elif section.tag == b'File':
                info = XP3Info()
                for chunk in section.data:
                    logger.debug('Chunk: %r', chunk.tag)
                    if chunk.tag == b'info':
                        info.flags = chunk.data.flags
                        if info.encrypted and not self.encryption:
                            logger.warning("Encountered encrypted file, but encryption not set.")
                        info.original_size = chunk.data.original_size
                        info.compressed_size = chunk.data.compressed_size
                        info.file_name = chunk.data.file_name
                        logger.debug('%r (%r/%r bytes)', info.file_name, info.compressed_size, info.original_size)
                    elif chunk.tag == b'adlr':
                        info.key = chunk.data.key
                        logger.debug('adlr: %s', hex(info.key))
                    elif chunk.tag == b'time':
                        info.timestamp = chunk.data.timestamp
                        logger.debug('time: %r', info.timestamp)
                    elif chunk.tag == b'segm':
                        info.segments = list(chunk.data)
                        for seg in info.segments:
                            logger.debug(
                                'f: %r; o: %s (%r/%r bytes)',
                                seg.flags,
                                seg.offset,
                                seg.compressed_size,
                                seg.original_size,
                            )
                if info.key in files:
                    logger.debug('duplicate adlr key 0x%08x for %r', info.key, info.file_name)
                files[info.key] = info
        self.files = list(files.values())
        for k, name in elifs.items():
            f = files[k]
            info = XP3Info(
                file_name=name,
                key=k,
                flags=f.flags,
                original_size=f.original_size,
                compressed_size=f.compressed_size,
                segments=f.segments,
            )
            self.files.append(info)

    def open(self, member, mode='rb', encoding=None, errors=None, newline=None):
        """Return a file-like object for a member's decompressed, decrypted contents.

        member: Either a file name (str) or an XP3Info object.
        mode: 'rb' for binary (default), 'r' for text.
        encoding: Text encoding (only for text mode, default 'utf-8').
        errors: Text error handling (only for text mode).
        newline: Newline handling (only for text mode).
        """
        if mode not in ('r', 'rb'):
            raise ValueError(f"open() requires mode 'r' or 'rb', not {mode!r}")

        if not isinstance(member, XP3Info):
            for f in self.files:
                if f.file_name == member:
                    member = f
                    break
            else:
                raise KeyError(member)

        buf = io.BytesIO()
        for s in member.segments:
            self.fp.seek(s.offset, 0)
            data = self.fp.read(s.compressed_size)
            if self.encryption and (member.encrypted or self.force_encrypt):
                decrypted = self.encryption.decrypt(data, member, s)
                if s.compressed:
                    try:
                        data = zlib.decompress(decrypted)
                    except zlib.error:
                        # Decryption produced invalid data; the file may not
                        # actually be encrypted despite the flag.  Fall back
                        # to raw decompression.
                        logger.debug(
                            "%s: decryption+decompression failed, retrying without decryption",
                            member.file_name,
                        )
                        data = zlib.decompress(data)
                else:
                    data = decrypted
            elif s.compressed:
                data = zlib.decompress(data)
            buf.write(data)
        buf.seek(0)

        if mode == 'r':
            return io.TextIOWrapper(buf, encoding=encoding or 'utf-8', errors=errors, newline=newline)
        return buf

    def extract(self, member, path, convert_tlg=False):
        if not isinstance(member, XP3Info):
            for f in self.files:
                if f.file_name == member:
                    member = f
                    break
            else:
                raise ValueError(f"No member named {member!r}.")

        if convert_tlg and member.file_name.lower().endswith('.tlg'):
            from tamago.formats.xp3.tlg import open_tlg

            with self.open(member) as src:
                img = open_tlg(src)
            png_path = os.path.splitext(path)[0] + '.png'
            img.save(png_path, 'PNG')
            return

        try:
            dst_fp = open(path, 'xb')
        except OSError as e:
            if e.errno == errno.ENAMETOOLONG:
                logger.warning("Skipping %r: file name too long for filesystem", member.file_name)
                return
            raise

        with self.open(member) as src, dst_fp as dst:
            dst.write(src.read())
            if dst.tell() != member.original_size:
                logger.warning(f"Expected {member.original_size} uncompressed bytes, got {dst.tell()} for {member!r}")
        if hasattr(member, 'timestamp'):
            logger.warning("Member %r has timestamp %r", member, member.timestamp)

    def extract_all(self, path, glob=None, convert_tlg=False):
        for f in self.files:
            if glob and not fnmatch.fnmatch(f.file_name, glob):
                continue
            filepath = os.path.abspath(os.path.join(path, *f.file_name.split('/')))
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            self.extract(f, filepath, convert_tlg=convert_tlg)
