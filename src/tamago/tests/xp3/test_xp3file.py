import logging
import os
import struct
import tempfile
import zlib

import pytest

from tamago.formats.xp3 import XP3File
from tamago.formats.xp3.encryption import HashXorEncryption

SAMPLES = os.path.join(os.path.dirname(__file__), 'samples')

HELLO = b'Hello, world!'
BINARY = bytes(range(256))
EMPTY = b''


def _extract_member(xp3, member):
    """Extract a member to a temp file and return its contents."""
    with tempfile.TemporaryDirectory() as tmpdir:
        outpath = os.path.join(tmpdir, os.path.basename(member.file_name))
        xp3.extract(member, outpath)
        with open(outpath, 'rb') as f:
            return f.read()


ENC = HashXorEncryption(shift=3)


@pytest.mark.integration
@pytest.mark.parametrize(
    'sample, encryption, expected_encrypted',
    [
        ('single_compressed.xp3', None, False),
        ('single_uncompressed.xp3', None, False),
        ('single_encrypted_compressed.xp3', ENC, True),
        ('single_encrypted_uncompressed.xp3', ENC, True),
    ],
)
class TestSingleFile:
    def test_content(self, sample, encryption, expected_encrypted):
        with XP3File(os.path.join(SAMPLES, sample), encryption=encryption) as xp3:
            assert len(xp3.files) == 1
            assert xp3.files[0].file_name == 'hello.txt'
            assert xp3.files[0].encrypted == expected_encrypted
            assert _extract_member(xp3, xp3.files[0]) == HELLO


@pytest.mark.integration
@pytest.mark.parametrize(
    'sample, encryption',
    [
        ('multi_compressed.xp3', None),
        ('multi_encrypted.xp3', ENC),
    ],
)
class TestMultiFile:
    def test_all_contents(self, sample, encryption):
        expected = {'hello.txt': HELLO, 'binary.bin': BINARY, 'empty.dat': EMPTY}
        with XP3File(os.path.join(SAMPLES, sample), encryption=encryption) as xp3:
            assert len(xp3.files) == len(expected)
            for member in xp3.files:
                assert _extract_member(xp3, member) == expected[member.file_name]


@pytest.mark.integration
class TestEmptyFile:
    def test_content(self):
        with XP3File(os.path.join(SAMPLES, 'empty_file.xp3')) as xp3:
            assert xp3.files[0].original_size == 0
            assert _extract_member(xp3, xp3.files[0]) == EMPTY


@pytest.mark.integration
class TestExtractByName:
    def test_extract_by_name(self):
        with XP3File(os.path.join(SAMPLES, 'multi_compressed.xp3')) as xp3:
            with tempfile.TemporaryDirectory() as tmpdir:
                outpath = os.path.join(tmpdir, 'hello.txt')
                xp3.extract('hello.txt', outpath)
                with open(outpath, 'rb') as f:
                    assert f.read() == HELLO

    def test_extract_missing_name(self):
        with XP3File(os.path.join(SAMPLES, 'multi_compressed.xp3')) as xp3:
            with tempfile.TemporaryDirectory() as tmpdir:
                with pytest.raises(ValueError, match="No member named"):
                    xp3.extract('nonexistent.txt', os.path.join(tmpdir, 'out'))


@pytest.mark.integration
@pytest.mark.parametrize(
    'sample, encryption, expected',
    [
        ('single_compressed.xp3', None, {'hello.txt': HELLO}),
        ('single_encrypted_compressed.xp3', ENC, {'hello.txt': HELLO}),
        ('multi_compressed.xp3', None, {'hello.txt': HELLO, 'binary.bin': BINARY, 'empty.dat': EMPTY}),
        ('empty_file.xp3', None, {'empty.dat': EMPTY}),
    ],
)
class TestOpen:
    def test_open_by_name(self, sample, encryption, expected):
        with XP3File(os.path.join(SAMPLES, sample), encryption=encryption) as xp3:
            for name, content in expected.items():
                with xp3.open(name) as f:
                    assert f.read() == content

    def test_open_by_info(self, sample, encryption, expected):
        with XP3File(os.path.join(SAMPLES, sample), encryption=encryption) as xp3:
            for member in xp3.files:
                if member.file_name in expected:
                    with xp3.open(member) as f:
                        assert f.read() == expected[member.file_name]

    def test_open_partial_read(self, sample, encryption, expected):
        with XP3File(os.path.join(SAMPLES, sample), encryption=encryption) as xp3:
            for name, content in expected.items():
                with xp3.open(name) as f:
                    assert f.read(min(4, len(content))) == content[:4]

    def test_open_seek(self, sample, encryption, expected):
        with XP3File(os.path.join(SAMPLES, sample), encryption=encryption) as xp3:
            for name, content in expected.items():
                if len(content) < 2:
                    continue
                with xp3.open(name) as f:
                    f.seek(2)
                    assert f.read(2) == content[2:4]

    def test_open_missing_name(self, sample, encryption, expected):
        with XP3File(os.path.join(SAMPLES, sample), encryption=encryption) as xp3:
            with pytest.raises(KeyError):
                xp3.open('nonexistent.txt')

    def test_open_invalid_mode(self, sample, encryption, expected):
        with XP3File(os.path.join(SAMPLES, sample), encryption=encryption) as xp3:
            name = next(iter(expected))
            with pytest.raises(ValueError, match="mode"):
                xp3.open(name, mode='w')

    def test_open_text_mode(self, sample, encryption, expected):
        with XP3File(os.path.join(SAMPLES, sample), encryption=encryption) as xp3:
            if 'hello.txt' not in expected:
                return
            with xp3.open('hello.txt', mode='r') as f:
                assert f.read() == 'Hello, world!'

    def test_open_text_mode_encoding(self, sample, encryption, expected):
        with XP3File(os.path.join(SAMPLES, sample), encryption=encryption) as xp3:
            if 'hello.txt' not in expected:
                return
            with xp3.open('hello.txt', mode='r', encoding='ascii') as f:
                assert f.read() == 'Hello, world!'

    def test_open_text_mode_readline(self, sample, encryption, expected):
        with XP3File(os.path.join(SAMPLES, sample), encryption=encryption) as xp3:
            if 'hello.txt' not in expected:
                return
            with xp3.open('hello.txt', mode='r') as f:
                assert f.readline() == 'Hello, world!'


@pytest.mark.integration
class TestRoundTrip:
    """Write a new archive and read it back to verify consistency."""

    @pytest.mark.parametrize('encryption', [None, ENC])
    def test_round_trip(self, encryption):
        with tempfile.TemporaryDirectory() as tmpdir:
            srcfile = os.path.join(tmpdir, 'test.txt')
            with open(srcfile, 'wb') as f:
                f.write(BINARY)

            xp3path = os.path.join(tmpdir, 'round_trip.xp3')
            with XP3File(xp3path, 'x', encryption=encryption) as xp3:
                xp3.write(srcfile)

            with XP3File(xp3path, encryption=encryption) as xp3:
                assert xp3.files[0].encrypted == (encryption is not None)
                assert _extract_member(xp3, xp3.files[0]) == BINARY


@pytest.mark.integration
class TestFalseEncryptedFlag:
    """Files flagged as encrypted but not actually encrypted should extract correctly."""

    def test_compressed_fallback(self):
        """Decryption of a not-actually-encrypted file should fall back to raw decompression."""
        from tamago.formats.xp3.models import XP3_FLAG_ENCRYPTED

        content = b'Alice was beginning to get very tired of sitting by her sister on the bank'
        with tempfile.TemporaryDirectory() as tmpdir:
            srcfile = os.path.join(tmpdir, 'alice.txt')
            with open(srcfile, 'wb') as f:
                f.write(content)

            xp3path = os.path.join(tmpdir, 'data.xp3')
            # Write without encryption (data is not encrypted)
            with XP3File(xp3path, 'x') as xp3:
                xp3.write(srcfile)
                # Manually set the encrypted flag (simulates a broken flag)
                xp3.files[0].flags |= XP3_FLAG_ENCRYPTED

            # Open with encryption; the file is flagged encrypted but data isn't.
            # Decryption should fail silently and fall back to raw decompression.
            with XP3File(xp3path, encryption=ENC) as xp3:
                assert xp3.files[0].encrypted is True
                assert _extract_member(xp3, xp3.files[0]) == content


@pytest.mark.unit
class TestInvalidFile:
    def test_bad_magic(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bad = os.path.join(tmpdir, 'bad.xp3')
            with open(bad, 'wb') as f:
                f.write(b'not an xp3 file at all')
            with pytest.raises(ValueError, match="Invalid magic number"):
                XP3File(bad)

    def test_invalid_mode(self):
        with pytest.raises(ValueError, match="mode"):
            XP3File('dummy.xp3', mode='w')


@pytest.mark.integration
class TestUncompressedFileTable:
    """XP3 files with an uncompressed file table (indexbyte 0x00) should parse correctly."""

    def test_uncompressed_round_trip(self):
        """Write an archive, rewrite its file table as uncompressed, and read it back."""
        with tempfile.TemporaryDirectory() as tmpdir:
            srcfile = os.path.join(tmpdir, 'hello.txt')
            with open(srcfile, 'wb') as f:
                f.write(HELLO)

            # Create a normal (compressed file table) archive first
            xp3path = os.path.join(tmpdir, 'test.xp3')
            with XP3File(xp3path, 'x') as xp3:
                xp3.write(srcfile)

            # Read it, find the file table, and rewrite with uncompressed table
            with open(xp3path, 'rb') as f:
                raw = f.read()

            # Parse header to find file table
            info_offset = struct.unpack('<Q', raw[11:19])[0]
            pos = info_offset
            indexbyte = raw[pos]
            pos += 1
            if indexbyte == 0x80:
                pos += 8
                info_offset = struct.unpack('<Q', raw[pos : pos + 8])[0]
                pos = info_offset
                indexbyte = raw[pos]
                pos += 1
            assert indexbyte == 0x01, "Expected compressed file table"
            compressed_size = struct.unpack('<Q', raw[pos : pos + 8])[0]
            uncompressed_size = struct.unpack('<Q', raw[pos + 8 : pos + 16])[0]
            compressed_data = raw[pos + 16 : pos + 16 + compressed_size]

            table_data = zlib.decompress(compressed_data)
            assert len(table_data) == uncompressed_size

            # Rebuild XP3 with uncompressed file table (indexbyte 0x00)
            data_portion = raw[:info_offset]
            new_table = b'\x00' + struct.pack('<Q', len(table_data)) + table_data
            # Update the file table offset in the header
            new_raw = bytearray(data_portion + new_table)
            # The offset at position 11 points to the file table
            struct.pack_into('<Q', new_raw, 11, info_offset)

            uncompressed_xp3 = os.path.join(tmpdir, 'uncompressed_table.xp3')
            with open(uncompressed_xp3, 'wb') as f:
                f.write(new_raw)

            # Verify it parses correctly
            with XP3File(uncompressed_xp3) as xp3:
                assert len(xp3.files) == 1
                assert xp3.files[0].file_name == 'hello.txt'
                assert _extract_member(xp3, xp3.files[0]) == HELLO


@pytest.mark.integration
class TestLongFilename:
    """Extraction should skip files whose names exceed filesystem limits."""

    LONG_NAME = "A" * 300 + ".txt"  # 304 chars, exceeds 255-byte limit

    def _make_archive_with_long_name(self, tmpdir):
        """Create an XP3 with a short-named file, then patch the name to be overlong."""
        srcfile = os.path.join(tmpdir, "alice.txt")
        with open(srcfile, "wb") as f:
            f.write(b"Down the rabbit hole.")

        xp3path = os.path.join(tmpdir, "long_name.xp3")
        with XP3File(xp3path, "x") as xp3:
            xp3.write(srcfile)
        return xp3path

    def test_extract_skips_long_filename(self, caplog):
        """extract() should warn and return without creating a file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            xp3path = self._make_archive_with_long_name(tmpdir)
            with XP3File(xp3path) as xp3:
                member = xp3.files[0]
                # Patch the member's file_name to be overlong
                member.file_name = self.LONG_NAME
                outpath = os.path.join(tmpdir, "out", self.LONG_NAME)
                os.makedirs(os.path.dirname(outpath), exist_ok=True)

                with caplog.at_level(logging.WARNING, logger="tamago.formats.xp3.xp3file"):
                    xp3.extract(member, outpath)

                assert not os.path.exists(outpath)
                assert any("Skipping" in r.message and "file name too long" in r.message for r in caplog.records)

    def test_extract_all_skips_long_filename(self, caplog):
        """extract_all() should skip overlong names and extract the rest."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create archive with two files: one normal, one will be patched to overlong
            src_normal = os.path.join(tmpdir, "normal.txt")
            with open(src_normal, "wb") as f:
                f.write(b"Curiouser and curiouser!")

            src_long = os.path.join(tmpdir, "placeholder.txt")
            with open(src_long, "wb") as f:
                f.write(b"Off with her head!")

            xp3path = os.path.join(tmpdir, "multi_long.xp3")
            with XP3File(xp3path, "x") as xp3:
                xp3.write(src_normal)
                xp3.write(src_long)

            with XP3File(xp3path) as xp3:
                # Patch the second member to have an overlong name
                for member in xp3.files:
                    if member.file_name == "placeholder.txt":
                        member.file_name = self.LONG_NAME
                        break

                outdir = os.path.join(tmpdir, "extracted")
                with caplog.at_level(logging.WARNING, logger="tamago.formats.xp3.xp3file"):
                    xp3.extract_all(outdir)

                # Normal file was extracted
                assert os.path.exists(os.path.join(outdir, "normal.txt"))
                with open(os.path.join(outdir, "normal.txt"), "rb") as f:
                    assert f.read() == b"Curiouser and curiouser!"

                # Long-named file was skipped
                assert not os.path.exists(os.path.join(outdir, self.LONG_NAME))
                assert any("Skipping" in r.message for r in caplog.records)


@pytest.mark.integration
class TestExtractSimpleCryptDecode:
    """extract() transparently decodes simple-crypt text by default."""

    ALICE = "Alice fell down the rabbit hole."
    ALICE_UTF16 = b"\xff\xfe" + ALICE.encode("utf-16-le")

    def _make_archive_with_simple_crypt(self, tmpdir):
        from tamago.formats.xp3 import simple_crypt

        encoded = simple_crypt.encode(self.ALICE_UTF16)
        scrpath = os.path.join(tmpdir, "script.ks")
        with open(scrpath, "wb") as f:
            f.write(encoded)
        xp3path = os.path.join(tmpdir, "scripts.xp3")
        with XP3File(xp3path, "x") as xp3:
            xp3.write(scrpath)
        return xp3path, encoded

    def test_decodes_by_default(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            xp3path, _ = self._make_archive_with_simple_crypt(tmpdir)
            outdir = os.path.join(tmpdir, "out")
            with XP3File(xp3path) as xp3:
                xp3.extract_all(outdir)
            with open(os.path.join(outdir, "script.ks"), "rb") as f:
                assert f.read() == self.ALICE_UTF16

    def test_no_decode_keeps_raw(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            xp3path, encoded = self._make_archive_with_simple_crypt(tmpdir)
            outdir = os.path.join(tmpdir, "out")
            with XP3File(xp3path) as xp3:
                xp3.extract_all(outdir, decode_text=False)
            with open(os.path.join(outdir, "script.ks"), "rb") as f:
                assert f.read() == encoded

    def test_binary_unchanged(self):
        """Binaries that don't start with FE FE pass through even with decode_text=True."""
        with tempfile.TemporaryDirectory() as tmpdir:
            binpath = os.path.join(tmpdir, "image.bin")
            with open(binpath, "wb") as f:
                f.write(BINARY)
            xp3path = os.path.join(tmpdir, "binary.xp3")
            with XP3File(xp3path, "x") as xp3:
                xp3.write(binpath)
            outdir = os.path.join(tmpdir, "out")
            with XP3File(xp3path) as xp3:
                xp3.extract_all(outdir)
            with open(os.path.join(outdir, "image.bin"), "rb") as f:
                assert f.read() == BINARY
