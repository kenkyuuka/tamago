import struct

import pytest
from construct import Container

from tamago.formats.xp3.models import XP3Info


@pytest.mark.unit
class TestXP3Info:
    def test_defaults(self):
        info = XP3Info()
        assert info.segments == []
        assert info.flags == 0
        assert info.compressed_size == 0
        assert info.original_size == 0

    def test_not_encrypted_by_default(self):
        info = XP3Info()
        assert not info.encrypted

    def test_encrypted_flag(self):
        info = XP3Info(flags=1 << 31)
        assert info.encrypted

    def test_not_encrypted_with_low_flags(self):
        info = XP3Info(flags=0x7FFFFFFF)
        assert not info.encrypted

    def test_repr(self):
        info = XP3Info(file_name='test.txt', key=42)
        r = repr(info)
        assert 'test.txt' in r
        assert '42' in r

    def test_get_info_bytes_structure(self):
        info = XP3Info(
            file_name='test.txt',
            key=0xDEADBEEF,
            flags=0,
            original_size=100,
            compressed_size=80,
            segments=[Container(flags=1, offset=200, original_size=100, compressed_size=80)],
        )

        data = info.get_info_bytes()

        # Starts with 'File' + 8-byte size
        assert data[:4] == b'File'
        size = struct.unpack('<Q', data[4:12])[0]
        assert len(data) == 12 + size

        # Contains expected chunks
        assert b'info' in data
        assert b'segm' in data
        assert b'adlr' in data

    def test_get_info_bytes_contains_filename(self):
        info = XP3Info(file_name='hello.txt', key=1)

        data = info.get_info_bytes()
        assert 'hello.txt'.encode('utf_16le') in data

    def test_get_info_bytes_contains_adlr_key(self):
        info = XP3Info(file_name='x', key=0x12345678)

        data = info.get_info_bytes()
        assert struct.pack('<I', 0x12345678) in data
