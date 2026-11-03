"""Tests for RPA detection and the CLI handler."""

import argparse
import pathlib
import pickle
import zlib

import pytest

from tamago.cli import detect_format, get_format_handlers
from tamago.formats.rpa import RPAFile
from tamago.formats.rpa.handler import RPAHandler

ENGINE_FIXTURE = pathlib.Path(__file__).resolve().parent / 'fixtures' / 'renpy-8.5.3.rpa'


@pytest.mark.unit
class TestDetection:
    def test_entry_point_registered(self):
        assert get_format_handlers()['rpa'].load() is RPAHandler

    def test_detects_rpa3_by_magic_with_any_extension(self, tmp_path):
        path = tmp_path / 'renamed.dat'
        path.write_bytes(ENGINE_FIXTURE.read_bytes())
        assert detect_format(path) == 'rpa'

    def test_detects_rpa2_by_magic(self, tmp_path):
        path = tmp_path / 'old.dat'
        path.write_bytes(b'RPA-2.0 0000000000000019\n')
        assert detect_format(path) == 'rpa'

    def test_detects_rpa1_index_by_extension(self, tmp_path):
        path = tmp_path / 'old.rpi'
        path.write_bytes(zlib.compress(pickle.dumps({}, 2)))
        assert detect_format(path) == 'rpa'

    def test_detects_headerless_data_file_by_extension(self, tmp_path):
        path = tmp_path / 'old.rpa'
        path.write_bytes(b'no header in a version 1 data file')
        assert detect_format(path) == 'rpa'


@pytest.mark.integration
class TestHandler:
    def test_extract(self, tmp_path):
        args = argparse.Namespace(input=ENGINE_FIXTURE, output=tmp_path, glob=None)
        RPAHandler().cmd_extract(args)
        expected = b'Why is a raven like a writing-desk?\n'
        assert (tmp_path / 'wonderland' / 'tea_party' / 'hatter.txt').read_bytes() == expected

    def test_create_uses_key_option(self, tmp_path):
        src = tmp_path / 'src'
        src.mkdir()
        (src / 'door.txt').write_bytes(b'Drink me')
        out = tmp_path / 'out.rpa'
        args = argparse.Namespace(input=src, output=out, glob=None, key=0xDEADBEEF)
        RPAHandler().cmd_create(args)
        assert out.read_bytes()[8 + 16 + 1 : 8 + 16 + 1 + 8] == b'deadbeef'
        with RPAFile(out) as rpa:
            assert rpa.read('door.txt') == b'Drink me'

    def test_create_defaults_key_when_option_absent(self, tmp_path):
        """Top-level `tamago create` only adds format options when extra arguments are given."""
        src = tmp_path / 'src'
        src.mkdir()
        (src / 'door.txt').write_bytes(b'Drink me')
        out = tmp_path / 'out.rpa'
        RPAHandler().cmd_create(argparse.Namespace(input=src, output=out, glob=None))
        assert out.read_bytes()[8 + 16 + 1 : 8 + 16 + 1 + 8] == b'42424242'

    @pytest.mark.parametrize('text', ['deadbeef', '0xdeadbeef', 'DEADBEEF'])
    def test_key_option_parses_hex(self, text):
        parser = argparse.ArgumentParser()
        RPAHandler().add_create_args(parser)
        assert parser.parse_args(['--key', text]).key == 0xDEADBEEF

    @pytest.mark.parametrize('text', ['nonsense', '100000000', '-1'])
    def test_key_option_rejects_bad_values(self, text):
        parser = argparse.ArgumentParser()
        RPAHandler().add_create_args(parser)
        with pytest.raises(SystemExit):
            parser.parse_args([f'--key={text}'])
