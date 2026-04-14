import pathlib

import pytest

from tamago.cli import detect_format, get_format_handlers

_TESTS_ROOT = pathlib.Path(__file__).resolve().parent
SAMPLES_DIR = _TESTS_ROOT / "xp3" / "samples"


@pytest.mark.unit
class TestGetFormatHandlers:
    def test_discovers_xp3(self):
        handlers = get_format_handlers()
        assert 'xp3' in handlers

    def test_xp3_entry_point_loads(self):
        handlers = get_format_handlers()
        cls = handlers['xp3'].load()
        from tamago.formats.xp3.handler import XP3Handler

        assert cls is XP3Handler


@pytest.mark.unit
class TestDetectFormat:
    def test_detects_xp3(self):
        path = SAMPLES_DIR / "single_uncompressed.xp3"
        assert detect_format(path) == 'xp3'

    def test_returns_none_for_unknown(self, tmp_path):
        p = tmp_path / "fake.dat"
        p.write_bytes(b'\x00\x01\x02\x03')
        assert detect_format(p) is None

    def test_returns_none_for_missing_file(self, tmp_path):
        assert detect_format(tmp_path / "nonexistent") is None


@pytest.mark.integration
class TestIdentifySubcommand:
    def test_identify_xp3(self, capsys):
        import argparse

        from tamago.cli import cmd_identify

        args = argparse.Namespace(files=[SAMPLES_DIR / "single_uncompressed.xp3"])
        cmd_identify(args)
        captured = capsys.readouterr()
        assert "xp3" in captured.out
