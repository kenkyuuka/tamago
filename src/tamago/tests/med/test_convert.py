"""Tests for converting PRS images and WADY audio while extracting MD archives."""

import argparse
import logging
import pathlib
import wave

import pytest
from PIL import Image

from tamago.formats.med import MEDFile
from tamago.formats.med.handler import MEDHandler
from tamago.tests.med.test_medfile import ALICE, _build
from tamago.tests.med.test_prs import HEART, RED_PAINT, WHITE_ROSE, _literals, _prs
from tamago.tests.med.test_wady import _wady

ROSE_GARDEN = _prs(_literals(WHITE_ROSE + RED_PAINT + HEART + WHITE_ROSE), 2, 2)
LULLABY = _wady(bytes([0x90, 0xA0, 0x10, 0x50]), channels=2, rate=44100)
NOT_A_PRS = b'YB\x83\x04' + b'\x10\x00' * 20  # PRS signature, then filler
NOT_A_WADY = b'WADY' + bytes(range(60))


def _archive(tmp_path, members, signature=b'MDN1'):
    path = tmp_path / 'md_gra.med'
    path.write_bytes(_build(members, signature=signature))
    return path


def _extract(path, out, **kwargs):
    with MEDFile(path) as med:
        med.extract_all(out, **kwargs)


@pytest.mark.integration
class TestExtractConversion:
    def test_prs_becomes_png(self, tmp_path):
        out = tmp_path / 'out'
        _extract(_archive(tmp_path, {'BG_GARDEN': ROSE_GARDEN}), out, convert_prs=True)
        assert sorted(p.name for p in out.iterdir()) == ['BG_GARDEN.png']
        with Image.open(out / 'BG_GARDEN.png') as img:
            assert img.mode == 'RGBA'
            assert img.size == (2, 2)
            assert img.getpixel((0, 0)) == (0xF0, 0xF0, 0xF0, 0xFF)
            assert img.getpixel((1, 0)) == (0xC0, 0x10, 0x20, 0xFF)

    def test_wady_becomes_wav(self, tmp_path):
        out = tmp_path / 'out'
        _extract(_archive(tmp_path, {'M01': LULLABY}, signature=b'MDE6'), out, convert_wady=True)
        assert sorted(p.name for p in out.iterdir()) == ['M01.wav']
        with wave.open(str(out / 'M01.wav'), 'rb') as w:
            assert (w.getnchannels(), w.getframerate(), w.getnframes()) == (2, 44100, 2)

    def test_library_default_keeps_raw_bytes(self, tmp_path):
        out = tmp_path / 'out'
        _extract(_archive(tmp_path, {'BG_GARDEN': ROSE_GARDEN, 'M01': LULLABY}), out)
        assert (out / 'BG_GARDEN').read_bytes() == ROSE_GARDEN
        assert (out / 'M01').read_bytes() == LULLABY

    def test_each_flag_converts_only_its_format(self, tmp_path):
        out = tmp_path / 'out'
        _extract(_archive(tmp_path, {'BG_GARDEN': ROSE_GARDEN, 'M01': LULLABY}), out, convert_wady=True)
        assert sorted(p.name for p in out.iterdir()) == ['BG_GARDEN', 'M01.wav']

    def test_other_members_are_untouched(self, tmp_path):
        out = tmp_path / 'out'
        archive = _archive(tmp_path, {'BG_GARDEN': ROSE_GARDEN, 'NOTE': ALICE})
        _extract(archive, out, convert_prs=True, convert_wady=True)
        assert sorted(p.name for p in out.iterdir()) == ['BG_GARDEN.png', 'NOTE']
        assert (out / 'NOTE').read_bytes() == ALICE

    def test_name_with_a_dot_keeps_it(self, tmp_path):
        """The extension is appended, so a dotted member name is not truncated."""
        out = tmp_path / 'out'
        _extract(_archive(tmp_path, {'CH_ALICE.01': ROSE_GARDEN}), out, convert_prs=True)
        assert sorted(p.name for p in out.iterdir()) == ['CH_ALICE.01.png']

    def test_glob_still_matches_member_names(self, tmp_path):
        out = tmp_path / 'out'
        archive = _archive(tmp_path, {'BG_GARDEN': ROSE_GARDEN, 'CH_QUEEN': ROSE_GARDEN})
        with MEDFile(archive) as med:
            med.extract_all(out, glob='CH_*', convert_prs=True)
        assert sorted(p.name for p in out.iterdir()) == ['CH_QUEEN.png']

    @pytest.mark.parametrize('name,bogus', [('BG_BROKEN', NOT_A_PRS), ('M_BROKEN', NOT_A_WADY)])
    def test_undecodable_member_is_extracted_raw(self, tmp_path, name, bogus):
        out = tmp_path / 'out'
        _extract(_archive(tmp_path, {name: bogus}), out, convert_prs=True, convert_wady=True)
        assert sorted(p.name for p in out.iterdir()) == [name]
        assert (out / name).read_bytes() == bogus

    def test_fallback_warning_is_deduplicated(self, tmp_path, caplog):
        members = {f'BG_CARD_{i:02d}': NOT_A_PRS + bytes([i]) for i in range(10)}
        members.update({f'M_{i:02d}': NOT_A_WADY + bytes([i]) for i in range(3)})
        with caplog.at_level(logging.WARNING, logger='tamago.formats.med'):
            _extract(_archive(tmp_path, members), tmp_path / 'out', convert_prs=True, convert_wady=True)
        warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 2, warnings
        assert any('PRS' in w for w in warnings)
        assert any('WADY' in w for w in warnings)


@pytest.mark.integration
class TestHandlerConversion:
    def _parse(self, *argv):
        """Parse arguments the way `tamago med extract` does."""
        parser = argparse.ArgumentParser()
        parser.add_argument('input', type=pathlib.Path)
        parser.add_argument('output', type=pathlib.Path)
        parser.add_argument('--glob')
        MEDHandler().add_extract_args(parser)
        return parser.parse_args([str(a) for a in argv])

    def test_converts_by_default(self, tmp_path):
        out = tmp_path / 'out'
        archive = _archive(tmp_path, {'BG_GARDEN': ROSE_GARDEN, 'M01': LULLABY})
        MEDHandler().cmd_extract(self._parse(archive, out))
        assert sorted(p.name for p in out.iterdir()) == ['BG_GARDEN.png', 'M01.wav']

    def test_namespace_without_flags_converts(self, tmp_path):
        out = tmp_path / 'out'
        archive = _archive(tmp_path, {'BG_GARDEN': ROSE_GARDEN})
        MEDHandler().cmd_extract(argparse.Namespace(input=archive, output=out, glob=None))
        assert sorted(p.name for p in out.iterdir()) == ['BG_GARDEN.png']

    def test_no_convert_flags_keep_raw_bytes(self, tmp_path):
        out = tmp_path / 'out'
        archive = _archive(tmp_path, {'BG_GARDEN': ROSE_GARDEN, 'M01': LULLABY})
        MEDHandler().cmd_extract(self._parse(archive, out, '--no-convert-prs', '--no-convert-wady'))
        assert (out / 'BG_GARDEN').read_bytes() == ROSE_GARDEN
        assert (out / 'M01').read_bytes() == LULLABY

    @pytest.mark.parametrize(
        'flag,kept,converted',
        [('--no-convert-prs', 'BG_GARDEN', 'M01.wav'), ('--no-convert-wady', 'M01', 'BG_GARDEN.png')],
    )
    def test_flags_are_independent(self, tmp_path, flag, kept, converted):
        out = tmp_path / 'out'
        archive = _archive(tmp_path, {'BG_GARDEN': ROSE_GARDEN, 'M01': LULLABY})
        MEDHandler().cmd_extract(self._parse(archive, out, flag))
        assert sorted(p.name for p in out.iterdir()) == sorted([kept, converted])

    def test_unconverted_extract_still_roundtrips(self, tmp_path):
        archive = _archive(tmp_path, {'BG_GARDEN': ROSE_GARDEN, 'CH_QUEEN': ROSE_GARDEN[::-1]})
        out = tmp_path / 'out'
        MEDHandler().cmd_extract(self._parse(archive, out, '--no-convert-prs'))
        rebuilt = tmp_path / 'rebuilt.med'
        MEDHandler().cmd_create(
            argparse.Namespace(input=out, output=rebuilt, glob=None, keyword=None, signature='MDN1')
        )
        assert rebuilt.read_bytes() == archive.read_bytes()
