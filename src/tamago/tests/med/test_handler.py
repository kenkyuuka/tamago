"""Tests for MD archive detection and the CLI handler."""

import argparse

import pytest

from tamago.cli import detect_format, get_format_handlers
from tamago.formats.med import MEDFile
from tamago.formats.med.handler import MEDHandler
from tamago.tests.med.test_medfile import PRS, SCRIPTS, _build


def _scripts_archive(tmp_path, keyword=b'goro5656'):
    path = tmp_path / 'md_scr.med'
    path.write_bytes(_build(SCRIPTS, signature=b'MDE0', keyword=keyword))
    return path


@pytest.mark.unit
class TestDetection:
    def test_entry_point_registered(self):
        assert get_format_handlers()['med'].load() is MEDHandler

    @pytest.mark.parametrize('signature', [b'MDE0', b'MDN1', b'MDE6'])
    def test_detects_by_header(self, tmp_path, signature):
        path = tmp_path / 'md_gra.med'
        path.write_bytes(_build({'BG_HALL': PRS}, signature=signature))
        assert detect_format(path) == 'med'


@pytest.mark.integration
class TestHandler:
    def test_extract_decrypts_and_reports_keyword(self, tmp_path, capsys):
        out = tmp_path / 'out'
        args = argparse.Namespace(input=_scripts_archive(tmp_path), output=out, glob=None)
        MEDHandler().cmd_extract(args)
        assert (out / 'CROQUET').read_bytes() == SCRIPTS['CROQUET']
        assert '--keyword goro5656' in capsys.readouterr().err

    def test_extract_no_decrypt(self, tmp_path):
        out = tmp_path / 'out'
        archive = _scripts_archive(tmp_path)
        MEDHandler().cmd_extract(argparse.Namespace(input=archive, output=out, glob=None, keyword=None, decrypt=False))
        with MEDFile(archive, decrypt=False) as med:
            assert (out / 'CROQUET').read_bytes() == med.read('CROQUET')

    def test_extract_unrecoverable_keyword_exits(self, tmp_path, capsys):
        archive = tmp_path / 'md_scr.med'
        scripts = {k: v for k, v in SCRIPTS.items() if k != '_VIEW'}
        archive.write_bytes(_build(scripts, signature=b'MDE0', keyword=b'goro5656'))
        with pytest.raises(SystemExit):
            MEDHandler().cmd_extract(argparse.Namespace(input=archive, output=tmp_path / 'out', glob=None))
        assert '--keyword' in capsys.readouterr().err
        assert not (tmp_path / 'out').exists()

    def test_extract_then_create_roundtrip(self, tmp_path):
        archive = _scripts_archive(tmp_path)
        out = tmp_path / 'out'
        MEDHandler().cmd_extract(argparse.Namespace(input=archive, output=out, glob=None))
        rebuilt = tmp_path / 'rebuilt.med'
        MEDHandler().cmd_create(
            argparse.Namespace(input=out, output=rebuilt, glob=None, keyword='goro5656', signature=None)
        )
        expected = _build(dict(sorted(SCRIPTS.items())), signature=b'MDE0', keyword=b'goro5656')
        assert rebuilt.read_bytes() == expected

    def test_create_decrypted_scripts_without_keyword_exits(self, tmp_path, capsys):
        src = tmp_path / 'src'
        src.mkdir()
        for name, data in SCRIPTS.items():
            (src / name).write_bytes(data)
        with pytest.raises(SystemExit):
            MEDHandler().cmd_create(argparse.Namespace(input=src, output=tmp_path / 'out.med', glob=None))
        assert 'keyword' in capsys.readouterr().err
