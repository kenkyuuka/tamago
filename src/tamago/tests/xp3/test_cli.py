import argparse
from types import SimpleNamespace

import pytest

from tamago.formats.xp3.encryption import HashXorEncryption
from tamago.formats.xp3.handler import _resolve_encryption


@pytest.mark.unit
class TestResolveEncryption:
    def test_none_when_no_scheme(self):
        args = SimpleNamespace(encryption=None, key=None)
        assert _resolve_encryption(args) is None

    def test_known_scheme_with_key(self):
        args = SimpleNamespace(encryption='hash-xor', key=3)
        enc = _resolve_encryption(args)
        assert isinstance(enc, HashXorEncryption)
        assert enc.shift == 3

    def test_unknown_scheme(self):
        args = SimpleNamespace(encryption='totally-fake', key=None)
        with pytest.raises(argparse.ArgumentTypeError, match="Unknown encryption"):
            _resolve_encryption(args)

    def test_unknown_scheme_lists_available(self):
        args = SimpleNamespace(encryption='totally-fake', key=None)
        with pytest.raises(argparse.ArgumentTypeError, match="hash-xor"):
            _resolve_encryption(args)

    def test_scheme_without_required_key(self):
        args = SimpleNamespace(encryption='hash-xor', key=None)
        with pytest.raises(argparse.ArgumentTypeError, match="Failed to instantiate"):
            _resolve_encryption(args)
