"""Nonfree roundtrip tests for simple-crypt text files.

Walks every XP3 archive under ``nonfree/``, extracts each member, and
exercises ``simple_crypt.decode`` + ``simple_crypt.encode`` on any member
whose first three bytes are the ``FE FE 01`` magic.  Verifies that:

- the decoded buffer starts with the UTF-16LE BOM and decodes as UTF-16LE
- re-encoding produces the original bytes verbatim (round-trip)

Skips gracefully when no nonfree samples are present.
"""

import os
import tempfile

import pytest

from tamago.formats.xp3 import simple_crypt
from tamago.formats.xp3.detect import auto_detect
from tamago.formats.xp3.xp3file import XP3File

NONFREE = os.path.join(os.path.dirname(__file__), 'nonfree')


def _collect_xp3_files():
    if not os.path.isdir(NONFREE):
        return []
    results = []
    for root, _dirs, files in os.walk(NONFREE):
        for f in sorted(files):
            if f.lower().endswith('.xp3'):
                results.append(os.path.relpath(os.path.join(root, f), NONFREE))
    return sorted(results)


xp3_files = _collect_xp3_files()
skip_no_samples = pytest.mark.skipif(not xp3_files, reason="no nonfree XP3 samples available")


@pytest.mark.nonfree
@pytest.mark.integration
@skip_no_samples
@pytest.mark.parametrize('relpath', xp3_files)
def test_simple_crypt_roundtrip(relpath):
    """Every simple-crypt member in the archive decodes and round-trips."""
    path = os.path.join(NONFREE, relpath)
    encryption = auto_detect(path)

    seen = 0
    with tempfile.TemporaryDirectory() as tmpdir, XP3File(path, encryption=encryption) as xp3:
        for i, member in enumerate(xp3.files):
            outpath = os.path.join(tmpdir, f"m_{i:06d}")
            try:
                xp3.extract(member, outpath)
            except (OSError, UnicodeError):
                continue
            with open(outpath, 'rb') as f:
                data = f.read()
            if not (len(data) >= 3 and data[:3] == b"\xfe\xfe\x01"):
                continue
            seen += 1
            decoded = simple_crypt.decode(data)
            assert decoded[:2] == b"\xff\xfe", f"{relpath}:{member.file_name} missing BOM after decode"
            decoded.decode('utf-16-le')  # raises if invalid UTF-16LE
            assert simple_crypt.encode(decoded) == data, f"{relpath}:{member.file_name} roundtrip mismatch"

    if seen == 0:
        pytest.skip(f"{relpath} contains no simple-crypt members")
