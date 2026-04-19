"""Member-content roundtrip tests for real XP3 archives in ``nonfree/``.

For each XP3 sample, extract every member, build a fresh (unencrypted) XP3
from the extracted files, extract it again, and verify that every member's
bytes survive the round-trip.

Archive bytes are not checked: real XP3s may legitimately carry leftover
data from earlier builds, different compression choices, or different
member orderings than what the library would produce, so byte-level archive
equality is not a meaningful goal.  Member content equality is.

Members that cannot be extracted (e.g. filenames too long for the host
filesystem) are silently dropped during the first extraction and therefore
omitted from the comparison — the test only checks that the members that
did extract also extract cleanly from the rebuilt archive.

Skips gracefully when no nonfree samples are present.
"""

import os
import tempfile

import pytest

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


def _walk_extracted(root):
    """Yield (POSIX-relative-path, absolute-path) for every regular file under root."""
    for dirpath, _dirs, files in os.walk(root):
        for name in sorted(files):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, '/')
            yield rel, full


def _read_all_under(root):
    return {rel: open(full, 'rb').read() for rel, full in _walk_extracted(root)}


@pytest.mark.nonfree
@pytest.mark.integration
@skip_no_samples
@pytest.mark.parametrize('relpath', xp3_files)
def test_xp3_member_content_roundtrip(relpath):
    """Every member that extracts from the source also extracts identically after rebuild."""
    path = os.path.join(NONFREE, relpath)
    encryption = auto_detect(path)

    with tempfile.TemporaryDirectory() as tmpdir:
        ext1 = os.path.join(tmpdir, 'ext1')
        ext2 = os.path.join(tmpdir, 'ext2')
        rebuilt = os.path.join(tmpdir, 'rebuilt.xp3')

        # source -> ext1. Disable text decoding so we compare raw archived
        # bytes rather than the post-decode UTF-16LE form.
        with XP3File(path, encryption=encryption) as xp3:
            xp3.extract_all(ext1, decode_text=False)

        if not os.path.isdir(ext1) or not any(os.scandir(ext1)):
            pytest.skip(f"{relpath}: no extractable members")

        # ext1 -> rebuilt.xp3 (unencrypted; roundtrip concerns member content, not crypto).
        # compresslevel=0 keeps the zlib-wrapped "store" path exercised but skips the
        # expensive deflate step — the test checks content fidelity, not compressed size.
        with XP3File(rebuilt, mode='x', compresslevel=0) as xp3:
            for rel, full in _walk_extracted(ext1):
                xp3.write(full, arcname=rel)

        # rebuilt.xp3 -> ext2
        with XP3File(rebuilt) as xp3:
            xp3.extract_all(ext2, decode_text=False)

        original = _read_all_under(ext1)
        roundtripped = _read_all_under(ext2)
        common = sorted(set(original) & set(roundtripped))
        assert common, f"{relpath}: no members survived the roundtrip"
        for name in common:
            assert original[name] == roundtripped[name], f"{relpath}:{name} content differs after roundtrip"
