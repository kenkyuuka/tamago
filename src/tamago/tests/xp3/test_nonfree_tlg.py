"""Decoder smoke tests for real-world TLG images in nonfree/tlg/.

These tests verify that the TLG decoder can handle the full range of
structural variations found in the wild.  The nonfree/tlg/ directory is
gitignored — populate it with curated samples from curate_tlg_samples.py.

Each .tlg file is decoded and checked for basic validity (correct mode,
non-zero dimensions, non-trivial pixel data).  The manifest.tsv produced
by curate_tlg_samples.py is used to report which variation each sample
represents.
"""

import os

import pytest
from PIL import Image

from tamago.formats.xp3.tlg import TLG0_MAGIC, TLG5_MAGIC, TLG6_MAGIC, open_tlg

NONFREE_TLG = os.path.join(os.path.dirname(__file__), 'nonfree', 'tlg')


def _collect_tlg_files():
    """Collect .tlg files from nonfree/tlg/."""
    if not os.path.isdir(NONFREE_TLG):
        return []
    return sorted(f for f in os.listdir(NONFREE_TLG) if f.lower().endswith('.tlg'))


tlg_files = _collect_tlg_files()
skip_no_samples = pytest.mark.skipif(not tlg_files, reason="no nonfree TLG samples available")


def _read_manifest():
    """Load manifest.tsv into a dict keyed by filename."""
    manifest_path = os.path.join(NONFREE_TLG, 'manifest.tsv')
    if not os.path.exists(manifest_path):
        return {}
    manifest = {}
    with open(manifest_path) as f:
        header = f.readline()  # noqa: F841
        for line in f:
            parts = line.strip().split('\t', 3)
            if parts:
                manifest[parts[0]] = parts[1] if len(parts) > 1 else ''
    return manifest


_manifest = _read_manifest()


def _sample_id(filename):
    """Generate a readable test ID from the manifest variation label."""
    label = _manifest.get(filename, '')
    if label:
        # Shorten the label for readable test IDs
        return label.replace('  ', '_').replace(' ', '')
    return filename


@pytest.mark.nonfree
@pytest.mark.integration
@skip_no_samples
@pytest.mark.parametrize('filename', tlg_files, ids=[_sample_id(f) for f in tlg_files])
class TestNonfreeTLGSamples:
    """Decoder smoke tests for real-world TLG images."""

    def test_decodes_without_error(self, filename):
        """The file decodes without raising an exception."""
        path = os.path.join(NONFREE_TLG, filename)
        img = open_tlg(path)
        assert img is not None

    def test_mode_is_rgba(self, filename):
        """Decoded image is in RGBA mode."""
        path = os.path.join(NONFREE_TLG, filename)
        img = open_tlg(path)
        assert img.mode == 'RGBA'

    def test_dimensions_are_positive(self, filename):
        """Decoded image has positive width and height."""
        path = os.path.join(NONFREE_TLG, filename)
        img = open_tlg(path)
        w, h = img.size
        assert w > 0 and h > 0, f"unexpected dimensions: {w}x{h}"

    def test_has_nontrivial_data(self, filename):
        """Decoded image has at least some non-zero pixel data.

        Some images (e.g. transparent overlay placeholders) are legitimately
        all-zero.  When a reference PNG exists and is also all-zero, the
        decoder output is correct and the test passes.
        """
        path = os.path.join(NONFREE_TLG, filename)
        img = open_tlg(path)
        data = img.tobytes()
        if all(b == 0 for b in data):
            # Check if the reference PNG confirms the image is genuinely blank
            png_path = os.path.splitext(path)[0] + '.png'
            if os.path.exists(png_path):
                ref = Image.open(png_path).convert('RGBA')
                if all(b == 0 for b in ref.tobytes()):
                    return  # genuinely blank image, decoder is correct
            pytest.fail("image is entirely zero (no reference PNG to confirm this is expected)")

    def test_magic_matches_format(self, filename):
        """The file's magic bytes match a known TLG variant."""
        path = os.path.join(NONFREE_TLG, filename)
        with open(path, 'rb') as f:
            magic = f.read(11)
        assert magic in (TLG0_MAGIC, TLG5_MAGIC, TLG6_MAGIC), f"unexpected magic: {magic!r}"

    def test_matches_reference_png(self, filename):
        """Decoded image matches the reference PNG pixel-for-pixel."""
        tlg_path = os.path.join(NONFREE_TLG, filename)
        png_path = os.path.splitext(tlg_path)[0] + '.png'
        if not os.path.exists(png_path):
            pytest.skip("no reference PNG")
        decoded = open_tlg(tlg_path)
        reference = Image.open(png_path).convert('RGBA')
        assert decoded.size == reference.size, f"size mismatch: {decoded.size} vs {reference.size}"
        assert decoded.tobytes() == reference.tobytes(), "pixel data does not match reference PNG"
