import io
import os
import tempfile

import pytest

from tamago.formats.xp3 import XP3File
from tamago.formats.xp3.tlg import TLG0_MAGIC, TLG5_MAGIC, TLG6_MAGIC, open_tlg

SAMPLES = os.path.join(os.path.dirname(__file__), 'samples')


@pytest.mark.unit
class TestOpenTlgTlg5:
    """Test open_tlg with synthetic TLG5 images."""

    def test_decode_checkerboard(self):
        """Decode a 4x4 checkerboard TLG5 and verify every pixel."""
        img = open_tlg(os.path.join(SAMPLES, 'cheshire_4x4.tlg'))
        assert img.mode == 'RGBA'
        assert img.size == (4, 4)
        px = img.load()
        for y in range(4):
            for x in range(4):
                expected = (128, 0, 128, 255) if (x + y) % 2 == 0 else (0, 0, 0, 0)
                assert px[x, y] == expected, f"pixel ({x},{y}): got {px[x, y]}, expected {expected}"

    def test_decode_solid_red(self):
        """Decode a 2x2 solid red TLG5 image."""
        img = open_tlg(os.path.join(SAMPLES, 'red_2x2.tlg'))
        assert img.mode == 'RGBA'
        assert img.size == (2, 2)
        px = img.load()
        for y in range(2):
            for x in range(2):
                assert px[x, y] == (255, 0, 0, 255)

    def test_tlg0_wrapper(self):
        """TLG0-wrapped TLG5 should produce identical output to raw TLG5."""
        img_raw = open_tlg(os.path.join(SAMPLES, 'cheshire_4x4.tlg'))
        img_wrapped = open_tlg(os.path.join(SAMPLES, 'cheshire_4x4_tlg0.tlg'))
        assert img_raw.tobytes() == img_wrapped.tobytes()

    def test_open_from_file_object(self):
        """open_tlg should accept a file-like object."""
        with open(os.path.join(SAMPLES, 'red_2x2.tlg'), 'rb') as f:
            img = open_tlg(f)
        assert img.size == (2, 2)

    def test_open_from_bytes_io(self):
        """open_tlg should accept a BytesIO object."""
        with open(os.path.join(SAMPLES, 'red_2x2.tlg'), 'rb') as f:
            data = f.read()
        img = open_tlg(io.BytesIO(data))
        assert img.size == (2, 2)

    def test_consistent_decode(self):
        """Decoding the same file twice produces identical output."""
        path = os.path.join(SAMPLES, 'cheshire_4x4.tlg')
        assert open_tlg(path).tobytes() == open_tlg(path).tobytes()


@pytest.mark.unit
class TestOpenTlgTlg6:
    """Test open_tlg with a TLG0-wrapped TLG6 image (owari02.tlg)."""

    def test_decode_owari02(self):
        """Decode a TLG6 image and verify dimensions and mode."""
        img = open_tlg(os.path.join(SAMPLES, 'owari02.tlg'))
        assert img.mode == 'RGBA'
        assert img.size == (360, 66)

    def test_owari02_has_content(self):
        """The decoded image should have non-trivial pixel data."""
        img = open_tlg(os.path.join(SAMPLES, 'owari02.tlg'))
        data = img.tobytes()
        assert any(b != 0 for b in data)

    def test_owari02_save_as_png(self):
        """Decoded TLG6 image should be saveable as PNG."""
        img = open_tlg(os.path.join(SAMPLES, 'owari02.tlg'))
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as tmp:
            tmp_path = tmp.name
        try:
            img.save(tmp_path, 'PNG')
            assert os.path.getsize(tmp_path) > 0
        finally:
            os.unlink(tmp_path)


@pytest.mark.unit
class TestOpenTlgAllTransparent:
    """Test that all-transparent TLG images decode correctly.

    Some TLG images are legitimately all-zero (fully transparent), e.g.
    foreground overlay placeholders named ``clear.tlg``.  The decoder should
    handle these without error.
    """

    def test_decode_transparent_2x2(self):
        """Decode an all-transparent 2x2 TLG5 image."""
        result = open_tlg(os.path.join(SAMPLES, 'transparent_2x2.tlg'))
        assert result.mode == 'RGBA'
        assert result.size == (2, 2)

    def test_transparent_pixels_are_zero(self):
        """All pixels should be (0, 0, 0, 0)."""
        result = open_tlg(os.path.join(SAMPLES, 'transparent_2x2.tlg'))
        px = result.load()
        for y in range(2):
            for x in range(2):
                assert px[x, y] == (0, 0, 0, 0), f"pixel ({x},{y}): got {px[x, y]}"


@pytest.mark.unit
class TestTlg5SharedRing:
    """Test that TLG5 LZSS decompression uses a shared ring buffer across channels.

    The rabbit_4x2_lzss.tlg sample has channel 1 (G) encoded with an LZSS
    back-reference into data written by channel 0 (B).  If each channel has its
    own ring buffer, the back-reference resolves to zeros; with a shared ring,
    it correctly copies channel 0's decompressed bytes.
    """

    def test_shared_ring_pixel_values(self):
        """Channel 1 should contain data from channel 0's ring buffer."""
        img = open_tlg(os.path.join(SAMPLES, 'rabbit_4x2_lzss.tlg'))
        px = img.load()
        # With shared ring: G channel gets [0xAA, 0xBB, 0xCC, 0xDD] from B's ring
        # With separate rings: G channel gets [0x00, 0x00, 0x00, 0x00]
        assert px[0, 0] == (187, 170, 84, 255), f"got {px[0, 0]}"
        assert px[1, 0] == (152, 101, 202, 255), f"got {px[1, 0]}"
        assert px[2, 0] == (151, 49, 98, 255), f"got {px[2, 0]}"
        assert px[3, 0] == (184, 14, 28, 255), f"got {px[3, 0]}"

    def test_shared_ring_green_nonzero(self):
        """G channel must be nonzero (proves ring data was shared, not zeroed)."""
        img = open_tlg(os.path.join(SAMPLES, 'rabbit_4x2_lzss.tlg'))
        _, g, _, _ = img.split()
        assert any(b != 0 for b in g.tobytes())


@pytest.mark.unit
class TestTlg6PixelAccuracy:
    """Test TLG6 decoding produces correct pixel values.

    Verifies both the zig-zag sign decoding formula and the RGBA channel
    ordering.  The owari02.tlg sample contains pixels with distinct R, G, B
    values that would differ if channels were swapped.
    """

    def test_uniform_region(self):
        """Pixel in a uniform region should decode to (21, 21, 21, 255)."""
        img = open_tlg(os.path.join(SAMPLES, 'owari02.tlg'))
        px = img.load()
        assert px[0, 0] == (21, 21, 21, 255)

    def test_colored_region_rgb_order(self):
        """Pixel with distinct R/G/B values should have correct channel order."""
        img = open_tlg(os.path.join(SAMPLES, 'owari02.tlg'))
        px = img.load()
        # This pixel has R=29, G=49, B=71 — all different, so any
        # channel swap would produce a visibly wrong result.
        assert px[200, 40] == (29, 49, 71, 255)


@pytest.mark.unit
class TestOpenTlgErrors:
    """Test error handling in open_tlg."""

    def test_invalid_magic(self):
        """Non-TLG data should raise ValueError."""
        with pytest.raises(ValueError, match="Unknown TLG magic"):
            open_tlg(io.BytesIO(b'not a tlg file at all!!'))


@pytest.mark.integration
class TestExtractConvertTlg:
    """Test XP3File.extract and extract_all with convert_tlg=True."""

    def test_extract_converts_tlg_to_png(self):
        """extract() with convert_tlg=True should produce a .png file."""
        with XP3File(os.path.join(SAMPLES, 'with_tlg.xp3')) as xp3:
            tlg_member = next(f for f in xp3.files if f.file_name == 'cheshire.tlg')
            with tempfile.TemporaryDirectory() as tmpdir:
                outpath = os.path.join(tmpdir, 'cheshire.tlg')
                xp3.extract(tlg_member, outpath, convert_tlg=True)

                png_path = os.path.join(tmpdir, 'cheshire.png')
                assert os.path.exists(png_path)
                assert not os.path.exists(outpath)
                assert os.path.getsize(png_path) > 0

    def test_extract_without_convert_keeps_tlg(self):
        """extract() without convert_tlg should keep the original .tlg file."""
        with XP3File(os.path.join(SAMPLES, 'with_tlg.xp3')) as xp3:
            tlg_member = next(f for f in xp3.files if f.file_name == 'cheshire.tlg')
            with tempfile.TemporaryDirectory() as tmpdir:
                outpath = os.path.join(tmpdir, 'cheshire.tlg')
                xp3.extract(tlg_member, outpath)
                assert os.path.exists(outpath)

    def test_extract_all_converts_tlg_files(self):
        """extract_all() with convert_tlg=True should convert all TLG files to PNG."""
        with XP3File(os.path.join(SAMPLES, 'with_tlg.xp3')) as xp3:
            with tempfile.TemporaryDirectory() as tmpdir:
                xp3.extract_all(tmpdir, convert_tlg=True)

                assert os.path.exists(os.path.join(tmpdir, 'cheshire.png'))
                assert not os.path.exists(os.path.join(tmpdir, 'cheshire.tlg'))
                assert os.path.exists(os.path.join(tmpdir, 'subfolder', 'red.png'))
                assert not os.path.exists(os.path.join(tmpdir, 'subfolder', 'red.tlg'))

    def test_extract_all_without_convert(self):
        """extract_all() without convert_tlg should keep TLG files as-is."""
        with XP3File(os.path.join(SAMPLES, 'with_tlg.xp3')) as xp3:
            with tempfile.TemporaryDirectory() as tmpdir:
                xp3.extract_all(tmpdir)
                assert os.path.exists(os.path.join(tmpdir, 'cheshire.tlg'))
                assert os.path.exists(os.path.join(tmpdir, 'subfolder', 'red.tlg'))

    def test_converted_png_has_correct_pixels(self):
        """Extracted+converted PNG should have the same pixels as direct open_tlg."""
        with XP3File(os.path.join(SAMPLES, 'with_tlg.xp3')) as xp3:
            tlg_member = next(f for f in xp3.files if f.file_name == 'cheshire.tlg')
            with tempfile.TemporaryDirectory() as tmpdir:
                xp3.extract(tlg_member, os.path.join(tmpdir, 'cheshire.tlg'), convert_tlg=True)
                from PIL import Image

                png_img = Image.open(os.path.join(tmpdir, 'cheshire.png'))
                direct_img = open_tlg(os.path.join(SAMPLES, 'cheshire_4x4.tlg'))
                assert png_img.tobytes() == direct_img.tobytes()
