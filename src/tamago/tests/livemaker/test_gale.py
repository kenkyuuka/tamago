"""Tests for the Gale image format decoder."""

from __future__ import annotations

import io
import os
import struct
import zlib

import pytest

pytest.importorskip('PIL.Image')

from tamago.formats.livemaker.gale import open_gal

# ---------------------------------------------------------------------------
# Synthetic Gale 103+ image builders
# ---------------------------------------------------------------------------


def _gale_stride(width: int, bpp: int) -> int:
    stride = (width * bpp + 7) // 8
    if bpp >= 8:
        stride = (stride + 3) & ~3
    return stride


def _alpha_stride(width: int) -> int:
    return (width + 3) & ~3


def _build_header(
    version: int,
    width: int,
    height: int,
    bpp: int,
    frame_count: int,
    compression: int,
    block_width: int = 0,
    block_height: int = 0,
    shuffled: bool = False,
    mask: int = 0xFFFFFF,
) -> bytes:
    body = bytearray(0x28)
    struct.pack_into('<i', body, 0x00, version)
    struct.pack_into('<I', body, 0x04, width)
    struct.pack_into('<I', body, 0x08, height)
    struct.pack_into('<i', body, 0x0C, bpp)
    struct.pack_into('<i', body, 0x10, frame_count)
    body[0x14] = 0
    body[0x15] = 1 if shuffled else 0
    body[0x16] = compression
    body[0x17] = 0
    struct.pack_into('<I', body, 0x18, mask & 0xFFFFFFFF)
    struct.pack_into('<i', body, 0x1C, block_width)
    struct.pack_into('<i', body, 0x20, block_height)
    return bytes(body)


def _build_frame(
    version: int,
    width: int,
    height: int,
    bpp: int,
    layers: list[tuple[bytes, bytes | None]],
    palette: bytes = b'',
) -> bytes:
    """Serialize one frame: name + header + palette + layers.

    ``layers`` is a list of ``(pixel_payload, alpha_payload | None)`` tuples
    where each payload is already formatted for the target compression mode.
    """
    out = bytearray()
    name = b'Frame1'
    out += struct.pack('<I', len(name)) + name
    out += struct.pack('<I', 0xFFFFFF)
    out += b'\x00' * 9
    out += struct.pack('<i', len(layers))
    out += struct.pack('<i', width)
    out += struct.pack('<i', height)
    out += struct.pack('<i', bpp)
    out += palette

    for pixels, alpha in layers:
        out += struct.pack('<i', 0)  # left
        out += struct.pack('<i', 0)  # top
        out += b'\x01'  # visible
        out += struct.pack('<i', -1)  # trans_color
        out += struct.pack('<i', 0xFF)  # alpha
        out += b'\x01' if alpha is not None else b'\x00'  # alpha_on
        layer_name = b'Layer1'
        out += struct.pack('<I', len(layer_name)) + layer_name
        if version >= 107:
            out += b'\x00'  # lock
        out += struct.pack('<i', len(pixels)) + pixels
        if alpha is None:
            out += struct.pack('<i', 0)
        else:
            out += struct.pack('<i', len(alpha)) + alpha
    return bytes(out)


def build_gale(
    width: int,
    height: int,
    bpp: int,
    pixels: bytes,
    alpha: bytes | None = None,
    *,
    version: int = 105,
    compression: int = 1,
    block_width: int = 0,
    block_height: int = 0,
    palette: bytes = b'',
) -> bytes:
    """Assemble a single-frame, single-layer Gale image for tests."""
    out = bytearray()
    out += b'Gale' + str(version).encode('ascii')
    body = _build_header(
        version=version,
        width=width,
        height=height,
        bpp=bpp,
        frame_count=1,
        compression=compression,
        block_width=block_width,
        block_height=block_height,
    )
    out += struct.pack('<I', len(body))
    out += body

    layer_pixels = pixels
    layer_alpha = alpha
    if compression == 0:
        # Zlib-wrap the raw/block stream.
        layer_pixels = zlib.compress(layer_pixels)
        if layer_alpha is not None:
            layer_alpha = zlib.compress(layer_alpha)
    out += _build_frame(version, width, height, bpp, [(layer_pixels, layer_alpha)], palette=palette)
    return bytes(out)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestOpenGalBasic:
    def test_decode_2x2_rgb(self):
        """A simple 2x2 24bpp image decodes to the expected RGB pixels."""
        # Stride for width=2, 24bpp is 6 bytes padded to 8.
        row0 = bytes([0, 0, 0xFF, 0, 0xFF, 0, 0, 0])  # red, green, pad
        row1 = bytes([0xFF, 0, 0, 0xFF, 0xFF, 0xFF, 0, 0])  # blue, white, pad
        data = build_gale(2, 2, 24, row0 + row1)
        img = open_gal(io.BytesIO(data))
        assert img.mode == 'RGB'
        assert img.size == (2, 2)
        assert img.getpixel((0, 0)) == (255, 0, 0)
        assert img.getpixel((1, 0)) == (0, 255, 0)
        assert img.getpixel((0, 1)) == (0, 0, 255)
        assert img.getpixel((1, 1)) == (255, 255, 255)

    def test_decode_with_alpha(self):
        """A 2x2 24bpp image with an alpha plane decodes to RGBA."""
        row0 = bytes([0, 0, 0xFF, 0, 0xFF, 0, 0, 0])
        row1 = bytes([0xFF, 0, 0, 0xFF, 0xFF, 0xFF, 0, 0])
        # Alpha plane stride for width=2 is padded to 4.
        alpha = bytes([0x80, 0xFF, 0, 0, 0x40, 0x20, 0, 0])
        data = build_gale(2, 2, 24, row0 + row1, alpha=alpha)
        img = open_gal(io.BytesIO(data))
        assert img.mode == 'RGBA'
        assert img.getpixel((0, 0)) == (255, 0, 0, 0x80)
        assert img.getpixel((1, 0)) == (0, 255, 0, 0xFF)
        assert img.getpixel((0, 1)) == (0, 0, 255, 0x40)
        assert img.getpixel((1, 1)) == (255, 255, 255, 0x20)

    def test_decode_zlib_compression(self):
        """Compression mode 0 wraps the block stream in zlib."""
        # Solid cyan (R=0, G=255, B=255) image; stride for width=4, 24bpp is 12.
        pixels = bytes([0xFF, 0xFF, 0]) * 4 * 4  # width 4, height 4
        data = build_gale(4, 4, 24, pixels, compression=0)
        img = open_gal(io.BytesIO(data))
        assert img.size == (4, 4)
        for y in range(4):
            for x in range(4):
                assert img.getpixel((x, y)) == (0, 255, 255)

    def test_decode_block_references(self):
        """A block-based layer with -1 (literal) entries decodes correctly."""
        # 4x4 image, 2x2 blocks, 24bpp.  4 blocks total.
        w, h = 4, 4
        bw, bh = 2, 2
        stride = _gale_stride(w, 24)
        # Build the output pixels we want: a red/green/blue/white 2x2 mosaic
        # of 2x2 solid blocks.
        block_colors = [
            (0, 0, 0xFF),  # red
            (0, 0xFF, 0),  # green
            (0xFF, 0, 0),  # blue
            (0xFF, 0xFF, 0xFF),  # white
        ]
        expected = bytearray(stride * h)
        for by in range(2):
            for bx in range(2):
                color = block_colors[by * 2 + bx]
                for dy in range(bh):
                    for dx in range(bw):
                        row = by * bh + dy
                        col = bx * bw + dx
                        pos = row * stride + col * 3
                        expected[pos : pos + 3] = bytes(color)

        # Block stream: ref table (4 blocks * 8 bytes = 32) + literal block data.
        # Each block is 2 rows x (2px * 3 bytes) = 12 bytes.
        refs = struct.pack('<' + 'i' * 8, -1, 0, -1, 0, -1, 0, -1, 0)
        block_data = bytearray()
        for block_idx in range(4):
            color = bytes(block_colors[block_idx])
            block_data += color * bw  # row of 2 pixels
            block_data += color * bw

        payload = refs + bytes(block_data)
        data = build_gale(w, h, 24, payload, compression=1, block_width=bw, block_height=bh)
        img = open_gal(io.BytesIO(data))
        for y in range(h):
            for x in range(w):
                expected_color = block_colors[(y // bh) * 2 + (x // bw)]
                # Gale stores BGR; open_gal returns RGB.
                assert img.getpixel((x, y)) == expected_color[::-1]

    def test_decode_from_path(self, tmp_path):
        """open_gal should accept a path argument."""
        pixels = bytes([0x11, 0x22, 0x33, 0])  # B=0x11, G=0x22, R=0x33, pad
        data = build_gale(1, 1, 24, pixels)
        path = tmp_path / 'one.gal'
        path.write_bytes(data)
        img = open_gal(str(path))
        assert img.getpixel((0, 0)) == (0x33, 0x22, 0x11)

    def test_decode_from_pathlike(self, tmp_path):
        """open_gal should accept os.PathLike arguments."""
        pixels = bytes([0, 0, 0xAA, 0])
        data = build_gale(1, 1, 24, pixels)
        path = tmp_path / 'one.gal'
        path.write_bytes(data)
        img = open_gal(path)
        assert img.getpixel((0, 0)) == (0xAA, 0, 0)

    def test_save_as_png_roundtrip(self, tmp_path):
        """Decoded image can be saved as PNG without error."""
        data = build_gale(2, 2, 24, bytes([0x80, 0x40, 0x20, 0, 0, 0, 0, 0]) * 2)
        img = open_gal(io.BytesIO(data))
        out = tmp_path / 'out.png'
        img.save(out, 'PNG')
        assert out.stat().st_size > 0


@pytest.mark.unit
class TestOpenGalErrors:
    def test_rejects_missing_magic(self):
        with pytest.raises(ValueError, match='missing magic'):
            open_gal(io.BytesIO(b'NOPE0000' + b'\x00' * 64))

    def test_rejects_old_version(self):
        """Gale 100 is not supported."""
        data = bytearray(b'Gale100' + struct.pack('<I', 0x28) + b'\x00' * 0x40)
        with pytest.raises(NotImplementedError, match='not supported'):
            open_gal(io.BytesIO(bytes(data)))

    def test_rejects_future_version(self):
        """Versions beyond 107 are rejected."""
        data = bytearray(b'Gale108' + struct.pack('<I', 0x28) + b'\x00' * 0x40)
        with pytest.raises(NotImplementedError, match='not supported'):
            open_gal(io.BytesIO(bytes(data)))

    def test_rejects_unreasonable_header_size(self):
        data = b'Gale105' + struct.pack('<I', 0x1000) + b'\x00' * 8
        with pytest.raises(ValueError, match='header size'):
            open_gal(io.BytesIO(data))

    def test_shuffled_without_key_raises(self):
        """An image with shuffled=1 and no key raises NotImplementedError."""
        body = _build_header(105, 2, 2, 24, 1, compression=1, shuffled=True)
        data = b'Gale105' + struct.pack('<I', len(body)) + body
        data += _build_frame(105, 2, 2, 24, [(b'\x00' * 16, None)])
        with pytest.raises(NotImplementedError, match='Shuffled'):
            open_gal(io.BytesIO(data))


# ---------------------------------------------------------------------------
# GaleX200 tests
# ---------------------------------------------------------------------------


def build_galex(
    width: int,
    height: int,
    bpp: int,
    pixels: bytes,
    alpha: bytes | None = None,
    *,
    compression: int = 1,
    block_width: int = 0,
    block_height: int = 0,
    palette_hex: str = '',
) -> bytes:
    """Assemble a single-frame GaleX200 image with an XML header."""
    palette_elem = f'<RGB>{palette_hex}</RGB>' if palette_hex else ''
    alpha_on = '1' if alpha is not None else '0'
    xml = (
        f'<?xml version="1.0"?>'
        f'<Frames Width="{width}" Height="{height}" Bpp="{bpp}" Count="1"'
        f' Version="200" Randomized="0" CompType="{compression}" BGColor="0"'
        f' BlockWidth="{block_width}" BlockHeight="{block_height}">'
        f'<Frame>'
        f'<Layers Width="{width}" Height="{height}" Bpp="{bpp}" Count="1">'
        f'{palette_elem}'
        f'<Layer AlphaOn="{alpha_on}"/>'
        f'</Layers>'
        f'</Frame>'
        f'</Frames>'
    ).encode()
    compressed = zlib.compress(xml)

    layer_pixels = pixels
    layer_alpha = alpha
    if compression == 0:
        layer_pixels = zlib.compress(layer_pixels)
        if layer_alpha is not None:
            layer_alpha = zlib.compress(layer_alpha)

    out = bytearray()
    out += b'GaleX200'
    out += struct.pack('<I', len(compressed))
    out += compressed
    out += struct.pack('<i', len(layer_pixels)) + layer_pixels
    if layer_alpha is not None:
        out += struct.pack('<i', len(layer_alpha))
        out += layer_alpha
    return bytes(out)


@pytest.mark.unit
class TestOpenGalX:
    def test_decode_galx_rgb(self):
        """A GaleX200 image with XML header decodes the same as classic Gale."""
        row0 = bytes([0, 0, 0xFF, 0, 0xFF, 0, 0, 0])
        row1 = bytes([0xFF, 0, 0, 0xFF, 0xFF, 0xFF, 0, 0])
        data = build_galex(2, 2, 24, row0 + row1)
        img = open_gal(io.BytesIO(data))
        assert img.mode == 'RGB'
        assert img.size == (2, 2)
        assert img.getpixel((0, 0)) == (255, 0, 0)
        assert img.getpixel((1, 1)) == (255, 255, 255)

    def test_decode_galx_with_alpha(self):
        row0 = bytes([0, 0, 0xFF, 0, 0, 0, 0, 0])
        row1 = bytes([0, 0, 0, 0, 0, 0, 0, 0])
        alpha = bytes([0x40, 0x80, 0, 0, 0xC0, 0xFF, 0, 0])
        data = build_galex(2, 2, 24, row0 + row1, alpha=alpha)
        img = open_gal(io.BytesIO(data))
        assert img.mode == 'RGBA'
        assert img.getpixel((0, 0)) == (255, 0, 0, 0x40)
        assert img.getpixel((1, 1)) == (0, 0, 0, 0xFF)

    def test_galx_rejects_missing_magic(self):
        with pytest.raises(ValueError, match='missing magic'):
            open_gal(io.BytesIO(b'NOPE0000' + b'\x00' * 64))

    def test_galx_strips_duplicate_frame_attributes(self):
        """GaleXml files sometimes carry duplicate <Frame> attributes."""
        row0 = bytes([0xFF, 0, 0, 0, 0xFF, 0, 0, 0])  # blue, green
        row1 = bytes([0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0])  # red, white
        # Inject a bogus Frame element with duplicate attributes.
        xml = (
            b'<?xml version="1.0"?>'
            b'<Frames Width="2" Height="2" Bpp="24" Count="1" Version="200"'
            b' Randomized="0" CompType="1" BGColor="0" BlockWidth="0" BlockHeight="0">'
            b'<Frame X="1" X="2" Y="3">'
            b'<Layers Width="2" Height="2" Bpp="24" Count="1">'
            b'<Layer AlphaOn="0"/>'
            b'</Layers>'
            b'</Frame>'
            b'</Frames>'
        )
        compressed = zlib.compress(xml)
        payload = row0 + row1
        data = b'GaleX200' + struct.pack('<I', len(compressed)) + compressed + struct.pack('<i', len(payload)) + payload
        img = open_gal(io.BytesIO(data))
        assert img.size == (2, 2)
        assert img.getpixel((0, 0)) == (0, 0, 255)  # B=0xFF
        assert img.getpixel((1, 0)) == (0, 255, 0)  # G=0xFF
        assert img.getpixel((0, 1)) == (255, 0, 0)  # R=0xFF
        assert img.getpixel((1, 1)) == (255, 255, 255)


# ---------------------------------------------------------------------------
# Integration: VFFile.extract with convert_gal
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestConvertGalThroughVFFile:
    def _make_archive_with_gal(self, tmp_path, gal_bytes: bytes, arcname: str = 'sprites\\alice.gal'):
        """Return the path to a .dat archive containing one .gal member."""
        from tamago.formats.livemaker.vffile import VFFile

        gal_file = tmp_path / 'alice.gal'
        gal_file.write_bytes(gal_bytes)
        dat = tmp_path / 'cheshire.dat'
        with VFFile(dat, mode='w') as arc:
            arc.write(gal_file, arcname=arcname, compress=False)
        return dat

    def test_extract_all_converts_gal_to_png(self, tmp_path):
        """When convert_gal=True, .gal members become .png files on disk."""
        from tamago.formats.livemaker.vffile import VFFile

        data = build_gale(1, 1, 24, bytes([0, 0, 0xFF, 0]))  # red pixel
        dat = self._make_archive_with_gal(tmp_path, data)

        out_dir = tmp_path / 'out'
        with VFFile(dat) as arc:
            arc.extract_all(out_dir, convert_gal=True)

        png_path = out_dir / 'sprites' / 'alice.png'
        gal_path = out_dir / 'sprites' / 'alice.gal'
        assert png_path.exists()
        assert not gal_path.exists()
        # And the PNG round-trips back to the original pixel.
        from PIL import Image as PILImage

        img = PILImage.open(png_path)
        assert img.getpixel((0, 0)) == (255, 0, 0)

    def test_extract_all_keeps_gal_when_disabled(self, tmp_path):
        """convert_gal=False preserves the original .gal bytes."""
        from tamago.formats.livemaker.vffile import VFFile

        data = build_gale(1, 1, 24, bytes([0, 0, 0xFF, 0]))
        dat = self._make_archive_with_gal(tmp_path, data)

        out_dir = tmp_path / 'out'
        with VFFile(dat) as arc:
            arc.extract_all(out_dir, convert_gal=False)

        gal_path = out_dir / 'sprites' / 'alice.gal'
        png_path = out_dir / 'sprites' / 'alice.png'
        assert gal_path.exists()
        assert not png_path.exists()
        assert gal_path.read_bytes() == data

    def test_extract_falls_back_for_invalid_gal(self, tmp_path):
        """An unparseable .gal is extracted as raw bytes with a warning."""
        from tamago.formats.livemaker.vffile import VFFile

        bogus = b'NOPE0000' + b'\x00' * 64
        dat = self._make_archive_with_gal(tmp_path, bogus)

        out_dir = tmp_path / 'out'
        with VFFile(dat) as arc:
            arc.extract_all(out_dir, convert_gal=True)

        gal_path = out_dir / 'sprites' / 'alice.gal'
        assert gal_path.exists()
        assert gal_path.read_bytes() == bogus

    def test_fallback_warning_is_deduplicated(self, tmp_path, caplog):
        """Multiple bad .gal members share one warning, not one per file."""
        import logging as _logging

        from tamago.formats.livemaker.vffile import VFFile

        bogus = b'NOPE0000' + b'\x00' * 64
        gal = tmp_path / 'bogus.gal'
        gal.write_bytes(bogus)
        dat = tmp_path / 'many.dat'
        with VFFile(dat, mode='w') as arc:
            for i in range(10):
                arc.write(gal, arcname=f'sprites\\bad{i}.gal', compress=False)

        out_dir = tmp_path / 'out'
        with caplog.at_level(_logging.WARNING, logger='tamago.formats.livemaker.vffile'):
            with VFFile(dat) as arc:
                arc.extract_all(out_dir, convert_gal=True)

        warnings = [r for r in caplog.records if r.levelno == _logging.WARNING]
        assert len(warnings) == 1, f'expected 1 warning, got {len(warnings)}'


# ---------------------------------------------------------------------------
# Nonfree real-sample sweep
# ---------------------------------------------------------------------------


@pytest.mark.nonfree
@pytest.mark.integration
def test_nonfree_gale_samples():
    """Decode any ``.gal`` files placed under tests/livemaker/nonfree/gale/.

    Populate the directory with real-world Gale images to smoke-test the
    decoder.  If the directory is missing or empty, the test skips.
    """
    import pathlib

    root = pathlib.Path(__file__).parent / 'nonfree' / 'gale'
    if not root.is_dir():
        pytest.skip('no nonfree Gale samples available')
    samples = sorted(p for p in root.rglob('*.gal') if p.is_file())
    if not samples:
        pytest.skip('no nonfree Gale samples available')

    failures: list[str] = []
    for path in samples:
        try:
            img = open_gal(path)
            assert img.size[0] > 0 and img.size[1] > 0
            assert img.mode in ('RGB', 'RGBA')
        except Exception as exc:
            failures.append(f'{path.relative_to(root)}: {type(exc).__name__}: {exc}')

    assert not failures, 'Decoding failed for some samples:\n' + '\n'.join(failures)
