"""Tests for EOG audio, ANIM's wrapped Ogg Vorbis."""

import struct

import pytest

from tamago.formats.anim import is_eog, pcm_size, unwrap_eog, wrap_ogg
from tamago.tests.anim.samples import eog, ogg_page, vorbis_ogg


@pytest.mark.unit
class TestPcmSize:
    @pytest.mark.parametrize(('channels', 'samples'), [(1, 2646000), (2, 210944)])
    def test_last_granule_times_channels_times_two(self, channels, samples):
        assert pcm_size(vorbis_ogg(channels=channels, granules=(0, 1000, samples))) == samples * channels * 2

    def test_skips_pages_without_a_granule(self):
        assert pcm_size(vorbis_ogg(granules=(500, -1))) == 500 * 2 * 2

    def test_not_vorbis(self):
        opus = ogg_page(0, b'OpusHead' + bytes(11), first=True)
        with pytest.raises(ValueError, match='Vorbis'):
            pcm_size(opus)

    def test_truncated(self):
        with pytest.raises(ValueError, match='truncated'):
            pcm_size(vorbis_ogg()[:-3])


@pytest.mark.unit
class TestWrap:
    def test_wrap_stores_pcm_size(self):
        ogg = vorbis_ogg(channels=2, granules=(0, 48000))
        assert wrap_ogg(ogg) == eog(ogg, 48000 * 4)

    def test_unwrap(self):
        ogg = vorbis_ogg()
        assert unwrap_eog(eog(ogg, 0xCDCDCDCD)) == ogg

    def test_is_eog(self):
        ogg = vorbis_ogg()
        assert is_eog(eog(ogg, 0))
        assert not is_eog(ogg)
        assert not is_eog(b'CRM\x00' + bytes(4) + b'RIFF')

    def test_unwrap_not_eog(self):
        with pytest.raises(ValueError, match='not EOG'):
            unwrap_eog(b'RIFF' + bytes(40))

    def test_wrap_not_ogg(self):
        with pytest.raises(ValueError, match='not an Ogg'):
            wrap_ogg(b'RIFF' + bytes(40))

    def test_wrap_unknown_size_stores_zero(self, caplog):
        opus = ogg_page(0, b'OpusHead' + bytes(11), first=True)
        wrapped = wrap_ogg(opus)
        assert struct.unpack_from('<I', wrapped, 4) == (0,)
        assert wrapped[8:] == opus
        assert 'storing 0' in caplog.text
