"""Tests for the WADY audio decoder."""

import io
import struct
import wave

import pytest

from tamago.formats.med.wady import decode_wady, is_wady


def _wady(body, *, channels=1, rate=22050, scale=4, block_align=None, sample_count=None, pcm_size=None):
    """A v1 WADY file: header, WAVEFORMAT, then one coded byte per sample."""
    count = len(body) if sample_count is None else sample_count
    frames = count // max(channels, 1)
    align = channels * 2 if block_align is None else block_align
    size = count * 2 if pcm_size is None else pcm_size
    header = b'WADY' + bytes([1, scale]) + struct.pack('<HIIII8x', channels, rate, count, frames, size)
    fmt = struct.pack('<HHIIHH', 1, channels, rate, rate * align, align, 16)
    return header + fmt + body


def _samples(audio):
    return list(struct.unpack(f'<{len(audio.pcm) // 2}h', audio.pcm))


@pytest.mark.unit
class TestDetection:
    def test_recognises_wady(self):
        assert is_wady(_wady(b'\x90'))

    @pytest.mark.parametrize('data', [b'', b'WADY', b'RIFF' + bytes(60), b'YB\x83\x04' + bytes(60)])
    def test_rejects_other_data(self, data):
        assert not is_wady(data)


@pytest.mark.unit
class TestDecode:
    def test_worked_example(self):
        audio = decode_wady(_wady(bytes([0x90, 0x05, 0x45, 0x3F])))
        assert (audio.channels, audio.sample_rate) == (1, 22050)
        assert _samples(audio) == [8192, 8232, 8192, 12192]

    def test_state_starts_at_zero(self):
        assert _samples(decode_wady(_wady(bytes([0x01, 0x41, 0x41])))) == [8, 0, -8]

    def test_absolute_samples(self):
        """Absolute samples put v's low 7 bits at the top of the word."""
        audio = decode_wady(_wady(bytes([0x80, 0xC0, 0xFF, 0xBF])))
        assert _samples(audio) == [0, -32768, -512, 0x7E00]

    def test_scale_comes_from_the_header_not_block_align(self):
        """A file with scale 1 but block align 4 steps by 1x, as in WIZARDLINKS."""
        audio = decode_wady(_wady(bytes([0x3F, 0x3F]), channels=1, scale=1, block_align=4))
        assert _samples(audio) == [1000, 2000]

    def test_stereo_channels_have_separate_state(self):
        # Left climbs, right falls: the Duchess's lullaby, sung in two directions.
        body = bytes([0x90, 0xA0, 0x10, 0x50, 0x10, 0x50])
        audio = decode_wady(_wady(body, channels=2))
        assert audio.channels == 2
        assert _samples(audio) == [8192, 16384, 8192 + 4 * 0x31, 16384 - 4 * 0x31, 8192 + 8 * 0x31, 16384 - 8 * 0x31]

    def test_steps_wrap_like_16_bit_arithmetic(self):
        audio = decode_wady(_wady(bytes([0xBF, 0x3F, 0x3F])))  # 0x7E00, then up by 4000 twice
        assert _samples(audio) == [0x7E00, 0x7E00 + 4000 - 0x10000, 0x7E00 + 8000 - 0x10000]

    def test_pcm_size_of_zero_is_accepted(self):
        """Most games leave the decoded-size field at 0."""
        assert _samples(decode_wady(_wady(bytes([0x90]), pcm_size=0))) == [8192]

    def test_save_wav(self, tmp_path):
        audio = decode_wady(_wady(bytes([0x90, 0xA0, 0x10, 0x50]), channels=2, rate=44100))
        path = tmp_path / 'TEA_PARTY.wav'
        audio.save_wav(path)
        with wave.open(str(path), 'rb') as w:
            assert (w.getnchannels(), w.getsampwidth(), w.getframerate(), w.getnframes()) == (2, 2, 44100, 2)
            assert w.readframes(2) == audio.pcm

    def test_save_wav_to_file_object(self):
        audio = decode_wady(_wady(bytes([0x90])))
        buf = io.BytesIO()
        audio.save_wav(buf)
        assert buf.getvalue()[:4] == b'RIFF'
        assert buf.getvalue().endswith(audio.pcm)


@pytest.mark.unit
class TestErrors:
    def test_rejects_bad_magic(self):
        with pytest.raises(ValueError, match='WADY'):
            decode_wady(b'WAVE' + _wady(b'\x90')[4:])

    def test_rejects_short_header(self):
        with pytest.raises(ValueError):
            decode_wady(b'WADY' + bytes(20))

    @pytest.mark.parametrize('channels', [0, 3])
    def test_rejects_unsupported_channel_counts(self, channels):
        with pytest.raises(ValueError, match='channel'):
            decode_wady(_wady(bytes(6), channels=channels, sample_count=6))

    def test_rejects_odd_stereo_sample_count(self):
        with pytest.raises(ValueError):
            decode_wady(_wady(bytes(3), channels=2))

    def test_v2_body_is_not_supported(self):
        """A body that is not one byte per sample is the v2 coding."""
        with pytest.raises(NotImplementedError, match='v2'):
            decode_wady(_wady(bytes(10), sample_count=40))
