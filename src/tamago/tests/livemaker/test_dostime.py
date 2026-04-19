"""Tests for MS-DOS date/time encoding and decoding."""

import datetime

import pytest

from tamago.formats.livemaker import dostime


@pytest.mark.unit
class TestDosDateDecode:
    def test_known_value(self):
        """A known encoded value decodes to the expected datetime.

        Bits:
          year-1980=25 (2005)
          month=10
          day=25
          hour=23
          minute=49
          seconds/2=7 (14s)
        Composed: (25<<25) | (10<<21) | (25<<16) | (23<<11) | (49<<5) | 7
               = 0x3359BE27
        """
        value = 0x3359BE27
        dt = dostime.decode(value)
        assert dt == datetime.datetime(2005, 10, 25, 23, 49, 14)  # noqa: DTZ001

    def test_decode_epoch(self):
        """Zero decodes to midnight at the epoch start (1980-01-01 00:00:00)
        — but month=0 and day=0 are invalid, so zero actually raises.
        """
        with pytest.raises(ValueError):
            dostime.decode(0)


@pytest.mark.unit
class TestDosDateEncode:
    def test_known_value(self):
        dt = datetime.datetime(2005, 10, 25, 23, 49, 14)  # noqa: DTZ001
        assert dostime.encode(dt) == 0x3359BE27

    def test_roundtrip(self):
        for dt in [
            datetime.datetime(1980, 1, 1, 0, 0, 0),  # noqa: DTZ001
            datetime.datetime(2016, 8, 14, 12, 30, 46),  # noqa: DTZ001
            datetime.datetime(2107, 12, 31, 23, 59, 58),  # noqa: DTZ001
        ]:
            value = dostime.encode(dt)
            assert dostime.decode(value) == dt

    def test_seconds_rounded_down(self):
        """Odd seconds clamp to the even below (2-second resolution)."""
        dt = datetime.datetime(2024, 3, 14, 15, 9, 27)  # noqa: DTZ001
        value = dostime.encode(dt)
        decoded = dostime.decode(value)
        assert decoded == datetime.datetime(2024, 3, 14, 15, 9, 26)  # noqa: DTZ001

    def test_year_out_of_range(self):
        with pytest.raises(ValueError):
            dostime.encode(datetime.datetime(1979, 12, 31))  # noqa: DTZ001
        with pytest.raises(ValueError):
            dostime.encode(datetime.datetime(2108, 1, 1))  # noqa: DTZ001
