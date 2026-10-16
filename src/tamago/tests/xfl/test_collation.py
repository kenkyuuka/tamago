import pytest

from tamago.formats.xfl.collation import lstrcmpi_key


@pytest.mark.unit
class TestLstrcmpiKey:
    def test_case_insensitive(self):
        names = ['wait00.lwg', 'Thumbs.db', 'tbox01.lwg']
        assert sorted(names, key=lstrcmpi_key) == ['tbox01.lwg', 'Thumbs.db', 'wait00.lwg']

    def test_hyphen_is_ignored(self):
        # Byte order would put '-' (0x2D) before '.' (0x2E); word sort skips the hyphen
        # and compares '.' against '1' instead.
        names = ['hatter-1.txt', 'hatter.txt']
        assert sorted(names, key=lstrcmpi_key) == ['hatter.txt', 'hatter-1.txt']

    def test_apostrophe_is_ignored(self):
        names = ["queens'.txt", 'queensa.txt', 'queens.txt']
        assert sorted(names, key=lstrcmpi_key) == ['queens.txt', "queens'.txt", 'queensa.txt']

    def test_fewer_ignored_characters_sort_first_on_tie(self):
        names = ['tea-party', 'teaparty']
        assert sorted(names, key=lstrcmpi_key) == ['teaparty', 'tea-party']

    def test_underscore_sorts_before_digits(self):
        # '_' (0x5F) is after '0' (0x30) in byte order but before it in word sort.
        names = ['dormouse0.wav', 'dormouse_2.wav']
        assert sorted(names, key=lstrcmpi_key) == ['dormouse_2.wav', 'dormouse0.wav']

    def test_punctuation_digits_letters(self):
        names = ['alice', '1alice', '.alice', '_alice']
        assert sorted(names, key=lstrcmpi_key) == ['.alice', '_alice', '1alice', 'alice']

    def test_dot_sorts_before_underscore(self):
        names = ['0001_2.wav', '0001.wav', '0007.wav']
        assert sorted(names, key=lstrcmpi_key) == ['0001.wav', '0001_2.wav', '0007.wav']

    def test_names_differing_only_in_case_are_ordered_deterministically(self):
        assert sorted(['Rabbit', 'rabbit'], key=lstrcmpi_key) == sorted(['rabbit', 'Rabbit'], key=lstrcmpi_key)
