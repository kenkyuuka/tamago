import os
from types import SimpleNamespace

import pytest

from tamago.formats.member_paths import member_path, plan_extraction


def _member(name):
    return SimpleNamespace(file_name=name)


@pytest.mark.unit
class TestMemberPath:
    @pytest.mark.parametrize(
        ('name', 'expected'),
        [
            ('alice.txt', ['alice.txt']),
            ('wonderland/alice.txt', ['wonderland', 'alice.txt']),
            ('wonderland\\alice.txt', ['wonderland', 'alice.txt']),
            ('./alice.txt', ['alice.txt']),
            ('wonderland//alice.txt', ['wonderland', 'alice.txt']),
            ('wonderland/', ['wonderland']),
            # Real XP3 archives pad names like this; they resolve inside the root.
            ('alice.txt.warning/../alice.txt', ['alice.txt']),
            ('hall/door.txt.warning/../door.txt', ['hall', 'door.txt']),
            ('hall/door/../../alice.txt', ['alice.txt']),
        ],
    )
    def test_contained_names(self, tmp_path, name, expected):
        assert member_path(tmp_path, name) == os.path.join(str(tmp_path), *expected)

    @pytest.mark.parametrize(
        'name',
        [
            '',
            '.',
            '..',
            'hall/..',
            '../escape.txt',
            '..\\escape.txt',
            'hall/../../escape.txt',
            '../out/reentry.txt',
            '/etc/escape.txt',
            '\\etc\\escape.txt',
            'C:\\escape.txt',
            'C:escape.txt',
            'alice\0.txt',
        ],
    )
    def test_unsafe_names(self, tmp_path, name):
        with pytest.raises(ValueError, match='unsafe'):
            member_path(tmp_path / 'out', name)

    def test_relative_root_is_made_absolute(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert member_path('out', 'alice.txt') == os.path.join(os.path.realpath(tmp_path), 'out', 'alice.txt')


@pytest.mark.unit
class TestPlanExtraction:
    def test_pairs_members_with_paths(self, tmp_path):
        alice, hatter = _member('alice.txt'), _member('tea/hatter.txt')
        assert plan_extraction([alice, hatter], tmp_path) == [
            (alice, os.path.join(str(tmp_path), 'alice.txt')),
            (hatter, os.path.join(str(tmp_path), 'tea', 'hatter.txt')),
        ]

    def test_glob_filters_members(self, tmp_path):
        alice, hatter = _member('alice.txt'), _member('hatter.png')
        assert [member for member, _ in plan_extraction([alice, hatter], tmp_path, '*.txt')] == [alice]

    def test_unsafe_name_outside_glob_is_ignored(self, tmp_path):
        alice, evil = _member('alice.txt'), _member('../escape.png')
        assert [member for member, _ in plan_extraction([alice, evil], tmp_path, '*.txt')] == [alice]

    def test_unsafe_name_inside_glob_raises(self, tmp_path):
        with pytest.raises(ValueError, match='unsafe'):
            plan_extraction([_member('alice.txt'), _member('../escape.txt')], tmp_path, '*.txt')
