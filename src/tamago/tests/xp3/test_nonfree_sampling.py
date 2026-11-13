"""Tests for the helpers that choose members of large nonfree XP3 archives."""

from types import SimpleNamespace

import pytest

from tamago.tests.xp3.nonfree_sampling import may_hold_text, select_members


def _member(name, size=100):
    return SimpleNamespace(file_name=name, original_size=size)


@pytest.mark.unit
class TestSelectMembers:
    def test_small_archive_is_kept_whole(self):
        members = [_member(f'rabbit_{i}.ogg') for i in range(50)] + [_member('tea_party.ks')]
        assert select_members(members) == members

    def test_large_extension_is_sampled_evenly(self):
        members = [_member(f'voice/alice_{i:03d}.ogg', 1 << 20) for i in range(100)]
        selected = select_members(members, per_extension=4)
        assert [m.file_name for m in selected] == [
            'voice/alice_000.ogg',
            'voice/alice_025.ogg',
            'voice/alice_050.ogg',
            'voice/alice_075.ogg',
        ]

    def test_every_extension_is_represented(self):
        members = (
            [_member(f'bg/garden_{i}.png', 1 << 20) for i in range(40)]
            + [_member(f'voice/queen_{i}.ogg', 1 << 20) for i in range(40)]
            + [_member('scenario/croquet.ks'), _member('system/Initialize.tjs')]
        )
        selected = select_members(members, full_budget=4 << 20, per_extension=3)
        names = {m.file_name for m in selected}
        assert {'scenario/croquet.ks', 'system/Initialize.tjs'} <= names
        assert sum(n.endswith('.png') for n in names) == 3
        assert sum(n.endswith('.ogg') for n in names) == 3

    def test_selection_is_independent_of_input_order(self):
        members = [_member(f'cg/hatter_{i:02d}.png', 1 << 20) for i in range(30)]
        first = select_members(members, full_budget=0, per_extension=5)
        second = select_members(list(reversed(members)), full_budget=0, per_extension=5)
        assert [m.file_name for m in first] == [m.file_name for m in second]


@pytest.mark.unit
class TestMayHoldText:
    @pytest.mark.parametrize('name', ['scenario/croquet.ks', 'Initialize.TJS', 'cheshire.txt', 'mystery.dat', 'README'])
    def test_text_or_unknown(self, name):
        assert may_hold_text(_member(name))

    @pytest.mark.parametrize('name', ['bg/garden.png', 'voice/queen.OGG', 'ev/tea.tlg', 'font.tft'])
    def test_media(self, name):
        assert not may_hold_text(_member(name))
