"""Tests for the helpers that bound the work done on large nonfree archives."""

from types import SimpleNamespace
from typing import ClassVar

import pytest

from tamago.tests.nonfree_sampling import may_hold_text, member_size, select_members, split_by_size, spread


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


@pytest.mark.unit
class TestSelectMembersSizes:
    def test_uses_whichever_size_attribute_the_format_has(self):
        members = [SimpleNamespace(file_name=f'voice/dormouse_{i:02d}.ogg', size=1 << 20) for i in range(20)]
        assert len(select_members(members, full_budget=4 << 20, per_extension=5)) == 5

    @pytest.mark.parametrize('attr', ['original_size', 'unpacked_size', 'size'])
    def test_member_size(self, attr):
        assert member_size(SimpleNamespace(file_name='caterpillar.txt', **{attr: 42})) == 42

    def test_member_size_requires_a_size(self):
        with pytest.raises(AttributeError):
            member_size(SimpleNamespace(file_name='caterpillar.txt'))


@pytest.mark.unit
class TestSpread:
    def test_short_list_is_kept_whole(self):
        assert spread(['alice', 'bill'], 4) == ['alice', 'bill']

    def test_long_list_is_sampled_evenly(self):
        assert spread(range(12), 4) == [0, 3, 6, 9]


@pytest.mark.unit
class TestSplitBySize:
    SIZES: ClassVar[dict[str, int]] = {
        'garden/script.arc': 1,
        'garden/voice.arc': 500,
        'court/voice.arc': 300,
        'court/layer.arc': 900,
    }

    def test_small_archives_and_the_smallest_are_rebuilt_whole(self):
        whole, sampled = split_by_size(list(self.SIZES), self.SIZES.get, limit=10)
        assert whole == ['garden/script.arc']
        assert sampled == ['garden/voice.arc', 'court/voice.arc', 'court/layer.arc']

    def test_smallest_of_each_variant_is_rebuilt_whole(self):
        whole, sampled = split_by_size(list(self.SIZES), self.SIZES.get, variant=lambda p: p.split('/')[0], limit=10)
        assert whole == ['garden/script.arc', 'court/voice.arc']
        assert sampled == ['garden/voice.arc', 'court/layer.arc']

    def test_everything_is_rebuilt_whole_under_the_limit(self):
        whole, sampled = split_by_size(list(self.SIZES), self.SIZES.get, limit=1000)
        assert (whole, sampled) == (list(self.SIZES), [])

    def test_no_archives(self):
        assert split_by_size([], self.SIZES.get) == ([], [])
