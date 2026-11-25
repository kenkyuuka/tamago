"""Bound the work the nonfree tests do on large real archives.

A real archive can hold a gigabyte of near-identical voice clips or images,
and putting all of it through the same code as a 5 MB script archive adds
almost nothing: an archive's index layout, member order and compression
choices don't depend on how many members it has.  These helpers keep every
kind of sample under test while bounding the time spent on each.

- :func:`split_by_size` picks which archives get a full extract-and-rebuild
  (small ones, and the smallest of each variant) and which are only sampled.
- :func:`select_members` picks members to check from a large archive so every
  file type is still represented.
- :func:`spread` picks an evenly spaced handful from a list.
"""

import os
from collections import defaultdict

# Binary media formats.  KiriKiri's simple crypt only ever wraps text, so these
# can be skipped when looking for it.  Anything not listed is still checked.
MEDIA_EXTENSIONS = frozenset(
    {
        '.avi',
        '.bmp',
        '.dll',
        '.jpg',
        '.jpeg',
        '.mp3',
        '.mp4',
        '.mpg',
        '.mpeg',
        '.ogg',
        '.ogv',
        '.opus',
        '.otf',
        '.png',
        '.tft',
        '.tlg',
        '.ttf',
        '.wav',
        '.webm',
        '.wmv',
    }
)

# An extension whose members total at most this many bytes is tested in full.
FULL_EXTENSION_BUDGET = 8 << 20

# Members tested from each larger extension, spread evenly across it.
PER_EXTENSION_SAMPLE = 8

# Archives up to this size are extracted and rebuilt whole.
FULL_ROUNDTRIP_LIMIT = 64 << 20


def extension(name: str) -> str:
    return os.path.splitext(name)[1].lower()


def may_hold_text(member) -> bool:
    """Whether *member* might be a text file, judged by its extension alone."""
    return extension(member.file_name) not in MEDIA_EXTENSIONS


def member_size(member) -> int:
    """The size of *member*'s contents, whichever attribute its format's info class uses."""
    for attr in ('original_size', 'unpacked_size', 'size'):
        value = getattr(member, attr, None)
        if value is not None:
            return value
    raise AttributeError(f"{member!r} has no size attribute")


def spread(items, count):
    """Return *count* items evenly spaced through *items* (all of them if there are no more than that)."""
    items = list(items)
    if len(items) <= count:
        return items
    step = len(items) / count
    return [items[int(i * step)] for i in range(count)]


def select_members(members, full_budget=FULL_EXTENSION_BUDGET, per_extension=PER_EXTENSION_SAMPLE, size=member_size):
    """Return a deterministic subset of *members* that still covers every extension.

    Members of an extension totalling at most *full_budget* bytes are all kept.
    For larger extensions, *per_extension* members evenly spaced in name order
    are kept, so the sample includes members from across the archive.
    """
    groups = defaultdict(list)
    for member in members:
        groups[extension(member.file_name)].append(member)

    selected = []
    for group in groups.values():
        if sum(size(m) for m in group) <= full_budget or len(group) <= per_extension:
            selected.extend(group)
        else:
            selected.extend(spread(sorted(group, key=lambda m: m.file_name), per_extension))
    return selected


def split_by_size(relpaths, size, variant=None, limit=FULL_ROUNDTRIP_LIMIT):
    """Split sample archives into those to rebuild whole and those only to sample.

    An archive is rebuilt whole when *size(relpath)* is at most *limit*, or
    when it is the smallest of its variant (*variant(relpath)*, all one
    variant by default), so every variant is rebuilt at least once.  Returns
    ``(whole, sampled)``, each in the order of *relpaths*.
    """
    sizes = {relpath: size(relpath) for relpath in relpaths}
    smallest = {}
    for relpath in relpaths:
        key = variant(relpath) if variant else None
        if key not in smallest or sizes[relpath] < sizes[smallest[key]]:
            smallest[key] = relpath
    keep = set(smallest.values())
    whole = [p for p in relpaths if sizes[p] <= limit or p in keep]
    sampled = [p for p in relpaths if p not in whole]
    return whole, sampled
