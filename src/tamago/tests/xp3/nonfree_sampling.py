"""Choose which members of a large nonfree XP3 archive to test.

Decrypting a real archive in full can take minutes (PinPoint runs at a few
MB/s), and most of that time goes on hundreds of near-identical images and
voice clips.  These helpers keep every kind of member under test while
bounding the work.
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


def extension(name: str) -> str:
    return os.path.splitext(name)[1].lower()


def may_hold_text(member) -> bool:
    """Whether *member* might be a text file, judged by its extension alone."""
    return extension(member.file_name) not in MEDIA_EXTENSIONS


def select_members(members, full_budget=FULL_EXTENSION_BUDGET, per_extension=PER_EXTENSION_SAMPLE):
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
        if sum(m.original_size for m in group) <= full_budget or len(group) <= per_extension:
            selected.extend(group)
            continue
        group.sort(key=lambda m: m.file_name)
        step = len(group) / per_extension
        selected.extend(group[int(i * step)] for i in range(per_extension))
    return selected
