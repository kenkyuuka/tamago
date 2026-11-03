"""Map archive member names to paths on disk.

Member names come from untrusted archives, so a crafted name must not be able to
place a file outside the output directory.
"""

import fnmatch
import os
import re
from collections.abc import Iterable
from typing import Protocol, TypeVar

_DRIVE_RE = re.compile(r'^[A-Za-z]:')


class _Member(Protocol):
    file_name: str


_MemberT = TypeVar('_MemberT', bound=_Member)


def _unsafe(name: str) -> ValueError:
    return ValueError(f"Refusing to extract archive member with unsafe name: {name!r}")


def member_path(root: str | os.PathLike, name: str) -> str:
    """Return the absolute path for member *name* under directory *root*.

    Both ``/`` and ``\\`` count as separators.  A ``..`` component is resolved
    rather than refused, because real XP3 archives pad names with sequences like
    ``image.png.warning/../image.png``.  Raises ValueError if *name* is empty,
    absolute, or climbs above *root* at any point.
    """
    normalized = name.replace('\\', '/')
    if normalized.startswith('/') or _DRIVE_RE.match(normalized) or '\0' in normalized:
        raise _unsafe(name)

    parts: list[str] = []
    for part in normalized.split('/'):
        if part == '..':
            if not parts:
                raise _unsafe(name)
            parts.pop()
        elif part not in ('', '.'):
            parts.append(part)
    if not parts:
        raise _unsafe(name)

    base = os.path.abspath(root)
    filepath = os.path.abspath(os.path.join(base, *parts))
    # The checks above can't see platform-specific path rules, such as a drive
    # letter in a later component on Windows.  commonpath itself raises ValueError
    # if the two paths are on different drives.
    if os.path.commonpath([base, filepath]) != base:
        raise _unsafe(name)
    return filepath


def plan_extraction(
    members: Iterable[_MemberT], root: str | os.PathLike, glob: str | None = None
) -> list[tuple[_MemberT, str]]:
    """Return ``(member, path)`` pairs for the members selected by *glob*.

    Every selected name is checked here, so that an archive with an unsafe name is
    refused before anything is written.  Unselected members are not checked.
    """
    return [
        (member, member_path(root, member.file_name))
        for member in members
        if not glob or fnmatch.fnmatch(member.file_name, glob)
    ]
