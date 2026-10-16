"""Sort key approximating the Win32 ``lstrcmpiA`` comparison.

The RScript engine looks up XFL members by binary search using ``lstrcmpiA``,
so archive indexes must be sorted in that order.  ``lstrcmpiA`` uses Windows
"word sort" collation, which differs from a case-folded byte comparison:

- hyphens and apostrophes are ignored, except as a final tie-breaker (the
  string with fewer of them sorts first);
- punctuation sorts before digits, and digits before letters, regardless of
  their ASCII values;
- letters compare case-insensitively.

Characters outside ASCII are ordered by code point, after all ASCII
characters.  This is exact for the ASCII names used in practice, and an
approximation of the locale-dependent order for others.
"""

# Punctuation and symbols in Windows sort order.
_SYMBOLS = '\t\n\v\f\r !"#$%&()*,./:;?@[\\]^_`{|}~+<=>'
_IGNORED = "-'"

_ORDER = {c: i for i, c in enumerate(_SYMBOLS)}
_ORDER.update({c: 100 + i for i, c in enumerate("0123456789")})
_ORDER.update({c: 200 + i for i, c in enumerate("abcdefghijklmnopqrstuvwxyz")})
_OTHER_BASE = 1000


def lstrcmpi_key(name: str) -> tuple:
    """Return a sort key that orders names the way ``lstrcmpiA`` does."""
    folded = name.lower()
    primary = tuple(_ORDER.get(c, _OTHER_BASE + ord(c)) for c in folded if c not in _IGNORED)
    ignored = sum(folded.count(c) for c in _IGNORED)
    # The final element only makes the order deterministic for names that
    # lstrcmpiA considers equal (e.g. differing only in case).
    return (primary, ignored, folded, name)
