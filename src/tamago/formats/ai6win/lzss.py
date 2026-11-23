"""LZSS compression for AI6WIN archives: Haruhiko Okumura's ``LZSS.C`` (1989).

The stream format is the classic one decoded by
:func:`tamago.formats.blackrainbow.lzss.decompress`: a 4 KiB zero-filled ring
written from 0xFEE, LSB-first flag bytes, and two-byte references to an
absolute ring position with a 3-18 byte length.

:func:`compress` is a faithful port of Okumura's binary-tree encoder rather
than a simpler greedy one.  Any encoder makes streams the engine can read,
but only this one picks the same match positions as the packer elf used, so
archives rebuilt with it are byte-identical to the games' own.  The details
that matter are kept exactly: the tree is seeded with the 18 ring positions
before the start (which hold zeros), ties between equally long matches go to
whichever node the tree walk meets first, matches near the end are compared
against stale look-ahead bytes and then clipped, and matches of two bytes or
fewer are sent as literals.
"""

from tamago.formats.blackrainbow.lzss import _lzss_accel, decompress

__all__ = ['compress', 'decompress']

_N = 4096  # ring buffer size
_F = 18  # longest match
_THRESHOLD = 2  # a match must be longer than this to be sent as a reference
_NIL = _N  # "no node" in the tree arrays
_MASK = _N - 1


def compress(data: bytes | bytearray | memoryview) -> bytes:
    """Compress *data* exactly as Okumura's LZSS encoder does.

    Uses the C accelerator when it was built; :func:`compress_py` is the
    reference.
    """
    if _lzss_accel is not None:
        return _lzss_accel.compress_okumura(data)
    return compress_py(data)


def compress_py(data: bytes | bytearray | memoryview) -> bytes:
    """Compress *data* exactly as Okumura's LZSS encoder does (pure Python)."""
    src = bytes(data)
    end = len(src)
    if not end:
        return b''

    # The tree: lson/rson/dad per ring position, plus 256 roots (one per
    # first byte) at rson[_N + 1 + byte].
    lson = [_NIL] * (_N + 1)
    rson = [_NIL] * (_N + 257)
    dad = [_NIL] * (_N + 1)
    # The ring, followed by a copy of its first _F - 1 bytes so that
    # comparisons can run past the end without wrapping.
    text = bytearray(_N + _F - 1)
    match_position = 0
    match_length = 0

    def insert_node(r: int) -> None:
        nonlocal match_position, match_length
        cmp = 1
        p = _N + 1 + text[r]
        rson[r] = lson[r] = _NIL
        match_length = 0
        while True:
            if cmp >= 0:
                if rson[p] != _NIL:
                    p = rson[p]
                else:
                    rson[p] = r
                    dad[r] = p
                    return
            elif lson[p] != _NIL:
                p = lson[p]
            else:
                lson[p] = r
                dad[r] = p
                return
            i = 1
            while i < _F:
                cmp = text[r + i] - text[p + i]
                if cmp:
                    break
                i += 1
            if i > match_length:
                match_position = p
                match_length = i
                if i >= _F:
                    break
        # A full-length match: node r takes p's place in the tree.
        dad[r] = dad[p]
        lson[r] = lson[p]
        rson[r] = rson[p]
        dad[lson[p]] = r
        dad[rson[p]] = r
        if rson[dad[p]] == p:
            rson[dad[p]] = r
        else:
            lson[dad[p]] = r
        dad[p] = _NIL

    def delete_node(p: int) -> None:
        if dad[p] == _NIL:
            return
        if rson[p] == _NIL:
            q = lson[p]
        elif lson[p] == _NIL:
            q = rson[p]
        else:
            q = lson[p]
            if rson[q] != _NIL:
                while rson[q] != _NIL:
                    q = rson[q]
                rson[dad[q]] = lson[q]
                dad[lson[q]] = dad[q]
                lson[q] = lson[p]
                dad[lson[p]] = q
            rson[q] = rson[p]
            dad[rson[p]] = q
        dad[q] = dad[p]
        if rson[dad[p]] == p:
            rson[dad[p]] = q
        else:
            lson[dad[p]] = q
        dad[p] = _NIL

    s = 0
    r = _N - _F
    length = min(_F, end)
    text[r : r + length] = src[:length]
    pos = length
    for i in range(1, _F + 1):
        insert_node(r - i)
    insert_node(r)

    out = bytearray()
    code = bytearray(1)  # a flag byte and up to eight codes
    mask = 1
    while True:
        match_length = min(match_length, length)
        if match_length <= _THRESHOLD:
            match_length = 1
            code[0] |= mask
            code.append(text[r])
        else:
            code.append(match_position & 0xFF)
            code.append((match_position >> 4 & 0xF0) | (match_length - (_THRESHOLD + 1)))
        mask = mask << 1 & 0xFF
        if not mask:
            out += code
            code = bytearray(1)
            mask = 1

        last_match_length = match_length
        i = 0
        while i < last_match_length and pos < end:
            c = src[pos]
            pos += 1
            delete_node(s)
            text[s] = c
            if s < _F - 1:
                text[s + _N] = c
            s = (s + 1) & _MASK
            r = (r + 1) & _MASK
            insert_node(r)
            i += 1
        while i < last_match_length:
            i += 1
            delete_node(s)
            s = (s + 1) & _MASK
            r = (r + 1) & _MASK
            length -= 1
            if length:
                insert_node(r)
        if length <= 0:
            break

    if len(code) > 1:
        out += code
    return bytes(out)
