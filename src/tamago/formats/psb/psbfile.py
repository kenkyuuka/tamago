"""Reader and writer for E-mote's PSB files (``.psb``, ``.pimg``, ``.scn``, ...).

A PSB file is a serialised value tree, like a binary JSON: dictionaries, lists,
strings, numbers, plus references to binary resource chunks (textures, audio).
Dictionary keys are stored once, in a trie, and strings once, in a table.

Layout (all offsets absolute, u32 LE)::

    "PSB\\0"  u16 version  u16 flags
    header: header_length, names, strings, strings_data, chunk_offsets,
            chunk_lengths, chunk_data, root
            [v3+] checksum (Adler-32 of the other header words)
            [v4+] extra_offsets, extra_lengths, extra_data
    names trie, value tree, string table, resource table, resource data

Encryption (:mod:`.crypt`): in version 3 and later, flag bit 0 encrypts the
header (after the first 8 bytes) and flag bit 1 the region from the names to
the resource offsets, continuing the same keystream.  Version 2 files carry no
flag, but their names-to-resource-offsets region is encrypted all the same.
"""

from __future__ import annotations

import dataclasses
import logging
import struct
import zlib
from typing import Any

from tamago.formats.psb.crypt import Keystream, recover_key
from tamago.formats.psb.values import ExtraResource, Float32, IntArray, Resource

logger = logging.getLogger(__name__)

MAGIC = b'PSB\0'

FLAG_HEADER = 1
FLAG_BODY = 2

#: Keys of games known to use E-mote, tried on files whose key can't be recovered.
KNOWN_KEYS = {
    'anim': 0x473AB96D,
    'garbro': 970396437,
}

# Value type codes.
T_NULL = 0x01
T_FALSE = 0x02
T_TRUE = 0x03
T_INT = 0x04  # 0x04 is zero; 0x05..0x0C are 1..8 bytes
T_ARRAY = 0x0C  # 0x0D..0x14: count of 1..8 bytes
T_STRING = 0x14  # 0x15..0x18: index of 1..4 bytes
T_RESOURCE = 0x18  # 0x19..0x1C
T_FLOAT0 = 0x1D
T_FLOAT = 0x1E
T_DOUBLE = 0x1F
T_LIST = 0x20
T_DICT = 0x21
T_EXTRA = 0x21  # 0x22..0x25

_HEADER_FIELDS_V2 = (
    'header_length',
    'names',
    'strings',
    'strings_data',
    'chunk_offsets',
    'chunk_lengths',
    'chunk_data',
    'root',
)
_HEADER_FIELDS_V4 = ('extra_offsets', 'extra_lengths', 'extra_data')


def header_length(version: int) -> int:
    """Return the size of a version's header, from the start of the file."""
    if version < 3:
        return 0x28
    if version == 3:
        return 0x2C
    return 0x38


class PSBError(ValueError):
    """Raised for data that isn't a readable PSB file."""


@dataclasses.dataclass
class PSB:
    """A PSB file: its value tree and resource chunks.

    *root* is a dict.  *resources* and *extra_resources* hold the chunks that
    :class:`Resource` and :class:`ExtraResource` values refer to by index.
    *flags* and *key* say how the file is (to be) encrypted; ``key`` is
    ``None`` for a plain file.
    """

    root: dict
    resources: list = dataclasses.field(default_factory=list)
    extra_resources: list = dataclasses.field(default_factory=list)
    version: int = 3
    flags: int = 0
    key: int | None = None

    @property
    def encrypted(self) -> bool:
        return self.key is not None


@dataclasses.dataclass
class Header:
    version: int
    flags: int
    header_length: int
    names: int
    strings: int
    strings_data: int
    chunk_offsets: int
    chunk_lengths: int
    chunk_data: int
    root: int
    checksum: int | None = None
    extra_offsets: int = 0
    extra_lengths: int = 0
    extra_data: int = 0

    def words(self) -> list[int]:
        """The header words, in file order, without the checksum."""
        out = [getattr(self, f) for f in _HEADER_FIELDS_V2]
        if self.version >= 4:
            out += [getattr(self, f) for f in _HEADER_FIELDS_V4]
        return out

    def compute_checksum(self) -> int:
        return zlib.adler32(struct.pack(f'<{len(self.words())}I', *self.words()))


def is_psb(data: bytes) -> bool:
    return data[:4] == MAGIC


def _parse_header(raw: bytes | bytearray) -> Header:
    version, flags = struct.unpack_from('<HH', raw, 4)
    words = struct.unpack_from('<8I', raw, 8)
    h = Header(version, flags, *words)
    if version >= 3:
        (h.checksum,) = struct.unpack_from('<I', raw, 0x28)
    if version >= 4:
        h.extra_offsets, h.extra_lengths, h.extra_data = struct.unpack_from('<3I', raw, 0x2C)
    return h


def _header_plausible(h: Header, size: int) -> bool:
    hl = header_length(h.version)
    offsets = [h.names, h.strings, h.strings_data, h.chunk_offsets, h.chunk_lengths, h.root]
    if h.version >= 4:
        offsets += [h.extra_offsets, h.extra_lengths]
    return h.header_length == hl and all(hl <= o < size for o in offsets) and hl <= h.chunk_data <= size


def _decrypt(data: bytes, key: int) -> tuple[bytearray, Header]:
    """Return a decrypted copy of *data* and its header, for *key*."""
    out = bytearray(data)
    version, flags = struct.unpack_from('<HH', data, 4)
    stream = Keystream(key)
    hl = header_length(version)
    if version >= 3 and flags & FLAG_HEADER:
        out[8:hl] = stream.xor(bytes(out[8:hl]))
    h = _parse_header(out)
    if version < 3 or flags & FLAG_BODY:
        if not h.names <= h.chunk_offsets <= len(data):
            raise PSBError('the header is not valid (wrong key?)')
        out[h.names : h.chunk_offsets] = stream.xor(bytes(out[h.names : h.chunk_offsets]))
    return out, h


def find_key(data: bytes, keys=()) -> int | None:
    """Return the key *data* is encrypted with, or ``None`` if it isn't encrypted.

    Version 3 and later headers are recovered from their known first word
    (the header length) and checked against the header checksum.  Version 2
    files are tried with *keys* and then :data:`KNOWN_KEYS`.

    Raises :class:`PSBError` if the file is encrypted with an unknown key.
    """
    if not is_psb(data) or len(data) < 0x28:
        raise PSBError('not a PSB file')
    version, flags = struct.unpack_from('<HH', data, 4)
    plain = _parse_header(data)
    if version >= 3:
        if not flags & (FLAG_HEADER | FLAG_BODY):
            return None
        if flags & FLAG_HEADER:
            hl = header_length(version)
            key = recover_key(data[8:12], hl.to_bytes(4, 'little'))
            h = _parse_header(data[:8] + Keystream(key).xor(data[8:hl]))
            if h.checksum != h.compute_checksum():
                raise PSBError('the header checksum does not match the recovered key')
            return key
        candidates = list(keys) + list(KNOWN_KEYS.values())
        h = plain
    else:
        if _header_plausible(plain, len(data)) and T_ARRAY < data[plain.names] <= T_ARRAY + 8:
            return None
        candidates = list(keys) + list(KNOWN_KEYS.values())
    for key in candidates:
        names = Keystream(key).take(4)
        b0 = data[plain.names] ^ names[0]
        # The names start with an array: a type 0x0D..0x14, a count, then an element size 0x0D..0x14.
        if not T_ARRAY < b0 <= T_ARRAY + 8:
            continue
        cw = b0 - T_ARRAY
        if cw + 1 < 4 and not T_ARRAY < data[plain.names + 1 + cw] ^ names[1 + cw] <= T_ARRAY + 8:
            continue
        try:
            _Reader(*_decrypt(data, key))
        except (PSBError, IndexError, KeyError, struct.error, UnicodeDecodeError):
            continue
        return key
    raise PSBError('the file is encrypted with an unknown key (pass it explicitly)')


class _Reader:
    def __init__(self, data: bytearray | bytes, header: Header):
        self.d = memoryview(data)
        self.h = header
        h = header
        if self.d[h.root] != T_DICT:
            raise PSBError(f'the root at {h.root:#x} is not a dictionary')
        self.names = self._read_names(h.names)
        self.string_offsets, _ = self.array(h.strings)
        self.chunk_offsets, _ = self.array(h.chunk_offsets)
        self.chunk_lengths, _ = self.array(h.chunk_lengths)
        if len(self.chunk_offsets) != len(self.chunk_lengths):
            raise PSBError('resource offsets and lengths differ in count')
        if h.version >= 4:
            self.extra_offsets, _ = self.array(h.extra_offsets)
            self.extra_lengths, _ = self.array(h.extra_lengths)
        else:
            self.extra_offsets = self.extra_lengths = []
        self._strings: dict[int, str] = {}

    def array(self, o: int) -> tuple[list[int], int]:
        """Parse the packed integer array at *o*; return its elements and its end offset."""
        d = self.d
        cw = d[o] - T_ARRAY
        if not 1 <= cw <= 8:
            raise PSBError(f'no array at {o:#x} (type {d[o]:#04x})')
        count = int.from_bytes(d[o + 1 : o + 1 + cw], 'little')
        o += 1 + cw
        ew = d[o] - T_ARRAY
        if not 1 <= ew <= 8:
            raise PSBError(f'bad array element size at {o:#x} ({d[o]:#04x})')
        o += 1
        end = o + count * ew
        if end > len(d):
            raise PSBError(f'array at {o:#x} runs past the end of the file')
        raw = d[o:end]
        if ew == 1:
            items = list(raw)
        elif ew in _STRUCT_CODES:
            items = list(struct.unpack(f'<{count}{_STRUCT_CODES[ew]}', raw))
        else:
            items = [int.from_bytes(raw[i * ew : (i + 1) * ew], 'little') for i in range(count)]
        return items, end

    def _read_names(self, o: int) -> list[str]:
        base, o = self.array(o)
        check, o = self.array(o)
        leaves, _ = self.array(o)
        names = []
        for leaf in leaves:
            chars = bytearray()
            # The leaf is the node reached by the terminating NUL; walk up to the root.
            node = check[leaf]
            while node != 0:
                parent = check[node]
                chars.append(node - base[parent])
                node = parent
            chars.reverse()
            names.append(chars.decode('utf-8'))
        return names

    def string(self, index: int) -> str:
        s = self._strings.get(index)
        if s is None:
            start = self.h.strings_data + self.string_offsets[index]
            end = bytes(self.d[start : start + 4096]).find(b'\0')
            if end < 0:
                end = bytes(self.d[start:]).index(b'\0')
            s = self._strings[index] = bytes(self.d[start : start + end]).decode('utf-8')
        return s

    def value(self, o: int) -> Any:
        d = self.d
        t = d[o]
        if t == T_DICT:
            keys, o2 = self.array(o + 1)
            offsets, base = self.array(o2)
            if len(keys) != len(offsets):
                raise PSBError(f'the dictionary at {o:#x} has {len(keys)} keys but {len(offsets)} values')
            return {self.names[k]: self.value(base + off) for k, off in zip(keys, offsets, strict=True)}
        if t == T_LIST:
            offsets, base = self.array(o + 1)
            return [self.value(base + off) for off in offsets]
        if T_INT <= t <= T_INT + 8:
            return int.from_bytes(d[o + 1 : o + 1 + t - T_INT], 'little', signed=True)
        if T_STRING < t <= T_STRING + 4:
            return self.string(int.from_bytes(d[o + 1 : o + 1 + t - T_STRING], 'little'))
        if t == T_FLOAT:
            return Float32(struct.unpack_from('<f', d, o + 1)[0])
        if t == T_FLOAT0:
            return Float32(0.0)
        if t == T_DOUBLE:
            return struct.unpack_from('<d', d, o + 1)[0]
        if t == T_TRUE:
            return True
        if t == T_FALSE:
            return False
        if t == T_NULL:
            return None
        if T_RESOURCE < t <= T_RESOURCE + 4:
            index = int.from_bytes(d[o + 1 : o + 1 + t - T_RESOURCE], 'little')
            if index >= len(self.chunk_offsets):
                raise PSBError(f'resource index {index} out of range')
            return Resource(index)
        if T_EXTRA < t <= T_EXTRA + 4:
            index = int.from_bytes(d[o + 1 : o + 1 + t - T_EXTRA], 'little')
            if index >= len(self.extra_offsets):
                raise PSBError(f'extra resource index {index} out of range')
            return ExtraResource(index)
        if T_ARRAY < t <= T_ARRAY + 8:
            return IntArray(self.array(o)[0])
        raise PSBError(f'unknown value type {t:#04x} at {o:#x}')

    def chunks(self, offsets, lengths, base) -> list[bytes]:
        out = []
        for off, length in zip(offsets, lengths, strict=True):
            start = base + off
            if start + length > len(self.d):
                raise PSBError('a resource runs past the end of the file')
            out.append(bytes(self.d[start : start + length]))
        return out


_STRUCT_CODES = {2: 'H', 4: 'I', 8: 'Q'}


def decrypt(data: bytes, key: int | None = None) -> bytes:
    """Return *data* with its encryption removed and its flags cleared.

    The key is recovered or looked up as in :func:`find_key` if not given.
    """
    if key is None:
        key = find_key(data)
    if key is None:
        return bytes(data)
    out, _ = _decrypt(data, key)
    struct.pack_into('<H', out, 6, 0)
    return bytes(out)


def read(data: bytes, key: int | None = None, *, resources: bool = True) -> PSB:
    """Parse PSB *data* (decrypting it as needed) into a :class:`PSB`.

    With ``resources=False`` the chunks aren't copied out (the lists are empty).
    """
    if not is_psb(data):
        raise PSBError('not a PSB file')
    if key is None:
        key = find_key(data)
    plain: bytes | bytearray
    if key is None:
        plain = data
        h = _parse_header(data)
    else:
        plain, h = _decrypt(data, key)
    if not _header_plausible(h, len(data)):
        raise PSBError('the header is not valid')
    if h.checksum is not None and h.checksum != h.compute_checksum():
        logger.warning('PSB header checksum %#010x does not match (expected %#010x)', h.checksum, h.compute_checksum())
    r = _Reader(plain, h)
    root = r.value(h.root)
    psb = PSB(root=root, version=h.version, flags=h.flags, key=key)
    if resources:
        psb.resources = r.chunks(r.chunk_offsets, r.chunk_lengths, h.chunk_data)
        psb.extra_resources = r.chunks(r.extra_offsets, r.extra_lengths, h.extra_data)
    return psb


def read_file(path, key: int | None = None, *, resources: bool = True) -> PSB:
    with open(path, 'rb') as f:
        return read(f.read(), key, resources=resources)


# --- Writing ---------------------------------------------------------------

_DATA_ALIGN = 0x20
_EXTRA_ALIGN = 0x40


def _uwidth(n: int) -> int:
    """The number of bytes (at least 1) that hold the unsigned *n*."""
    return max(1, (n.bit_length() + 7) // 8)


def _swidth(n: int) -> int:
    """The number of bytes (at least 1) that hold the signed *n*."""
    return max(1, (n.bit_length() + 8) // 8) if n >= 0 else max(1, ((~n).bit_length() + 8) // 8)


def pack_array(items) -> bytes:
    """Encode integers as a packed array, with the narrowest count and element widths."""
    items = list(items)
    count = len(items)
    cw = _uwidth(count)
    ew = _uwidth(max(items, default=0))
    head = bytes([T_ARRAY + cw]) + count.to_bytes(cw, 'little') + bytes([T_ARRAY + ew])
    if ew == 1:
        return head + bytes(items)
    if ew in _STRUCT_CODES:
        return head + struct.pack(f'<{count}{_STRUCT_CODES[ew]}', *items)
    return head + b''.join(i.to_bytes(ew, 'little') for i in items)


def build_names(names) -> tuple[list[int], list[int], list[int]]:
    """Build the names trie for the sorted, distinct *names*: (base, check, leaves).

    It's a double array: node ``n``'s child for byte ``c`` is node
    ``base[n] + c``, and ``check`` holds each node's parent.  Every name ends
    with a NUL edge to a leaf, whose ``base`` is the name's index; ``leaves``
    maps an index to its leaf.  Nodes are placed depth first, children in byte
    order, each node taking the lowest base (from 1) for which its children's
    slots are all free.
    """
    trie: dict = {}
    for index, name in enumerate(names):
        node = trie
        for ch in name.encode('utf-8'):
            node = node.setdefault(ch, {})
        node[0] = index
    base = [0]
    check = [0]
    used = bytearray(1)
    used[0] = 1
    leaves = [0] * len(names)
    free_from = 1

    def grow(n):
        if n >= len(base):
            extra = n + 1 - len(base)
            base.extend([0] * extra)
            check.extend([0] * extra)
            used.extend(bytes(extra))

    if not names:
        return base, check, leaves
    stack = [(0, trie)]
    while stack:
        node_id, node = stack.pop()
        kids = sorted(node)
        # The base itself needn't be free, only its children's slots.
        b = max(1, free_from - kids[0])
        while True:
            grow(b + kids[-1])
            if not any(used[b + k] for k in kids):
                break
            b += 1
        base[node_id] = b
        for k in kids:
            used[b + k] = 1
            check[b + k] = node_id
        while free_from < len(used) and used[free_from]:
            free_from += 1
        # Depth first: the first child is placed next.
        for k in reversed(kids):
            if k == 0:
                base[b] = node[0]
                leaves[node[0]] = b
            else:
                stack.append((b + k, node[k]))
    return base, check, leaves


class _Writer:
    def __init__(self, psb: PSB):
        self.psb = psb
        names: set = set()
        strings: set = set()
        self._collect(psb.root, names, strings)
        self.names = sorted(names, key=lambda s: s.encode('utf-8'))
        self.strings = sorted(strings, key=lambda s: s.encode('utf-8'))
        self.name_index = {n: i for i, n in enumerate(self.names)}
        self.string_index = {s: i for i, s in enumerate(self.strings)}

    def _collect(self, v, names, strings):
        stack = [v]
        while stack:
            v = stack.pop()
            if isinstance(v, dict):
                for k, x in v.items():
                    if not isinstance(k, str):
                        raise TypeError(f'dictionary keys must be strings, not {type(k).__name__}')
                    names.add(k)
                    stack.append(x)
            elif isinstance(v, list) and not isinstance(v, IntArray):
                stack.extend(v)
            elif isinstance(v, str):
                strings.add(v)

    def value(self, v) -> bytes:
        if isinstance(v, dict):
            items = sorted(((self.name_index[k], x) for k, x in v.items()), key=lambda kv: kv[0])
            return bytes([T_DICT]) + pack_array(k for k, _ in items) + self._container([x for _, x in items])
        if isinstance(v, IntArray):
            return pack_array(v)
        if isinstance(v, (list, tuple)):
            return bytes([T_LIST]) + self._container(v)
        if v is None:
            return bytes([T_NULL])
        if v is True:
            return bytes([T_TRUE])
        if v is False:
            return bytes([T_FALSE])
        if isinstance(v, int):
            if v == 0:
                return bytes([T_INT])
            w = _swidth(v)
            if w > 8:
                raise OverflowError(f'{v} does not fit in 8 bytes')
            return bytes([T_INT + w]) + v.to_bytes(w, 'little', signed=True)
        if isinstance(v, Float32):
            raw = struct.pack('<f', v)
            return bytes([T_FLOAT0]) if raw == b'\0\0\0\0' else bytes([T_FLOAT]) + raw
        if isinstance(v, float):
            return bytes([T_DOUBLE]) + struct.pack('<d', v)
        if isinstance(v, str):
            i = self.string_index[v]
            w = _uwidth(i)
            return bytes([T_STRING + w]) + i.to_bytes(w, 'little')
        if isinstance(v, Resource):
            w = _uwidth(v.index)
            return bytes([T_RESOURCE + w]) + v.index.to_bytes(w, 'little')
        if isinstance(v, ExtraResource):
            w = _uwidth(v.index)
            return bytes([T_EXTRA + w]) + v.index.to_bytes(w, 'little')
        raise TypeError(f'cannot store a {type(v).__name__} in a PSB file')

    def _container(self, values) -> bytes:
        """The offsets array and the values of a list or dictionary; identical values are stored once."""
        offsets = []
        seen: dict[bytes, int] = {}
        body = bytearray()
        for x in values:
            enc = self.value(x)
            at = seen.get(enc)
            if at is None:
                at = seen[enc] = len(body)
                body += enc
            offsets.append(at)
        return pack_array(offsets) + bytes(body)


def _align(n: int, a: int = _DATA_ALIGN) -> int:
    return (n + a - 1) // a * a


def _chunk_table(chunks) -> tuple[bytes, bytes, bytes]:
    offsets, data = [], bytearray()
    for c in chunks:
        offsets.append(len(data))
        data += c
    return pack_array(offsets), pack_array(len(c) for c in chunks), bytes(data)


def write(psb: PSB) -> bytes:
    """Serialise *psb* to bytes, encrypting it with ``psb.key`` (if set) per ``psb.flags``."""
    if not isinstance(psb.root, dict):
        raise TypeError('the root of a PSB file must be a dictionary')
    version = psb.version
    if not 2 <= version <= 4:
        raise ValueError(f'unsupported PSB version {version}')
    if psb.extra_resources and version < 4:
        raise ValueError('extra resources need PSB version 4')
    w = _Writer(psb)
    hl = header_length(version)
    base, check, leaves = build_names(w.names)
    names = pack_array(base) + pack_array(check) + pack_array(leaves)
    tree = w.value(psb.root)
    string_data = bytearray()
    string_offsets = []
    for s in w.strings:
        string_offsets.append(len(string_data))
        string_data += s.encode('utf-8') + b'\0'

    out = bytearray(hl)
    h = Header(version, psb.flags, hl, 0, 0, 0, 0, 0, 0, 0)
    h.names = len(out)
    out += names
    h.root = len(out)
    out += tree
    h.strings = len(out)
    out += pack_array(string_offsets)
    h.strings_data = len(out)
    out += string_data
    if version >= 4:
        eo, el, ed = _chunk_table(psb.extra_resources)
        h.extra_offsets = len(out)
        out += eo
        h.extra_lengths = len(out)
        out += el
        if ed:
            out += bytes(_align(len(out), _EXTRA_ALIGN) - len(out))
        h.extra_data = len(out)
        out += ed
    co, cl, cd = _chunk_table(psb.resources)
    h.chunk_offsets = len(out)
    out += co
    h.chunk_lengths = len(out)
    out += cl
    out += bytes(_align(len(out)) - len(out))
    h.chunk_data = len(out)
    out += cd

    out[0:4] = MAGIC
    struct.pack_into('<HH', out, 4, version, psb.flags)
    struct.pack_into('<8I', out, 8, *h.words()[:8])
    if version >= 3:
        struct.pack_into('<I', out, 0x28, h.compute_checksum())
    if version >= 4:
        struct.pack_into('<3I', out, 0x2C, h.extra_offsets, h.extra_lengths, h.extra_data)

    if psb.key is not None:
        stream = Keystream(psb.key)
        if version >= 3 and psb.flags & FLAG_HEADER:
            out[8:hl] = stream.xor(bytes(out[8:hl]))
        if version < 3 or psb.flags & FLAG_BODY:
            out[h.names : h.chunk_offsets] = stream.xor(bytes(out[h.names : h.chunk_offsets]))
    return bytes(out)
