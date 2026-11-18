import argparse
import json
import logging
import pathlib
import sys

from tamago.formats.psb import jsontree, textures
from tamago.formats.psb.psbfile import PSB, PSBError, decrypt, read_file, write

logger = logging.getLogger(__name__)

TREE_FILE = 'psb.json'
RESOURCE_DIR = 'resources'
EXTRA_DIR = 'extra'
TEXTURE_DIR = 'textures'


def _parse_key(text):
    try:
        key = int(text, 0)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a key: {text!r}") from None
    if not 0 <= key <= 0xFFFFFFFF:
        raise argparse.ArgumentTypeError(f"the key must fit in 32 bits: {text!r}")
    return key


def _texture_file_name(name):
    return name.replace('/', '_').replace('\\', '_').replace('#', '_') + '.png'


def extract(path, out_dir, *, key=None, convert_textures=True):
    """Decompile the PSB at *path* into *out_dir*: ``psb.json``, the resource chunks, and the texture atlases."""
    psb = read_file(path, key)
    out_dir = pathlib.Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    doc = {
        'version': psb.version,
        'flags': psb.flags,
        'key': None if psb.key is None else f'{psb.key:#010x}',
        'resources': len(psb.resources),
        'extra_resources': len(psb.extra_resources),
        'root': jsontree.to_json(psb.root),
    }
    with open(out_dir / TREE_FILE, 'w', encoding='utf-8') as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
    for sub, chunks in ((RESOURCE_DIR, psb.resources), (EXTRA_DIR, psb.extra_resources)):
        if chunks:
            (out_dir / sub).mkdir(exist_ok=True)
        for i, data in enumerate(chunks):
            (out_dir / sub / f'{i}.bin').write_bytes(data)
    if convert_textures:
        for name, texture in textures.iter_textures(psb.root):
            try:
                im = textures.texture_image(texture, psb.resources)
            except (ValueError, KeyError, IndexError) as e:
                logger.warning('texture %s not converted: %s', name, e)
                continue
            (out_dir / TEXTURE_DIR).mkdir(exist_ok=True)
            im.save(out_dir / TEXTURE_DIR / _texture_file_name(name))
    return psb


def create(in_dir, path, *, key=None, encrypt=True):
    """Compile a directory made by :func:`extract` back into a PSB at *path*.

    The file is encrypted as the original was, with *key* in place of the
    recorded key if given; ``encrypt=False`` writes it plain.
    """
    in_dir = pathlib.Path(in_dir)
    with open(in_dir / TREE_FILE, encoding='utf-8') as f:
        doc = json.load(f)
    chunks = {}
    for sub, field in ((RESOURCE_DIR, 'resources'), (EXTRA_DIR, 'extra_resources')):
        chunks[field] = [(in_dir / sub / f'{i}.bin').read_bytes() for i in range(int(doc.get(field, 0)))]
    recorded = doc.get('key')
    if not encrypt:
        file_key, flags = None, 0
    else:
        file_key = key if key is not None else (None if recorded is None else int(recorded, 0))
        flags = int(doc.get('flags', 0))
    psb = PSB(
        root=jsontree.from_json(doc['root']),
        resources=chunks['resources'],
        extra_resources=chunks['extra_resources'],
        version=int(doc.get('version', 3)),
        flags=flags,
        key=file_key,
    )
    data = write(psb)
    pathlib.Path(path).write_bytes(data)
    return psb


class PSBHandler:
    """Format handler for E-mote's PSB files: decompiles them to JSON and resources, and back."""

    def add_extract_args(self, parser):
        parser.add_argument('--key', type=_parse_key, help='decryption key, if it cannot be found (e.g. 0x473ab96d)')
        parser.add_argument(
            '--no-textures',
            dest='convert_textures',
            action='store_false',
            help='do not write the texture atlases as PNG',
        )

    def add_create_args(self, parser):
        parser.add_argument('--key', type=_parse_key, help='encryption key, in place of the one recorded in psb.json')
        parser.add_argument('--no-encrypt', dest='encrypt', action='store_false', help='write the file unencrypted')

    def add_commands(self, subparsers):
        dec = subparsers.add_parser(
            'decrypt',
            help='Write a PSB file without its encryption',
            description='Remove the encryption from a PSB file, for tools that read only plain files.',
        )
        dec.add_argument('input', type=pathlib.Path, help='PSB file')
        dec.add_argument('output', type=pathlib.Path, help='Output PSB file')
        dec.add_argument('--key', type=_parse_key, help='decryption key, if it cannot be found')
        dec.set_defaults(func=self.cmd_decrypt)

        info = subparsers.add_parser('info', help='Describe a PSB file')
        info.add_argument('input', type=pathlib.Path, help='PSB file')
        info.add_argument('--key', type=_parse_key, help='decryption key, if it cannot be found')
        info.set_defaults(func=self.cmd_info)

    def cmd_extract(self, args):
        try:
            extract(
                args.input,
                args.output,
                key=getattr(args, 'key', None),
                convert_textures=getattr(args, 'convert_textures', True),
            )
        except (PSBError, OSError) as e:
            print(f"Error: {e}", file=sys.stderr)
            raise SystemExit(1) from None

    def cmd_create(self, args):
        try:
            create(args.input, args.output, key=getattr(args, 'key', None), encrypt=getattr(args, 'encrypt', True))
        except (OSError, ValueError, TypeError, KeyError) as e:
            print(f"Error: {e}", file=sys.stderr)
            raise SystemExit(1) from None

    def cmd_decrypt(self, args):
        try:
            data = decrypt(args.input.read_bytes(), args.key)
        except (PSBError, OSError) as e:
            print(f"Error: {e}", file=sys.stderr)
            raise SystemExit(1) from None
        args.output.write_bytes(data)

    def cmd_info(self, args):
        try:
            psb = read_file(args.input, args.key)
        except (PSBError, OSError) as e:
            print(f"Error: {e}", file=sys.stderr)
            raise SystemExit(1) from None
        print(f"version:   {psb.version}")
        print(f"encrypted: {'no' if psb.key is None else f'yes, key {psb.key:#010x} (flags {psb.flags})'}")
        print(
            f"resources: {len(psb.resources)}"
            + (f" (+{len(psb.extra_resources)} extra)" if psb.extra_resources else '')
        )
        for k in ('spec', 'id', 'version'):
            if k in psb.root:
                print(f"{k + ':':<10} {json.dumps(jsontree.to_json(psb.root[k]), ensure_ascii=False)}")
        for name, texture in textures.iter_textures(psb.root):
            print(
                f"texture {name}: {texture.get('type')} {texture.get('width')}x{texture.get('height')}"
                f" (used {texture.get('truncated_width')}x{texture.get('truncated_height')})"
            )
