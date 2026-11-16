import argparse
import logging
import os
import pathlib
import sys
from collections.abc import Callable

from tamago.formats.yuris.ycg import is_ycg, png_to_ycg, ycg_to_png
from tamago.formats.yuris.ypf import (
    DEFAULT_KEY,
    DEFAULT_LENGTH_TABLE,
    DEFAULT_VERSION,
    LENGTH_TABLES,
    YPFFile,
    archive_params,
)
from tamago.formats.yuris.ystb import DEFAULT_SCRIPT_KEY, decrypt_ystb, encrypt_ystb, guess_ystb_key, is_ystb

logger = logging.getLogger(__name__)

_PNG_MAGIC = b'\x89PNG\r\n\x1a\n'


def _hex_int(bits):
    def parse(text):
        try:
            value = int(text, 16)
        except ValueError:
            raise argparse.ArgumentTypeError(f"not a hexadecimal value: {text!r}") from None
        if not 0 <= value < 1 << bits:
            raise argparse.ArgumentTypeError(f"must fit in {bits} bits: {text!r}")
        return value

    return parse


def _version(text):
    try:
        value = int(text, 0)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a version number: {text!r}") from None
    if not 0 < value <= 0xFFFFFFFF:
        raise argparse.ArgumentTypeError(f"version out of range: {text!r}")
    return value


def _fail(message):
    print(f"Error: {message}", file=sys.stderr)
    raise SystemExit(1)


def _files(source: pathlib.Path) -> list[pathlib.Path]:
    if not source.is_dir():
        return [source]
    found: list[pathlib.Path] = []
    for root, dirs, files in os.walk(source):
        dirs.sort()
        found.extend(pathlib.Path(root, name) for name in sorted(files))
    return found


def _convert_tree(
    source: pathlib.Path,
    dest: pathlib.Path,
    select: Callable[[bytes], bool],
    transform: Callable[[bytes], bytes],
    what: str,
):
    """Apply *transform* to *source* (a file or directory tree) into *dest*.

    A single file must be one *select* accepts.  In a directory, files it
    rejects are copied unchanged, so the result can be packed again as a whole.
    """
    if not source.is_dir():
        data = source.read_bytes()
        if not select(data):
            _fail(f"{source} is not a {what}")
        try:
            data = transform(data)
        except ValueError as e:
            _fail(f"{source}: {e}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, 'xb') as f:
            f.write(data)
        return
    for path in _files(source):
        target = dest / path.relative_to(source)
        data = path.read_bytes()
        if select(data):
            try:
                data = transform(data)
            except ValueError as e:
                _fail(f"{path}: {e}")
        else:
            logger.info('copying %s unchanged', path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, 'xb') as f:
            f.write(data)


class YurisHandler:
    """Format handler for YU-RIS: YPF archives, YSTB scripts and YCG images."""

    def add_extract_args(self, parser):
        parser.add_argument(
            '--convert-ycg',
            action='store_true',
            help='write YCG images (stored under .png names) as real PNG files',
        )

    def add_create_args(self, parser):
        parser.add_argument(
            '--like',
            type=pathlib.Path,
            metavar='ARCHIVE',
            help="copy the version, name key and length table from an archive of the target game",
        )
        parser.add_argument(
            '--version',
            type=_version,
            dest='ypf_version',
            help=f'engine version, e.g. 494 or 0x1EE (default: {DEFAULT_VERSION})',
        )
        parser.add_argument(
            '--name-key',
            type=_hex_int(8),
            help=f'hex byte XOR\'d into member names (default: {DEFAULT_KEY:02x})',
        )
        parser.add_argument(
            '--length-table',
            choices=sorted(LENGTH_TABLES),
            help=f'name-length swap table (default: {DEFAULT_LENGTH_TABLE})',
        )
        parser.add_argument(
            '--encode-ycg',
            action='store_true',
            help='convert PNG files to YCG, for games that store their images as YCG',
        )

    def add_commands(self, subparsers):
        """Add ``decrypt``/``encrypt`` for YSTB scripts and ``decode-ycg``/``encode-ycg`` for YCG images."""
        dec = subparsers.add_parser(
            'decrypt',
            help='Decrypt YSTB scripts (ysbin/yst*.ybn)',
            description='Decrypt a script, or every script under a directory (other files are copied unchanged). '
            'Without --key, the key is recovered from the scripts themselves.',
        )
        dec.add_argument('input', type=pathlib.Path, help='Script file or directory')
        dec.add_argument('output', type=pathlib.Path, help='Output file or directory')
        dec.add_argument('--key', type=_hex_int(32), help='32-bit script key in hex (default: guess)')
        dec.set_defaults(func=self.cmd_decrypt)

        enc = subparsers.add_parser(
            'encrypt',
            help='Encrypt YSTB scripts',
            description='Encrypt a script, or every script under a directory (other files are copied unchanged).',
        )
        enc.add_argument('input', type=pathlib.Path, help='Script file or directory')
        enc.add_argument('output', type=pathlib.Path, help='Output file or directory')
        enc.add_argument(
            '--key',
            type=_hex_int(32),
            default=DEFAULT_SCRIPT_KEY,
            help=f'32-bit script key in hex (default: {DEFAULT_SCRIPT_KEY:08x}, the engine default)',
        )
        enc.set_defaults(func=self.cmd_encrypt)

        to_png = subparsers.add_parser(
            'decode-ycg',
            help='Convert YCG images to PNG',
            description='Convert a YCG image, or every YCG under a directory, to PNG keeping their names '
            '(other files are copied unchanged).',
        )
        to_png.add_argument('input', type=pathlib.Path, help='YCG file or directory')
        to_png.add_argument('output', type=pathlib.Path, help='Output file or directory')
        to_png.set_defaults(func=self.cmd_decode_ycg)

        to_ycg = subparsers.add_parser(
            'encode-ycg',
            help='Convert PNG images to YCG',
            description='Convert a PNG image, or every PNG under a directory, to YCG keeping their names '
            '(other files are copied unchanged).',
        )
        to_ycg.add_argument('input', type=pathlib.Path, help='PNG file or directory')
        to_ycg.add_argument('output', type=pathlib.Path, help='Output file or directory')
        to_ycg.set_defaults(func=self.cmd_encode_ycg)

    def cmd_extract(self, args):
        try:
            with YPFFile(args.input) as ypf:
                ypf.extract_all(
                    args.output, glob=getattr(args, 'glob', None), convert_ycg=getattr(args, 'convert_ycg', False)
                )
        except ValueError as e:
            _fail(e)

    def _create_params(self, args) -> dict:
        params = {'version': DEFAULT_VERSION, 'key': DEFAULT_KEY, 'length_table': DEFAULT_LENGTH_TABLE}
        like = getattr(args, 'like', None)
        if like is not None:
            try:
                found = archive_params(like)
            except (OSError, ValueError) as e:
                _fail(f"cannot read --like archive: {e}")
            params['version'] = found['version']
            if found['key'] is not None:
                params['key'] = found['key']
            if found['length_table'] is None and getattr(args, 'length_table', None) is None:
                _fail(f"the member names of {like} fit no known length table; choose one with --length-table")
            params['length_table'] = found['length_table'] or DEFAULT_LENGTH_TABLE
        for param, attr in (('version', 'ypf_version'), ('key', 'name_key'), ('length_table', 'length_table')):
            value = getattr(args, attr, None)
            if value is not None:
                params[param] = value
        return params

    def cmd_create(self, args):
        params = self._create_params(args)
        logger.info('creating version %d archive, name key %#04x, length table %s', *params.values())
        try:
            with YPFFile(
                args.output,
                mode='w',
                compress=getattr(args, 'compress', None),
                encode_ycg=getattr(args, 'encode_ycg', False),
                **params,
            ) as ypf:
                ypf.write_all(args.input, glob=getattr(args, 'glob', None))
        except ValueError as e:
            _fail(e)

    def cmd_decrypt(self, args):
        key = args.key
        if key is None:
            scripts = [data for data in (p.read_bytes() for p in _files(args.input)) if is_ystb(data)]
            if not scripts:
                _fail(
                    f"{args.input} is not a YSTB script"
                    if not args.input.is_dir()
                    else f"no YSTB scripts in {args.input}"
                )
            try:
                key = guess_ystb_key(scripts)
            except ValueError as e:
                _fail(e)
            count = len(scripts)
            print(f"Using script key {key:08x} (recovered from {count} scripts)", file=sys.stderr)
        _convert_tree(args.input, args.output, is_ystb, lambda data: decrypt_ystb(data, key), 'YSTB script')

    def cmd_encrypt(self, args):
        _convert_tree(args.input, args.output, is_ystb, lambda data: encrypt_ystb(data, args.key), 'YSTB script')

    def cmd_decode_ycg(self, args):
        _convert_tree(args.input, args.output, is_ycg, ycg_to_png, 'YCG image')

    def cmd_encode_ycg(self, args):
        _convert_tree(args.input, args.output, lambda d: d.startswith(_PNG_MAGIC), png_to_ycg, 'PNG image')
