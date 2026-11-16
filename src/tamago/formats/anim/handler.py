import argparse
import logging
import os
import pathlib
import sys

from tamago.formats.anim.crypt import HEADER_SIZE, KEY_SIZE, decrypt, encrypt, is_encrypted
from tamago.formats.anim.pckfile import PCKFile

logger = logging.getLogger(__name__)


def _parse_key(text):
    try:
        key = bytes.fromhex(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a hexadecimal key: {text!r}") from None
    if len(key) != KEY_SIZE:
        raise argparse.ArgumentTypeError(f"the key must be {KEY_SIZE} bytes ({2 * KEY_SIZE} hex digits): {text!r}")
    return key


def _is_encrypted_file(path):
    with open(path, 'rb') as f:
        return is_encrypted(f.read(HEADER_SIZE))


def _plan(source, dest, select):
    """Map *source* (a file or a directory) to (input, output) path pairs under *dest*.

    For a directory, *select* picks the files to convert; files it rejects are
    skipped with a note at info level.
    """
    source, dest = pathlib.Path(source), pathlib.Path(dest)
    if not source.is_dir():
        return [(source, dest)]
    pairs = []
    for root, dirs, files in os.walk(source):
        dirs.sort()
        for name in sorted(files):
            path = pathlib.Path(root, name)
            if select(path):
                pairs.append((path, dest / path.relative_to(source)))
            else:
                logger.info('skipping %s', path)
    return pairs


def _convert(pairs, transform):
    for src, dst in pairs:
        data = transform(src, src.read_bytes())
        dst.parent.mkdir(parents=True, exist_ok=True)
        with open(dst, 'xb') as f:
            f.write(data)


class AnimHandler:
    """Format handler for ANIM's packs (``*_wave.pck``, ``psbpack.dat``) and enciphered files."""

    def add_extract_args(self, parser):
        parser.add_argument(
            '--no-convert-eog',
            dest='convert_eog',
            action='store_false',
            help='keep EOG audio as stored instead of unwrapping it to Ogg',
        )

    def add_create_args(self, parser):
        parser.add_argument(
            '--no-wrap-ogg',
            dest='wrap_ogg',
            action='store_false',
            help='store .ogg files as they are instead of wrapping them as .eog',
        )

    def add_commands(self, subparsers):
        """Add ``decrypt`` and ``encrypt`` for the engine's single enciphered files."""
        dec = subparsers.add_parser(
            'decrypt',
            help='Decrypt enciphered files (*_sce.dat, *_define.dat, cg/*.gax)',
            description='Decrypt a file, or every enciphered file under a directory (keeping their names).',
        )
        dec.add_argument('input', type=pathlib.Path, help='Enciphered file or directory')
        dec.add_argument('output', type=pathlib.Path, help='Output file or directory')
        dec.set_defaults(func=self.cmd_decrypt)

        enc = subparsers.add_parser(
            'encrypt',
            help='Encipher files as the engine reads them',
            description='Encipher a file, or every file under a directory (keeping their names).',
        )
        enc.add_argument('input', type=pathlib.Path, help='Plaintext file or directory')
        enc.add_argument('output', type=pathlib.Path, help='Output file or directory')
        enc.add_argument(
            '--key',
            type=_parse_key,
            default=bytes(KEY_SIZE),
            help=f'initial key, {2 * KEY_SIZE} hex digits (default: zeros; the engine accepts any key)',
        )
        enc.set_defaults(func=self.cmd_encrypt)

    def cmd_extract(self, args):
        try:
            with PCKFile(args.input) as pck:
                pck.extract_all(
                    args.output, glob=getattr(args, 'glob', None), convert_eog=getattr(args, 'convert_eog', True)
                )
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            raise SystemExit(1) from None

    def cmd_create(self, args):
        try:
            with PCKFile(args.output, mode='w') as pck:
                pck.write_all(args.input, glob=getattr(args, 'glob', None), wrap_ogg=getattr(args, 'wrap_ogg', True))
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            raise SystemExit(1) from None

    def cmd_decrypt(self, args):
        if not args.input.is_dir() and not _is_encrypted_file(args.input):
            print(f"Error: {args.input} is not enciphered (expected a 00 00 00 01 header)", file=sys.stderr)
            raise SystemExit(1)
        _convert(_plan(args.input, args.output, _is_encrypted_file), lambda _path, data: decrypt(data))

    def cmd_encrypt(self, args):
        if not args.input.is_dir() and _is_encrypted_file(args.input):
            print(f"Error: {args.input} is already enciphered", file=sys.stderr)
            raise SystemExit(1)

        def select(path):
            if _is_encrypted_file(path):
                logger.warning('%s is already enciphered; skipping it', path)
                return False
            return True

        _convert(_plan(args.input, args.output, select), lambda _path, data: encrypt(data, args.key))
