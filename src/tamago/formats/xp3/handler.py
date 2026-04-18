import argparse

from tamago.formats.xp3.detect import auto_detect
from tamago.formats.xp3.encryption import get_encryption_schemes
from tamago.formats.xp3.xp3file import XP3File


def _resolve_encryption(args):
    """Resolve the encryption scheme from CLI arguments."""
    encryption = getattr(args, 'encryption', None)
    if not encryption:
        return None
    schemes = get_encryption_schemes()
    if encryption not in schemes:
        available = ', '.join(sorted(schemes))
        raise argparse.ArgumentTypeError(f"Unknown encryption scheme {encryption!r}. Available: {available}")
    cls = schemes[encryption].load()
    kwargs = {}
    key = getattr(args, 'key', None)
    if key is not None:
        kwargs['shift'] = key
    try:
        return cls(**kwargs)
    except TypeError as e:
        raise argparse.ArgumentTypeError(f"Failed to instantiate {encryption!r}: {e}")


class XP3Handler:
    """Format handler for XP3 archives (KiriKiri engine)."""

    def add_extract_args(self, parser):
        parser.add_argument('--encryption', metavar='SCHEME', help='encryption scheme name (e.g. hash-xor)')
        parser.add_argument('--key', metavar='KEY', type=int, help='encryption key (scheme-specific)')
        parser.add_argument('--no-auto-detect', action='store_true', help='disable automatic encryption detection')
        parser.add_argument(
            '--force-detect', action='store_true', help='force encryption probing even if no encrypted flag is set'
        )
        parser.add_argument(
            '--force-encrypt',
            action='store_true',
            help='decrypt all files regardless of per-file encrypted flag (for games with wrong flags)',
        )
        parser.add_argument(
            '--convert-tlg',
            action='store_true',
            help='convert TLG images to PNG during extraction (requires Pillow)',
        )
        parser.add_argument(
            '--no-decode-text',
            dest='decode_text',
            action='store_false',
            help='keep simple-crypt obfuscation on extracted text files (FE FE 01 ...)',
        )

    def add_create_args(self, parser):
        parser.add_argument('--encryption', metavar='SCHEME', help='encryption scheme name (e.g. hash-xor)')
        parser.add_argument('--key', metavar='KEY', type=int, help='encryption key (scheme-specific)')

    def cmd_extract(self, args):
        try:
            encryption = _resolve_encryption(args)
        except argparse.ArgumentTypeError as e:
            print(f"Error: {e}", file=__import__('sys').stderr)
            raise SystemExit(1)
        if encryption is None and not getattr(args, 'no_auto_detect', False):
            encryption = auto_detect(args.input, force_probe=getattr(args, 'force_detect', False))
        f = XP3File(args.input, encryption=encryption, force_encrypt=getattr(args, 'force_encrypt', False))
        f.extract_all(
            args.output,
            glob=getattr(args, 'glob', None),
            convert_tlg=getattr(args, 'convert_tlg', False),
            decode_text=getattr(args, 'decode_text', True),
        )

    def cmd_create(self, args):
        try:
            encryption = _resolve_encryption(args)
        except argparse.ArgumentTypeError as e:
            print(f"Error: {e}", file=__import__('sys').stderr)
            raise SystemExit(1)
        compressed = getattr(args, 'compress', None)
        if compressed is None:
            compressed = True
        f = XP3File(args.output, 'x', encryption=encryption)
        f.write_all(args.input, glob=getattr(args, 'glob', None) or '*', compressed=compressed)
