import sys

from tamago.formats.dxa.dxafile import DXAFile


class DXAHandler:
    """Format handler for DxLib DXA archives."""

    def add_extract_args(self, parser):
        parser.add_argument(
            '--password', help='archive password (default: recovered from the archive, so rarely needed)'
        )

    def add_create_args(self, parser):
        parser.add_argument('--password', default='', help="password to encrypt with (default: DxLib's default key)")

    def cmd_extract(self, args):
        try:
            with DXAFile(args.input, password=getattr(args, 'password', None)) as dxa:
                if dxa.password is None:
                    print(
                        f"Note: {args.input} uses a key that no password produces; it cannot be recreated as is",
                        file=sys.stderr,
                    )
                elif dxa.password:
                    print(
                        f"Note: {args.input} uses password {dxa.password!r} (pass --password to recreate it)",
                        file=sys.stderr,
                    )
                dxa.extract_all(args.output, glob=getattr(args, 'glob', None))
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            raise SystemExit(1) from None

    def cmd_create(self, args):
        compress = bool(getattr(args, 'compress', None))
        try:
            with DXAFile(args.output, mode='w', password=getattr(args, 'password', ''), compress=compress) as dxa:
                dxa.write_all(args.input, glob=getattr(args, 'glob', None))
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            raise SystemExit(1) from None
