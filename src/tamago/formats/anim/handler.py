import sys

from tamago.formats.anim.pckfile import PCKFile


class AnimHandler:
    """Format handler for ANIM's packs (``*_wave.pck``, ``psbpack.dat``)."""

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
