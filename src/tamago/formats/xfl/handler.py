from tamago.formats.xfl.xflfile import XFLFile


class XFLHandler:
    """Format handler for Liar-soft / RScript XFL archives."""

    def add_extract_args(self, parser):
        pass

    def add_create_args(self, parser):
        pass

    def cmd_extract(self, args):
        with XFLFile(args.input) as xfl:
            xfl.extract_all(args.output, glob=getattr(args, 'glob', None))

    def cmd_create(self, args):
        with XFLFile(args.output, mode='w') as xfl:
            xfl.write_all(args.input, glob=getattr(args, 'glob', None))
