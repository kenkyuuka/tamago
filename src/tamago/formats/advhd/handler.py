from tamago.formats.advhd.arcfile import ARCFile


class ARCHandler:
    """Format handler for AdvHD ARC archives."""

    def add_extract_args(self, parser):
        pass

    def add_create_args(self, parser):
        pass

    def cmd_extract(self, args):
        with ARCFile(args.input) as arc:
            arc.extract_all(args.output, glob=getattr(args, 'glob', None))

    def cmd_create(self, args):
        with ARCFile(args.output, mode='w') as arc:
            arc.write_all(args.input, glob=getattr(args, 'glob', None) or '*')
