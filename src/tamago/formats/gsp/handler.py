from tamago.formats.gsp.gspfile import GSPFile


class GSPHandler:
    """Format handler for GSP archives."""

    def add_extract_args(self, parser):
        pass

    def add_create_args(self, parser):
        pass

    def cmd_extract(self, args):
        with GSPFile(args.input) as gsp:
            gsp.extract_all(args.output, glob=getattr(args, 'glob', None))

    def cmd_create(self, args):
        with GSPFile(args.output, mode='w') as gsp:
            gsp.write_all(args.input, glob=getattr(args, 'glob', None) or '*')
