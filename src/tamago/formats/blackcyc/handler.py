import logging
import sys

from tamago.formats.blackcyc.packfile import PackFile

logger = logging.getLogger(__name__)


def _fail(message):
    print(f"Error: {message}", file=sys.stderr)
    raise SystemExit(1)


class BlackCycHandler:
    """Format handler for Black Cyc packs (Black Cyc, Cyc No-nos, CYCLET).

    Either file of a pair (``.gtb``/``.gpk`` images, ``.vtb``/``.vpk`` voices)
    can be given; ``create`` writes both.
    """

    def add_extract_args(self, parser):
        pass

    def add_create_args(self, parser):
        pass

    def cmd_extract(self, args):
        try:
            with PackFile(args.input) as pack:
                pack.extract_all(args.output, glob=getattr(args, 'glob', None))
        except ValueError as e:
            _fail(e)

    def cmd_create(self, args):
        if getattr(args, 'compress', None):
            logger.warning("Black Cyc packs are never compressed: ignoring --compress")
        try:
            with PackFile(args.output, mode='w') as pack:
                pack.write_all(args.input, glob=getattr(args, 'glob', None))
        except ValueError as e:
            _fail(e)
