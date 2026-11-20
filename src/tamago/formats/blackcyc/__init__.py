import logging

from tamago.formats.blackcyc.packfile import (
    DATA_EXTENSIONS,
    IMAGE,
    INDEX_EXTENSIONS,
    MEMBER_EXTENSIONS,
    VOICE,
    PackFile,
    PackInfo,
    is_blackcyc_pack,
    pack_kind,
    pack_paths,
)

# Configure library logger with a NullHandler (let the application control output).
logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    'DATA_EXTENSIONS',
    'IMAGE',
    'INDEX_EXTENSIONS',
    'MEMBER_EXTENSIONS',
    'VOICE',
    'PackFile',
    'PackInfo',
    'is_blackcyc_pack',
    'pack_kind',
    'pack_paths',
]
