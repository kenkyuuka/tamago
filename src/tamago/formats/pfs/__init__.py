import logging

from tamago.formats.pfs.pfsfile import MANIFEST_NAME, VERSIONS, PFSFile, PFSInfo, is_pfs, xor_key

# Configure library logger with a NullHandler (let the application control output).
logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    'MANIFEST_NAME',
    'VERSIONS',
    'PFSFile',
    'PFSInfo',
    'is_pfs',
    'xor_key',
]
