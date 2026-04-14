import logging

from tamago.formats.gsp.gspfile import GSPFile, GSPInfo
from tamago.formats.gsp.spt_crypto import decrypt as decrypt_spt
from tamago.formats.gsp.spt_crypto import encrypt as encrypt_spt
from tamago.formats.gsp.spt_crypto import is_encrypted as is_spt_encrypted

# Configure library logger with a NullHandler (let the application control output).
logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    'GSPFile',
    'GSPInfo',
    'decrypt_spt',
    'encrypt_spt',
    'is_spt_encrypted',
]
