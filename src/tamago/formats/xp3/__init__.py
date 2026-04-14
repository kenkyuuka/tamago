import logging

from .detect import auto_detect
from .encryption import XP3Encryption
from .models import XP3Info
from .xp3file import XP3File

# Configure library logger with a NullHandler (let the application control output).
logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    'XP3Encryption',
    'XP3File',
    'XP3Info',
    'auto_detect',
]
