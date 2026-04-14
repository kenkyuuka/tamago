import abc


class XP3Encryption(abc.ABC):
    """Abstract base class for XP3 encryption handlers."""

    @abc.abstractmethod
    def decrypt(self, data, info, segment):
        """Decrypt a segment's data.

        Args:
            data: Raw bytes read from the archive segment.
            info: Container with file metadata (flags, key, file_name, etc.).
            segment: Container with segment metadata (flags, offset, sizes).

        Returns:
            Decrypted bytes.
        """
        ...

    @abc.abstractmethod
    def encrypt(self, data, info, segment):
        """Encrypt a segment's data.

        Args:
            data: Plain bytes to be written to the archive segment.
            info: Container with file metadata (flags, key, file_name, etc.).
            segment: Container with segment metadata (flags, offset, sizes).

        Returns:
            Encrypted bytes.
        """
        ...
