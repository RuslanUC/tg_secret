import io
from io import RawIOBase
from typing import BinaryIO

from tg_secret.aes import ige256_encrypt, ige256_decrypt


class EncryptedFileWrapper(RawIOBase, BinaryIO):
    name = "encrypted_file.bin"

    def __init__(self, file: BinaryIO, key: bytes, iv: bytes, encrypt: bool) -> None:
        self._file = file
        self.key = key
        self.iv = iv
        self.encrypt = encrypt

    def readable(self) -> bool:
        return self.encrypt

    def writable(self) -> bool:
        return not self.encrypt

    def seekable(self) -> bool:
        return True

    def read(self, size: int = -1, /) -> bytes:
        if (size % 16) != 0:
            raise ValueError("Invalid read size: must be divisible by 16")
        if not self.encrypt:
            raise ValueError(f"{self.__class__.__name__} in decrypt mode does not support reading")
        if size == 0:
            return b""

        data = self._file.read(size)
        data_size = len(data)

        if data_size == 0:
            return b""
        if (data_size % 16) != 0:
            data += b"\x00" * (-data_size % 16)

        result = ige256_encrypt(data, self.key, self.iv)
        self.iv = result[-16:] + data[-16:]

        return result

    def write(self, data: bytes, /) -> int:
        if (len(data) % 16) != 0:
            raise ValueError("Invalid data size: must be divisible by 16")
        if self.encrypt:
            raise ValueError(f"{self.__class__.__name__} in encrypt mode does not support writing")
        if len(data) == 0:
            return 0

        result = ige256_decrypt(data, self.key, self.iv)
        self.iv = data[-16:] + result[-16:]

        return self._file.write(result)

    def seek(self, offset: int, whence: int = io.SEEK_SET, /) -> int:
        return self._file.seek(offset, whence)

    def tell(self) -> int:
        return self._file.tell()
