from io import BytesIO
from struct import pack, unpack
from typing import cast

from tg_secret.raw.tl_object import SecretTLObject


def write_intX(value: int, size: int, signed: bool = True) -> bytes:
    return value.to_bytes(size, "little", signed=signed)


def write_int(value: int, signed: bool = True) -> bytes:
    return write_intX(value, 4, signed)


def write_long(value: int) -> bytes:
    return write_intX(value, 8)


def write_int128(value: int) -> bytes:
    return write_intX(value, 16)


def write_int256(value: int) -> bytes:
    return write_intX(value, 32)


def write_double(value: float) -> bytes:
    return pack("d", value)


def write_bytes(value: bytes) -> bytes:
    length = len(value)

    if length <= 253:
        result = bytes([length])
    else:
        result = bytes([254]) + length.to_bytes(3, "little")

    result += value
    padding = -len(result) % 4
    if padding:
        result += b"\x00" * padding

    return result


def write_string(value: str) -> bytes:
    return write_bytes(value.encode("utf8"))


def write_bool(value: bool) -> bytes:
    return write_int(BoolTrue.ID if value else BoolFalse.ID)


def read_intX(value: bytes | BytesIO, size: int, signed: bool = True) -> int:
    value = value.read(size) if isinstance(value, BytesIO) else value[:size]
    return int.from_bytes(value, "little", signed=signed)


def read_int(value: bytes | BytesIO, signed: bool = True) -> int:
    return read_intX(value, 4, signed)


def read_long(value: bytes | BytesIO) -> int:
    return read_intX(value, 8)


def read_int128(value: bytes | BytesIO) -> int:
    return read_intX(value, 16)


def read_int256(value: bytes | BytesIO) -> int:
    return read_intX(value, 32)


def read_double(value: bytes | BytesIO) -> float:
    value = value.read(8) if isinstance(value, BytesIO) else value[:8]
    return cast(float, unpack("d", value)[0])


def read_bytes(value: BytesIO) -> bytes:
    length = value.read(1)[0]
    length_size = 1

    if length > 253:
        length_size = 0
        length = int.from_bytes(value.read(3), "little")

    result = value.read(length)

    padding = -(len(result) + length_size) % 4
    if padding:
        value.read(padding)

    return result


def read_string(value: BytesIO) -> str:
    return read_bytes(value).decode("utf8")


def read_bool(value: bytes | BytesIO) -> bool:
    return read_int(value) == BoolTrue.ID


class BoolFalse(SecretTLObject):
    ID = 0xBC799737
    value = False

    @classmethod
    def read(cls, *args: ...) -> bool:
        return cls.value


class BoolTrue(BoolFalse):
    ID = 0x997275B5
    value = True
