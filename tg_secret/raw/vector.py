import io
from io import BytesIO
from typing import Any, TypeVar, Callable

from tg_secret.raw.tl_object import SecretTLObject
from tg_secret.raw.primitives import read_int, read_long, write_int

PrimitiveT = TypeVar("PrimitiveT", bound=int | float | str | bytes | bool)
ReadT = TypeVar("ReadT", bound=int | float | str | bytes | bool | SecretTLObject)


class Vector(SecretTLObject):
    ID = 0x1CB5C415

    @staticmethod
    def read_bare(b: BytesIO, size: int) -> int | Any:
        if size == 4:
            return read_int(b)

        if size == 8:
            return read_long(b)

        return SecretTLObject.read(b)

    @classmethod
    def read(cls, data: BytesIO, read_func: Callable[[BytesIO], ReadT] | None = None, *args) -> list[ReadT]:
        count = read_int(data)
        left = len(data.read())
        size = (left / count) if count else 0
        data.seek(-left, io.SEEK_CUR)

        return [
            read_func(data) if read_func
            else Vector.read_bare(data, size)
            for _ in range(count)
        ]

    @classmethod
    def write_list(cls, value: list[SecretTLObject]) -> bytes:
        return b"".join([
            write_int(cls.ID, False),
            write_int(len(value)),
            *(i.write() for i in value)
        ])

    @classmethod
    def write_primitive_list(cls, value: list[PrimitiveT], write_func: Callable[[PrimitiveT], bytes]) -> bytes:
        return b"".join([
            write_int(cls.ID, False),
            write_int(len(value)),
            *(write_func(i) for i in value)
        ])
