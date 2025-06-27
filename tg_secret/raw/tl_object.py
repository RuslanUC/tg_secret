from __future__ import annotations

from io import BytesIO
from json import dumps
from typing import cast, Any


class SecretTLObject:
    __slots__: tuple[str] = ()

    QUALNAME = "Base"

    @classmethod
    def read(cls, b: BytesIO, *args) -> SecretTLObject:
        from tg_secret.raw.all import objects
        return cast(SecretTLObject, objects[int.from_bytes(b.read(4), "little")]).read(b, *args)

    def write(self) -> bytes:
        pass

    @staticmethod
    def default(obj: SecretTLObject) -> str | dict[str, str]:
        if isinstance(obj, bytes):
            return repr(obj)

        return {
            "_": obj.QUALNAME,
            **{
                attr: getattr(obj, attr)
                for attr in obj.__slots__
                if getattr(obj, attr) is not None
            }
        }

    def __str__(self) -> str:
        return dumps(self, indent=4, default=self.default, ensure_ascii=False)

    def __repr__(self) -> str:
        if not hasattr(self, "QUALNAME"):
            return repr(self)

        fields = ", ".join(
            f"{attr}={getattr(self, attr)!r}"
            for attr in self.__slots__
            if getattr(self, attr) is not None
        )

        return f"tg_secret.raw.types.{self.QUALNAME}({fields})"

    def __eq__(self, other: Any) -> bool:
        for attr in self.__slots__:
            try:
                if getattr(self, attr) != getattr(other, attr):
                    return False
            except AttributeError:
                return False

        return True

    def __len__(self) -> int:
        return len(self.write())
