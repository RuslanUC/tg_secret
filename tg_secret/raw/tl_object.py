from __future__ import annotations

from io import BytesIO
from typing import cast

from pyrogram.raw.core import TLObject


class SecretTLObject(TLObject):
    @classmethod
    def read(cls, b: BytesIO, *args) -> SecretTLObject:
        from tg_secret.raw.all import objects
        return cast(SecretTLObject, objects[int.from_bytes(b.read(4), "little")]).read(b, *args)

    def write(self) -> bytes:
        pass