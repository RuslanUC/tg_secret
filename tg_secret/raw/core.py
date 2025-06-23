from __future__ import annotations
from io import BytesIO

from pyrogram.raw.core import Int, Long


class SecretMessageDecrypted:
    def __init__(
            self, length: int, payload_type: int, random_bytes: bytes, layer: int, in_seq_no: int, out_seq_no: int,
            message_type: int, message_bytes: bytes, padding: bytes,
    ) -> None:
        self.length = length
        self.payload_type = payload_type
        self.random_bytes = random_bytes
        self.layer = layer
        self.in_seq_no = in_seq_no
        self.out_seq_no = out_seq_no
        self.message_type = message_type
        self.message_bytes = message_bytes
        self.padding = padding

    @classmethod
    def read(cls, buf: BytesIO) -> SecretMessage:
        length = Int.read(buf)
        payload_type = Int.read(buf)
        random_bytes = ...
        layer = Int.read(buf)
        in_seq_no = Int.read(buf)
        out_seq_no = Int.read(buf)
        message_type = Int.read(buf)
        message_bytes = ...
        padding = ...

        return SecretMessage(
            length, payload_type, random_bytes, layer, in_seq_no, out_seq_no, message_type, message_bytes, padding
        )

class SecretMessage:
    def __init__(self, fingerprint: int, msg_key: bytes, encrypted: bytes) -> None:
        self.fingerprint = fingerprint
        self.msg_key = msg_key
        self.encrypted = encrypted

    @classmethod
    def read(cls, buf: BytesIO) -> SecretMessage:
        fingerprint = Long.read(buf)
        msg_key = buf.read(128 // 8)
        encrypted = buf.read()

        return SecretMessage(fingerprint, msg_key, encrypted)

    def write(self) -> bytes:
        return (
                Long(self.fingerprint)
                + self.msg_key
                + self.encrypted
        )
