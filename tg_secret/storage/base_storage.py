from abc import ABC, abstractmethod
from enum import Enum, auto

from tg_secret.enums import ChatState

class MissingType(Enum):
    MISSING = auto()


MISSING = MissingType.MISSING


class DhConfig:
    __slots__ = ("version", "date", "p", "g",)

    def __init__(
            self,
            version: int,
            date: int,
            p: bytes,
            g: int,
    ) -> None:
        self.version = version
        self.date = date
        self.p = p
        self.g = g


class SecretChat:
    __slots__ = (
        "id", "access_hash", "created_at", "admin_id", "participant_id", "state", "originator", "peer_layer", "this_layer",
        "in_seq_no", "out_seq_no", "dh_config_version", "a", "exchange_id", "key", "key_fp", "fut_key", "fut_key_fp",
        "key_used", "key_created_at",
    )

    def __init__(
            self,
            id: int,
            access_hash: int,
            created_at: int,
            admin_id: int,
            participant_id: int,
            state: int,
            originator: bool,
            peer_layer: int,
            this_layer: int,
            in_seq_no: int,
            out_seq_no: int,
            dh_config_version: int,
            a: bytes | None,
            exchange_id: int | None,
            key: bytes | None,
            key_fp: int,
            fut_key: bytes | None,
            fut_key_fp: int | None,
            key_used: int,
            key_created_at: int,
    ) -> None:
        self.id = id
        self.access_hash = access_hash
        self.created_at = created_at
        self.admin_id = admin_id
        self.participant_id = participant_id
        self.state = ChatState(state)
        self.originator = originator
        self.peer_layer = peer_layer
        self.this_layer = this_layer
        self.in_seq_no = in_seq_no
        self.out_seq_no = out_seq_no
        self.dh_config_version = dh_config_version
        self.a = a
        self.exchange_id = exchange_id
        self.key = key
        self.key_fp = key_fp
        self.fut_key = fut_key
        self.fut_key_fp = fut_key_fp
        self.key_used = key_used
        self.key_created_at = key_created_at


class EncryptionKey:
    __slots__ = ("id", "chat_id", "fingerprint_hex", "key", "created_at", "used", "a", "exchange_id",)

    def __init__(
            self,
            id: int,
            chat_id: int,
            fingerprint_hex: str,
            key: bytes,
            created_at: int,
            used: int,
            a: bytes,
            exchange_id: int,
    ) -> None:
        self.id = id
        self.chat_id = chat_id
        self.fingerprint_hex = fingerprint_hex
        self.key = key
        self.created_at = created_at
        self.used = used
        self.a = a
        self.exchange_id = exchange_id


class BaseMessage:
    __slots__ = ("id", "chat_id", "message", "file_id", "file_hash", "file_key_fp",)

    def __init__(
            self,
            *,
            id: int,
            chat_id: int,
            message: bytes,
            file_id: int | None,
            file_hash: int | None,
            file_key_fp: int | None,
    ) -> None:
        self.id = id
        self.chat_id = chat_id
        self.message = message
        self.file_id = file_id
        self.file_hash = file_hash
        self.file_key_fp = file_key_fp


class SentMessage(BaseMessage):
    __slots__ = ("out_seq_no", "silent",)

    def __init__(
            self,
            *,
            id: int,
            chat_id: int,
            out_seq_no: int,
            message: bytes,
            file_id: int | None,
            file_hash: int | None,
            file_key_fp: int | None,
            silent: bool,
    ) -> None:
        super().__init__(
            id=id, chat_id=chat_id, message=message, file_id=file_id, file_hash=file_hash, file_key_fp=file_key_fp,
        )
        self.out_seq_no = out_seq_no
        self.silent = silent


class RecvMessage(BaseMessage):
    __slots__ = ("remote_out_seq_no", "file_dc", "file_size", "is_service",)

    def __init__(
            self,
            *,
            id: int,
            chat_id: int,
            remote_out_seq_no: int,
            message: bytes,
            file_id: int | None,
            file_dc: int | None,
            file_hash: int | None,
            file_size: int | None,
            file_key_fp: int | None,
            is_service: bool,
    ) -> None:
        super().__init__(
            id=id, chat_id=chat_id, message=message, file_id=file_id, file_hash=file_hash, file_key_fp=file_key_fp,
        )
        self.remote_out_seq_no = remote_out_seq_no
        self.file_dc = file_dc
        self.file_size = file_size
        self.is_service = is_service


class BaseStorage(ABC):
    @abstractmethod
    async def open(self) -> None:
        ...

    @abstractmethod
    async def save(self) -> None:
        ...

    @abstractmethod
    async def close(self) -> None:
        ...

    @abstractmethod
    async def delete(self) -> None:
        ...

    @abstractmethod
    async def get_dh_config(self, version: int | None) -> DhConfig | None:
        ...

    @abstractmethod
    async def set_dh_config(self, version: int, p: bytes, g: int) -> None:
        ...

    @abstractmethod
    async def add_chat(
            self, chat_id: int, *,
            access_hash: int,
            created_at: int,
            admin_id: int,
            participant_id: int,
            state: ChatState,
            originator: bool,
            peer_layer: int,
            this_layer: int,
    ) -> None:
        ...

    @abstractmethod
    async def update_chat(
            self, chat: int | SecretChat, *,
            access_hash: int | MissingType = MISSING,
            created_at: int | MissingType = MISSING,
            admin_id: int | MissingType = MISSING,
            participant_id: int | MissingType = MISSING,
            state: ChatState | MissingType = MISSING,
            originator: bool | MissingType = MISSING,
            peer_layer: int | MissingType = MISSING,
            this_layer: int | MissingType = MISSING,
            in_seq_no: int | MissingType = MISSING,
            out_seq_no: int | MissingType = MISSING,
            a: bytes | None | MissingType = MISSING,
            exchange_id: int | None | MissingType = MISSING,
            key: bytes | None | MissingType = MISSING,
            key_fp: int | None | MissingType = MISSING,
            fut_key: bytes | None | MissingType = MISSING,
            fut_key_fp: int | None | MissingType = MISSING,
            key_used: int | MissingType = MISSING,
            key_created_at: int | MissingType = MISSING,
    ) -> None:
        ...

    @abstractmethod
    async def get_chat(self, chat_id: int) -> SecretChat | None:
        ...

    @abstractmethod
    async def get_chat_by_peer(self, peer_id: int) -> SecretChat | None:
        ...

    @abstractmethod
    async def delete_chat(self, chat_id: int) -> None:
        ...

    @abstractmethod
    async def get_chat_ids(self) -> list[int]:
        ...

    @abstractmethod
    async def store_out_message(
            self, chat_id: int, out_seq_no: int, data: bytes, file_id: int | None, file_hash: int | None,
            file_key_fp: int | None, silent: bool,
    ) -> None:
        ...

    @abstractmethod
    async def get_out_messages(self, chat_id: int, start_seq_no: int, end_seq_no: int) -> list[SentMessage]:
        ...

    @abstractmethod
    async def store_in_message(
            self, chat_id: int, out_seq_no: int, data: bytes, file_id: int | None, file_dc: int | None,
            file_hash: int | None, file_size: int | None, file_key_fp: int | None, is_service: bool,
    ) -> None:
        ...

    @abstractmethod
    async def get_and_delete_in_message(self, chat_id: int, seq_no: int) -> RecvMessage | None:
        ...
