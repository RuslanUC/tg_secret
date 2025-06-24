from abc import ABC, abstractmethod

from tg_secret.enums import ChatState


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
        "id", "hash", "date", "admin_id", "participant_id", "state", "originator", "peer_layer", "this_layer",
        "in_seq_no", "out_seq_no", "dh_config_id",
    )

    def __init__(
            self,
            id: int,
            hash: int,
            date: int,
            admin_id: int,
            participant_id: int,
            state: int,
            originator: bool,
            peer_layer: int,
            this_layer: int,
            in_seq_no: int,
            out_seq_no: int,
            dh_config_id: int,
    ) -> None:
        self.id = id
        self.hash = hash
        self.date = date
        self.admin_id = admin_id
        self.participant_id = participant_id
        self.state = ChatState(state)
        self.originator = originator
        self.peer_layer = peer_layer
        self.this_layer = this_layer
        self.in_seq_no = in_seq_no
        self.out_seq_no = out_seq_no
        self.dh_config_id = dh_config_id


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
    async def set_chat(
            self, chat_id: int, *,
            access_hash: int | None = None,
            created_at: int | None = None,
            admin_id: int | None = None,
            participant_id: int | None = None,
            state: ChatState | None = None,
            originator: bool | None = None,
            peer_layer: int | None = None,
            this_layer: int | None = None,
            in_seq_no: int | None = None,
            out_seq_no: int | None = None,
    ) -> None:
        ...

    @abstractmethod
    async def get_chat(self, chat_id: int) -> SecretChat | None:
        ...

    @abstractmethod
    async def delete_chat(self, chat_id: int) -> None:
        ...

    @abstractmethod
    async def get_key(
            self, chat_id: int, fingerprint: bytes | None = None, key_id: int | None = None,
            exchange_id: int | None = None,
    ) -> EncryptionKey | None:
        ...

    @abstractmethod
    async def add_key(
            self, chat_id: int, key: bytes | None = None, a: bytes | None = None, exchange_id: int | None = None,
    ) -> None:
        ...

    @abstractmethod
    async def update_key(
            self, chat_id: int, *,
            fingerprint_hex: str | None = None,
            key: bytes | None = None,
            created_at: int | None = None,
            used: int | None = None,
            a: bytes | None = None,
            exchange_id: int | None = None,
    ) -> None:
        ...

    @abstractmethod
    async def inc_key(self, key_id: int) -> None:
        ...

    @abstractmethod
    async def delete_key(self, key_id: int) -> None:
        ...
