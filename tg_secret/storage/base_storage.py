from abc import ABC, abstractmethod

from tg_secret.enums import ChatState


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
    async def set_dh_values(self, version: int, p: bytes, g: int) -> None:
        ...

    @abstractmethod
    async def get_dh_version(self) -> int:
        ...

    @abstractmethod
    async def get_dh_values(self) -> tuple[bytes, int]:
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
            encryption_key: bytes | None = None,
    ) -> None:
        ...

    @abstractmethod
    async def get_chat(self, chat_id: int) -> tuple[int, int, int, int, ChatState, bool, int, int, int, int, bytes]:
        ...

    @abstractmethod
    async def delete_chat(self, chat_id: int) -> None:
        ...