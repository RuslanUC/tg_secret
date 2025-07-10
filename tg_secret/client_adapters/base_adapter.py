from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Callable, Awaitable, BinaryIO

from tg_secret.encrypted_file_wrapper import EncryptedFileWrapper
from tg_secret.enums import ParseMode as ParseModeA
from tg_secret.raw.base import MessageEntity


@dataclass(slots=True)
class DhConfigA:
    version: int
    p: bytes
    g: int


@dataclass(slots=True)
class DhConfigNotModifiedA:
    ...


@dataclass(slots=True)
class EncryptedChatA:
    id: int
    g_a_or_b: bytes
    key_fingerprint: int


@dataclass(slots=True)
class InputEncryptedChatA:
    chat_id: int
    access_hash: int


@dataclass(slots=True)
class EncryptedMessageA:
    random_id: int
    chat_id: int
    date: int
    bytes: bytes
    file: EncryptedFileA | None


@dataclass(slots=True)
class EncryptedMessageServiceA:
    random_id: int
    chat_id: int
    date: int
    bytes: bytes


@dataclass(slots=True)
class EncryptedFileA:
    id: int
    access_hash: int
    size: int
    dc_id: int
    key_fingerprint: int


@dataclass(slots=True)
class EncryptedChatRequestedA:
    id: int
    access_hash: int
    date: int
    admin_id: int
    participant_id: int
    g_a: bytes


@dataclass(slots=True)
class EncryptedChatWaitingA:
    id: int
    access_hash: int
    date: int
    admin_id: int
    participant_id: int


@dataclass(slots=True)
class InputFileA:
    id: int
    parts: int
    md5_checksum: str


@dataclass(slots=True)
class InputFileBigA:
    id: int
    parts: int


@dataclass(slots=True)
class InputExistingFileA:
    id: int
    access_hash: int


@dataclass(slots=True)
class InputPeerUserA:
    id: int
    access_hash: int


NewEncryptedMessageFuncT = Callable[[EncryptedMessageA | EncryptedMessageServiceA, int], Awaitable[Any]]
NewChatUpdateFuncT = Callable[[EncryptedChatA], Awaitable[Any]]
NewChatRequestedFuncT = Callable[[EncryptedChatRequestedA], Awaitable[Any]]
NewChatDiscardedFuncT = Callable[[int, bool], Awaitable[Any]]


class SecretClientAdapter(ABC):
    @abstractmethod
    async def get_dh_config(self, version: int) -> DhConfigA | DhConfigNotModifiedA | None:
        ...

    @abstractmethod
    async def accept_encryption(
            self, chat_id: int, access_hash: int, g_b: bytes, key_fingerprint: int,
    ) -> EncryptedChatA:
        ...

    @abstractmethod
    async def discard_encryption(self, chat_id: int, delete_history: bool) -> None:
        ...

    @abstractmethod
    async def send_encrypted(self, peer: InputEncryptedChatA, random_id: int, data: bytes, silent: bool) -> None:
        ...

    @abstractmethod
    async def send_encrypted_service(self, peer: InputEncryptedChatA, random_id: int, data: bytes) -> None:
        ...

    @abstractmethod
    async def send_encrypted_file(
            self, peer: InputEncryptedChatA, random_id: int, data: bytes, silent: bool,
            file: InputFileA | InputFileBigA | InputExistingFileA, key_fingerprint: int,
    ) -> EncryptedFileA:
        ...

    @abstractmethod
    async def parse_entities_for_layer(
            self, text: str, layer: int, mode: ParseModeA,
    ) -> tuple[str, list[MessageEntity]]:
        ...

    @abstractmethod
    async def upload_file(self, file: EncryptedFileWrapper) -> InputFileA | InputFileBigA:
        ...

    @abstractmethod
    async def get_file_mime(self, file_name: str, file: BinaryIO) -> str:
        ...

    @abstractmethod
    async def ack_qts(self, qts: int) -> None:
        ...

    @abstractmethod
    async def resolve_user(self, user_id: int | str) -> InputPeerUserA | None:
        ...

    @abstractmethod
    async def request_encryption(
            self, peer: InputPeerUserA, random_id: int, g_a: bytes,
    ) -> EncryptedChatWaitingA | None:
        ...

    @abstractmethod
    def set_encrypted_message_handler(self, func: NewEncryptedMessageFuncT) -> None:
        ...

    @abstractmethod
    def set_chat_update_handler(self, func: NewChatUpdateFuncT) -> None:
        ...

    @abstractmethod
    def set_chat_requested_handler(self, func: NewChatRequestedFuncT) -> None:
        ...

    @abstractmethod
    def set_chat_discarded_handler(self, func: NewChatDiscardedFuncT) -> None:
        ...

    @abstractmethod
    def get_event_loop(self) -> ...:
        ...

    @abstractmethod
    def get_session_name(self) -> str:
        ...
