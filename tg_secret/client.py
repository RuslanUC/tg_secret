from __future__ import annotations

from hashlib import sha1
from os import urandom
from pathlib import Path
from typing import TYPE_CHECKING, Awaitable, Any, Callable

from pyrogram.errors import SecurityCheckMismatch
from pyrogram.methods.utilities.idle import idle
from pyrogram.raw.functions.messages import DiscardEncryption, GetDhConfig, AcceptEncryption
from pyrogram.raw.types import User, UpdateEncryption, EncryptedChatRequested, InputEncryptedChat, EncryptedChat, \
    EncryptedChatDiscarded
from pyrogram.raw.types.messages import DhConfig, DhConfigNotModified

from .enums import ChatState, ChatRequestResult
from .storage import MemoryStorage, FileStorage

if TYPE_CHECKING:
    from pyrogram import Client

# TODO: replace client.log_out to also remove secret database file
# TODO: allow using same session file as pyrogram
# TODO: wrap EncryptedChat into class that stores user/chat info not in raw format, adds methods like ".send_message", etc.

ChatRequestFuncT = Callable[[EncryptedChatRequested, User], Awaitable[ChatRequestResult]]
ChatReadyFuncT = Callable[[EncryptedChat], Awaitable[Any]]


class TelegramSecretClient:
    def __init__(
            self,
            client: Client,
            session_name: str | None = None,
            workdir: Path | None = None,
            in_memory: bool = False
    ) -> None:
        self._client = client
        self._name = session_name or client.name
        self._workdir = workdir or client.workdir

        if in_memory or self._name == ":memory:":
            self._storage = MemoryStorage(self._name)
        else:
            self._storage = FileStorage(self._name, self._workdir)

        self._client.on_raw_update()(self._raw_updates_handler)

        self._on_requested_handlers: list[ChatRequestFuncT] = []
        self._on_ready_handlers: list[ChatReadyFuncT] = []

    def add_request_handler(self, func: ChatRequestFuncT) -> None:
        self._on_requested_handlers.append(func)

    def on_request(self, func: ChatRequestFuncT) -> ChatRequestFuncT:
        self.add_request_handler(func)
        return func

    def add_chat_ready_handler(self, func: ChatReadyFuncT) -> None:
        self._on_ready_handlers.append(func)

    def on_chat_ready(self, func: ChatReadyFuncT) -> ChatReadyFuncT:
        self.add_chat_ready_handler(func)
        return func

    async def start(self) -> None:
        await self._storage.open()

    async def stop(self) -> None:
        await self._storage.close()

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, _exc_type, _exc_val, _exc_tb) -> None:
        await self.stop()

    async def pyrogram_start(self) -> None:
        async with self:
            await self._client.start()
            await idle()
            await self._client.stop()

    async def _raw_updates_handler(self, _client, update: UpdateEncryption, users: dict[int, User], _chats) -> None:
        if not isinstance(update, UpdateEncryption):
            return

        chat = update.chat
        if isinstance(chat, EncryptedChatRequested):
            await self._storage.set_chat(
                chat.id,
                access_hash=chat.access_hash,
                created_at=chat.date,
                admin_id=chat.admin_id,
                participant_id=chat.participant_id,
                state=ChatState.REQUESTED,
            )

            for handler in self._on_requested_handlers:
                result = await handler(chat, users[chat.admin_id])
                if result is ChatRequestResult.ACCEPT:
                    await self._accept_chat(chat)
                    return
                elif result is ChatRequestResult.DISCARD:
                    await self._discard_chat(chat)
        elif isinstance(chat, EncryptedChatDiscarded):
            await self._storage.delete_chat(chat.id)

    async def _check_and_set_dh_values(self, version: int, p: bytes, g: int) -> None:
        dh_prime = int.from_bytes(p, "big")
        SecurityCheckMismatch.check(2 <= g <= 7, "2 <= g <= 7")
        SecurityCheckMismatch.check(2 ** 2047 < dh_prime < 2 ** 2048, "2 ** 2047 < dh_prime < 2 ** 2048")

        # TODO: check if both dh_prime and (dh_prime - 1) / 2 are prime numbers
        # TODO: check that g generates a cyclic subgroup of prime order (p-1)/2

        await self._storage.set_dh_values(version, p, g)

    async def _get_dh_values(self) -> tuple[bytes, int]:
        dh_version = await self._storage.get_dh_version()
        dh_config = await self._client.invoke(GetDhConfig(version=dh_version, random_length=0))
        if isinstance(dh_config, DhConfig):
            version, p, g = dh_config.version, dh_config.p, dh_config.g
            await self._check_and_set_dh_values(version, p, g)
        elif isinstance(dh_config, DhConfigNotModified):
            p, g = await self._storage.get_dh_values()
            if p is None or g is None:
                dh_config = await self._client.invoke(GetDhConfig(version=dh_version - 1, random_length=0))
                if not isinstance(dh_config, DhConfig):
                    raise ValueError("Client does not have dh values locally and server still returns NotModified")
                version, p, g = dh_config.version, dh_config.p, dh_config.g
                await self._check_and_set_dh_values(version, p, g)
        else:
            raise RuntimeError(f"Expected DhConfig or DhConfigNotModified, got {dh_config.__class__.__name__}")

        return p, g

    async def _accept_chat(self, chat: EncryptedChatRequested) -> None:
        p, g = await self._get_dh_values()
        dh_prime = int.from_bytes(p, "big")
        g_a = int.from_bytes(chat.g_a, "big")

        SecurityCheckMismatch.check(1 < g_a < dh_prime - 1, "1 < g_a < dh_prime - 1")
        SecurityCheckMismatch.check(
            2 ** (2048 - 64) < g_a < dh_prime - 2 ** (2048 - 64),
            "2 ** (2048 - 64) < g_a < dh_prime - 2 ** (2048 - 64)"
        )

        b = int.from_bytes(urandom(2048 // 8), "big")
        g_b = pow(g, b, dh_prime).to_bytes(256, "big")
        key = pow(g_a, b, dh_prime).to_bytes(256, "big")
        key_fingerprint = sha1(key).digest()[-8:]

        new_chat = await self._client.invoke(AcceptEncryption(
            peer=InputEncryptedChat(chat_id=chat.id, access_hash=chat.access_hash),
            g_b=g_b,
            key_fingerprint=int.from_bytes(key_fingerprint, "little"),
        ))

        if not isinstance(new_chat, EncryptedChat):
            raise ValueError(f"Expected server to return EncryptedChat, got {new_chat.__class__.__name__}")

        SecurityCheckMismatch.check(
            new_chat.g_a_or_b == chat.g_a, "new_chat.g_a_or_b == chat.g_a",
        )
        SecurityCheckMismatch.check(
            new_chat.key_fingerprint == key_fingerprint, "new_chat.key_fingerprint == key_fingerprint",
        )

        await self._storage.set_chat(
            new_chat.id,
            access_hash=new_chat.access_hash,
            created_at=new_chat.date,
            admin_id=new_chat.admin_id,
            participant_id=new_chat.participant_id,
            state=ChatState.READY,
            encryption_key=key,
        )

        for handler in self._on_ready_handlers:
            await handler(new_chat)

    async def _discard_chat(self, chat: EncryptedChatRequested) -> None:
        await self._client.invoke(DiscardEncryption(chat_id=chat.id))
        await self._storage.delete_chat(chat.id)






