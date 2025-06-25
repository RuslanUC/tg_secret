from __future__ import annotations

from hashlib import sha1
from io import BytesIO
from os import urandom
from pathlib import Path
from random import randint
from time import time
from typing import TYPE_CHECKING, Awaitable, Any, Callable, cast

from pyrogram.enums import ParseMode
from pyrogram.errors import SecurityCheckMismatch
from pyrogram.methods.utilities.idle import idle
from pyrogram.raw.core import Int, Long
from pyrogram.raw.functions.messages import DiscardEncryption, GetDhConfig, AcceptEncryption, SendEncryptedService, \
    SendEncrypted
from pyrogram.raw.types import MessageEntityBold as PyroEntityBold, MessageEntityItalic as PyroEntityItalic, \
    MessageEntityUnderline as PyroEntityUnderline, MessageEntityStrike as PyroEntityStrike, \
    MessageEntityBlockquote as PyroEntityBlockquote, MessageEntityCode as PyroEntityCode, \
    MessageEntityPre as PyroEntityPre, MessageEntitySpoiler as PyroEntitySpoiler, \
    MessageEntityTextUrl as PyroEntityTextUrl, MessageEntityCustomEmoji as PyroEntityCustomEmoji
from pyrogram.raw.types import User, UpdateEncryption, EncryptedChatRequested, InputEncryptedChat, EncryptedChat, \
    EncryptedChatDiscarded, UpdateNewEncryptedMessage, EncryptedMessageService, EncryptedMessage
from pyrogram.raw.types.messages import DhConfig, DhConfigNotModified
from tgcrypto import ige256_encrypt, ige256_decrypt

from .enums import ChatState, ChatRequestResult
from .exceptions import SecretChatNotReadyException, SecretLayerException
from .raw import SecretTLObject
from .raw.all import layer
from .raw.base import MessageEntity
from .raw.types import DecryptedMessageService_17, DecryptedMessageActionNotifyLayer, DecryptedMessageLayer, \
    DecryptedMessageService_8, DecryptedMessage_17, DecryptedMessage_45, DecryptedMessage_73, DecryptedMessage_8, \
    DecryptedMessageActionAbortKey, DecryptedMessageActionAcceptKey, DecryptedMessageActionCommitKey, \
    DecryptedMessageActionDeleteMessages, DecryptedMessageActionFlushHistory, DecryptedMessageActionNoop, \
    DecryptedMessageActionReadMessages, DecryptedMessageActionRequestKey, DecryptedMessageActionResend, \
    DecryptedMessageActionScreenshotMessages, DecryptedMessageActionSetMessageTTL, DecryptedMessageActionTyping, \
    DecryptedMessageMediaEmpty, MessageEntityBold, MessageEntityItalic, MessageEntityUnderline, MessageEntityStrike, \
    MessageEntityBlockquote, MessageEntityCode, MessageEntityPre, MessageEntitySpoiler, MessageEntityTextUrl, \
    MessageEntityCustomEmoji
from .storage import MemoryStorage, FileStorage, DhConfig as SecretDhConfig, SecretChat
from .types import SecretChat as TypesSecretChat, SecretMessage
from .utils import msg_key_v2, kdf_v2

if TYPE_CHECKING:
    from pyrogram import Client

# TODO: replace client.log_out to also remove secret database file
# TODO: allow using same session file as pyrogram
# TODO: support multiple libraries (pyrogram/pyrotgfork/hydrogram/telethon) at the same time

ChatRequestFuncT = Callable[[EncryptedChatRequested, User], Awaitable[ChatRequestResult]]
ChatReadyFuncT = Callable[[TypesSecretChat], Awaitable[Any]]
NewMessageFuncT = Callable[[SecretMessage], Awaitable[Any]]
MessagesDeletedFuncT = Callable[[TypesSecretChat, list[int]], Awaitable[Any]]
ChatDeletedFuncT = Callable[[TypesSecretChat], Awaitable[Any]]
HistoryDeletedFuncT = Callable[[TypesSecretChat], Awaitable[Any]]

decrypted_message_clss = (DecryptedMessage_8, DecryptedMessage_17, DecryptedMessage_45, DecryptedMessage_73)
decrypted_message_service_clss = (DecryptedMessageService_8, DecryptedMessageService_17)


class TelegramSecretClient:
    def __init__(
            self,
            client: Client,
            session_name: str | None = None,
            workdir: Path | None = None,
            in_memory: bool = False,
    ) -> None:
        self._client = client
        self._name = session_name or client.name
        self._workdir = workdir or client.workdir

        if in_memory or self._name == ":memory:":
            self._storage = MemoryStorage(self._name)
        else:
            self._storage = FileStorage(self._name, self._workdir)

        # TODO: pyrogram executes update handlers as separate tasks, find a way to ensure that updates
        #  are processed sequentially (maybe asyncio.Lock?)
        self._client.on_raw_update()(self._raw_updates_handler)

        self._on_requested_handlers: list[ChatRequestFuncT] = []
        self._on_ready_handlers: list[ChatReadyFuncT] = []
        self._on_new_message_handlers: list[NewMessageFuncT] = []
        self._on_messages_deleted_handlers: list[MessagesDeletedFuncT] = []
        self._on_chat_deleted_handlers: list[ChatDeletedFuncT] = []
        self._on_history_deleted_handlers: list[HistoryDeletedFuncT] = []

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

    def add_new_message_handler(self, func: NewMessageFuncT) -> None:
        self._on_new_message_handlers.append(func)

    def on_new_message(self, func: NewMessageFuncT) -> NewMessageFuncT:
        self.add_new_message_handler(func)
        return func

    def add_messages_deleted_handler(self, func: MessagesDeletedFuncT) -> None:
        self._on_messages_deleted_handlers.append(func)

    def on_messages_deleted(self, func: MessagesDeletedFuncT) -> MessagesDeletedFuncT:
        self.add_messages_deleted_handler(func)
        return func

    def add_chat_deleted_handler(self, func: ChatDeletedFuncT) -> None:
        self._on_chat_deleted_handlers.append(func)

    def on_chat_deleted(self, func: ChatDeletedFuncT) -> ChatDeletedFuncT:
        self.add_chat_deleted_handler(func)
        return func

    def add_history_deleted_handler(self, func: HistoryDeletedFuncT) -> None:
        self._on_history_deleted_handlers.append(func)

    def on_history_deleted(self, func: HistoryDeletedFuncT) -> HistoryDeletedFuncT:
        self.add_history_deleted_handler(func)
        return func

    async def start(self) -> None:
        await self._storage.open()
        await self._storage.save()

    async def stop(self) -> None:
        await self._storage.save()
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
        if isinstance(update, UpdateNewEncryptedMessage):
            await self._handle_encrypted_update(update)
            return

        if not isinstance(update, UpdateEncryption):
            return

        chat = update.chat
        if isinstance(chat, EncryptedChatRequested):
            await self._storage.add_chat(
                chat.id,
                access_hash=chat.access_hash,
                created_at=chat.date,
                admin_id=chat.admin_id,
                participant_id=chat.participant_id,
                state=ChatState.REQUESTED,
                originator=False,
                peer_layer=46,
                this_layer=46,
            )

            for handler in self._on_requested_handlers:
                result = await handler(chat, users[chat.admin_id])
                if result is ChatRequestResult.ACCEPT:
                    await self._accept_chat(chat)
                    return
                elif result is ChatRequestResult.DISCARD:
                    await self.discard_chat(chat.id)
        elif isinstance(chat, EncryptedChatDiscarded):
            secret_chat = await self.get_chat(chat.id)
            await self._storage.delete_chat(chat.id)

            for handler in self._on_chat_deleted_handlers:
                self._client.loop.create_task(handler(secret_chat))

    async def _check_and_set_dh_values(self, version: int, p: bytes, g: int) -> None:
        dh_prime = int.from_bytes(p, "big")
        SecurityCheckMismatch.check(2 <= g <= 7, "2 <= g <= 7")
        SecurityCheckMismatch.check(2 ** 2047 < dh_prime < 2 ** 2048, "2 ** 2047 < dh_prime < 2 ** 2048")

        # TODO: check if both dh_prime and (dh_prime - 1) / 2 are prime numbers
        # TODO: check that g generates a cyclic subgroup of prime order (p-1)/2

        await self._storage.set_dh_config(version, p, g)

    async def _get_dh_config(self) -> SecretDhConfig:
        local_config = await self._storage.get_dh_config(None)
        dh_version = local_config.version if local_config is not None else 0

        dh_config = await self._client.invoke(GetDhConfig(version=dh_version, random_length=0))
        if isinstance(dh_config, DhConfig):
            version, p, g = dh_config.version, dh_config.p, dh_config.g
            await self._check_and_set_dh_values(version, p, g)
            return await self._storage.get_dh_config(version)

        if isinstance(dh_config, DhConfigNotModified):
            if local_config is not None:
                return local_config

            dh_config = await self._client.invoke(GetDhConfig(version=dh_version - 1, random_length=0))
            if not isinstance(dh_config, DhConfig):
                raise ValueError("Client does not have dh values locally and server still returns NotModified")

            version, p, g = dh_config.version, dh_config.p, dh_config.g
            await self._check_and_set_dh_values(version, p, g)
            return await self._storage.get_dh_config(version)

        raise RuntimeError(f"Expected DhConfig or DhConfigNotModified, got {dh_config.__class__.__name__}")

    async def _gen_key_from_g_a(self, dh_version: int | None, g_a_bytes: bytes) -> tuple[bytes, bytes, int, int]:
        if dh_version is None:
            dh = await self._get_dh_config()
        else:
            dh = await self._storage.get_dh_config(dh_version)

        dh_prime = int.from_bytes(dh.p, "big")
        g_a = int.from_bytes(g_a_bytes, "big")

        SecurityCheckMismatch.check(1 < g_a < dh_prime - 1, "1 < g_a < dh_prime - 1")
        SecurityCheckMismatch.check(
            2 ** (2048 - 64) < g_a < dh_prime - 2 ** (2048 - 64),
            "2 ** (2048 - 64) < g_a < dh_prime - 2 ** (2048 - 64)"
        )

        b = int.from_bytes(urandom(2048 // 8), "big")
        g_b = pow(dh.g, b, dh_prime).to_bytes(256, "big")
        key = pow(g_a, b, dh_prime).to_bytes(256, "big")
        key_fingerprint = sha1(key).digest()[-8:]
        key_fingerprint = int.from_bytes(key_fingerprint, "little", signed=True)

        return g_b, key, key_fingerprint, dh.version

    async def _accept_chat(self, chat: EncryptedChatRequested) -> None:
        g_b, key, key_fingerprint, dh_version = await self._gen_key_from_g_a(None, chat.g_a)

        new_chat = await self._client.invoke(AcceptEncryption(
            peer=InputEncryptedChat(chat_id=chat.id, access_hash=chat.access_hash),
            g_b=g_b,
            key_fingerprint=key_fingerprint,
        ))

        if not isinstance(new_chat, EncryptedChat):
            raise ValueError(f"Expected server to return EncryptedChat, got {new_chat.__class__.__name__}")

        SecurityCheckMismatch.check(
            new_chat.g_a_or_b == chat.g_a, "new_chat.g_a_or_b == chat.g_a",
        )
        SecurityCheckMismatch.check(
            new_chat.key_fingerprint == key_fingerprint, "new_chat.key_fingerprint == key_fingerprint",
        )

        await self._storage.update_chat(
            new_chat.id,
            state=ChatState.READY,
            originator=False,
            this_layer=layer,
            dh_config_version=dh_version,
            key=key,
            key_fp=key_fingerprint,
            key_used=0,
            key_created_at=int(time()),
        )

        await self._notify_about_layer(new_chat.id)

        secret_chat = await self.get_chat(new_chat.id)
        for handler in self._on_ready_handlers:
            self._client.loop.create_task(handler(secret_chat))

    async def discard_chat(self, chat_id: int) -> None:
        await self._client.invoke(DiscardEncryption(chat_id=chat_id))
        await self._storage.delete_chat(chat_id)

    async def _notify_about_layer(self, chat_id: int) -> None:
        await self._send_service_message(chat_id, DecryptedMessageActionNotifyLayer(layer=layer))

    async def rekey(self, chat_id: int) -> None:
        chat = await self._storage.get_chat(chat_id)
        if chat.exchange_id is not None:
            return

        dh = await self._storage.get_dh_config(version=chat.dh_config_version)
        dh_prime = int.from_bytes(dh.p, "big")

        a_bytes = urandom(2048 // 8)
        a = int.from_bytes(a_bytes, "big")
        g_a = pow(dh.g, a, dh_prime).to_bytes(2048 // 8, "big")
        exchange_id = int.from_bytes(urandom(8), "little", signed=True)

        await self._storage.update_chat(chat, a=a_bytes, exchange_id=exchange_id)
        await self._send_service_message(chat_id, DecryptedMessageActionRequestKey(exchange_id=exchange_id, g_a=g_a))

    # TODO: properly annotate action
    async def _send_service_message(self, chat_id: int, action: SecretTLObject) -> None:
        random_id = int.from_bytes(urandom(8), "little", signed=True)
        await self._send_message(
            chat_id,
            DecryptedMessageService_17(
                random_id=random_id,
                action=action,
            ),
            random_id,
        )

    @staticmethod
    def _gen_in_out_seq_no(seq_no: int, out: bool, originator: bool):
        return seq_no * 2 + (1 if out == originator else 0)

    async def _get_or_switch_chat_key(self, chat: SecretChat, fingerprint: int | None = None) -> bytes:
        if fingerprint is None or fingerprint == chat.key_fp:
            return chat.key
        if fingerprint == chat.fut_key_fp:
            await self._storage.update_chat(
                chat,
                key=chat.fut_key,
                key_fp=chat.fut_key_fp,
                key_used=0,
                key_created_at=int(time()),
                fut_key=None,
                fut_key_fp=None,
                exchange_id=None,
                a=None,
            )

            return chat.key

        raise RuntimeError("Unreachable")

    async def _maybe_start_rekeying(self, chat: SecretChat) -> None:
        if (chat.key_used > 100 or (time() - chat.key_created_at) > 86400 * 7) and chat.exchange_id is None:
            await self.rekey(chat.id)

    # TODO: SendEncryptedFile
    async def _send_message(
            self, chat_id: int, decrypted_message: SecretTLObject, random_id: int, *,
            silent: bool = False,
    ) -> None:
        chat = await self._storage.get_chat(chat_id)
        if chat.state is not ChatState.READY:
            raise SecretChatNotReadyException

        key = await self._get_or_switch_chat_key(chat)

        await self._storage.update_chat(chat, key_used=chat.key_used + 1)
        old_out_seq = await self._storage.inc_chat_out_seq_no(chat_id)

        message_to_encrypt = DecryptedMessageLayer(
            random_bytes=urandom(randint(16, 32)),
            layer=min(chat.this_layer, max(46, chat.peer_layer)),
            in_seq_no=self._gen_in_out_seq_no(chat.in_seq_no, False, chat.originator),
            out_seq_no=self._gen_in_out_seq_no(old_out_seq, True, chat.originator),
            message=decrypted_message,
        ).write()
        to_encrypt = (
            Int(len(message_to_encrypt))
            + message_to_encrypt
            + urandom(randint(12, 512) // 4 * 4)
        )
        to_encrypt += b"\x00" * (-len(to_encrypt) % 16)

        msg_key = msg_key_v2(key, to_encrypt, chat.originator)
        aes_key, aes_iv = kdf_v2(key, msg_key, chat.originator)
        encrypted_payload = ige256_encrypt(to_encrypt, aes_key, aes_iv)

        final_payload = Long(chat.key_fp) + msg_key + encrypted_payload

        peer = InputEncryptedChat(chat_id=chat_id, access_hash=chat.access_hash)

        if isinstance(decrypted_message, decrypted_message_service_clss):
            request = SendEncryptedService(
                peer=peer,
                random_id=random_id,
                data=final_payload,
            )
        elif isinstance(decrypted_message, decrypted_message_clss):
            request = SendEncrypted(
                peer=peer,
                random_id=random_id,
                data=final_payload,
                silent=silent,
            )
        else:
            raise ValueError(
                f"Expected DecryptedMessage or DecryptedMessageService, got {decrypted_message.__class__.__name__}"
            )

        await self._client.invoke(request)
        await self._maybe_start_rekeying(chat)

    async def _handle_encrypted_update(self, update: UpdateNewEncryptedMessage) -> None:
        # TODO: handle files

        if isinstance(update.message, EncryptedMessageService):
            message = cast(EncryptedMessageService, update.message)
            is_service = True
            chat_id = message.chat_id
            data = message.bytes
            file = None
        elif isinstance(update.message, EncryptedMessage):
            # For some reason pycharm cant understand that if isinstance check succeeded,
            #  then `update.message` is EncryptedMessage and still thinks that `update.message` is "base" type,
            #  so doing typing-cast here.
            # It can be removed after pycharm stops complaining about
            #  "Unresolved attribute reference '...' for class 'EncryptedMessage'"
            message = cast(EncryptedMessage, update.message)
            is_service = False
            chat_id = message.chat_id
            data = message.bytes
            file = message.file
        else:
            raise ValueError(
                f"Expected EncryptedMessage or EncryptedMessageService, got {update.message.__class__.__name__}"
            )

        chat = await self._storage.get_chat(chat_id)
        key_fp = int.from_bytes(data[:8], "little", signed=True)
        key = await self._get_or_switch_chat_key(chat, key_fp)

        data = data[8:]
        msg_key = data[:128 // 8]
        data = data[128 // 8:]

        aes_key, aes_iv = kdf_v2(key, msg_key, not chat.originator)
        decrypted_payload = ige256_decrypt(data, aes_key, aes_iv)

        length = int.from_bytes(decrypted_payload[:4], "little", signed=True)
        decrypted_payload = decrypted_payload[4:]
        # Payload type + random bytes (at least 128 bits) + layer + in_seq_no + out_seq_no + message type + padding (at least 12 bytes)
        if length <= (4 + 128 // 8 + 4 + 4 + 4 + 4 + 12) or len(decrypted_payload) < length:
            return

        payload = decrypted_payload[:length]
        obj = SecretTLObject.read(BytesIO(payload))
        if not isinstance(obj, DecryptedMessageLayer):
            return

        remote_x_out = 1 if not chat.originator else 0
        if obj.out_seq_no % 2 != remote_x_out:
            # TODO: seq_no not consistent in terms of parity, should abort secret chat
            return

        remote_local_out_seq_no = (obj.out_seq_no - remote_x_out) // 2
        if remote_local_out_seq_no < chat.in_seq_no:
            return
        elif remote_local_out_seq_no > chat.in_seq_no:
            print(
                f"detected gap in seq_no: got {obj.out_seq_no=}, "
                f"remote has out_seq_no={remote_local_out_seq_no}, "
                f"we have {chat.in_seq_no=}"
            )

        await self._storage.update_chat(chat, key_used=chat.key_used + 1)
        await self._storage.inc_chat_in_seq_no(chat_id)

        if is_service:
            if not isinstance(obj.message, decrypted_message_service_clss):
                raise ValueError(
                    f"Expected DecryptedMessageService, got {obj.message.__class__.__name__}"
                )
            await self._handle_encrypted_service_message(chat.id, obj.message)
        else:
            if not isinstance(obj.message, decrypted_message_clss):
                raise ValueError(
                    f"Expected DecryptedMessage, got {obj.message.__class__.__name__}"
                )
            await self._handle_encrypted_message(chat.id, obj.message)

        await self._maybe_start_rekeying(chat)

    async def _send_abort_key(self, chat_id: int, exchange_id: int) -> None:
        await self._send_service_message(chat_id, DecryptedMessageActionAbortKey(
            exchange_id=exchange_id,
        ))

    async def _send_accept_key(self, chat_id: int, exchange_id: int, g_b: bytes, fp: int) -> None:
        await self._send_service_message(chat_id, DecryptedMessageActionAcceptKey(
            exchange_id=exchange_id,
            g_b=g_b,
            key_fingerprint=fp,
        ))

    async def _send_commit_key(self, chat_id: int, exchange_id: int, fp: int) -> None:
        await self._send_service_message(chat_id, DecryptedMessageActionCommitKey(
            exchange_id=exchange_id,
            key_fingerprint=fp,
        ))

    async def _handle_encrypted_service_message(
            self, chat_id: int, message: DecryptedMessageService_8 | DecryptedMessageService_17
    ) -> None:
        action = message.action
        chat = await self._storage.get_chat(chat_id)

        if isinstance(action, DecryptedMessageActionRequestKey):
            if chat.exchange_id is not None:
                if chat.exchange_id > action.exchange_id:
                    return
                else:
                    await self._send_abort_key(chat.id, chat.exchange_id)

            try:
                g_b, key, key_fingerprint, dh_version = await self._gen_key_from_g_a(chat.dh_config_version, action.g_a)
            except SecurityCheckMismatch:
                await self._send_abort_key(chat.id, action.exchange_id)
                return

            await self._storage.update_chat(
                chat,
                exchange_id=action.exchange_id,
                a=None,
                fut_key=key,
                fut_key_fp=key_fingerprint,
            )
            await self._send_accept_key(chat.id, action.exchange_id, g_b, key_fingerprint)
        elif isinstance(action, DecryptedMessageActionAcceptKey):
            if chat.exchange_id is None or chat.a is None or chat.exchange_id != action.exchange_id:
                await self._storage.update_chat(chat, exchange_id=None, a=None, fut_key=None, fut_key_fp=None)
                return await self._send_abort_key(chat.id, action.exchange_id)

            dh_config = await self._storage.get_dh_config(chat.dh_config_version)

            dh_prime = int.from_bytes(dh_config.p, "big")
            g_b = int.from_bytes(action.g_b, "big")
            a = int.from_bytes(chat.a, "big")
            key = pow(g_b, a, dh_prime).to_bytes(2048 // 8, "big")
            key_fingerprint = sha1(key).digest()[-8:]
            key_fingerprint = int.from_bytes(key_fingerprint, "little", signed=True)

            if key_fingerprint != action.key_fingerprint:
                await self._storage.update_chat(chat, exchange_id=None, a=None, fut_key=None, fut_key_fp=None)
                return await self._send_abort_key(chat.id, action.exchange_id)

            await self._storage.update_chat(
                chat,
                fut_key=key,
                fut_key_fp=key_fingerprint,
            )
            await self._send_commit_key(chat.id, action.exchange_id, key_fingerprint)
        elif isinstance(action, DecryptedMessageActionCommitKey):
            if chat.exchange_id == action.exchange_id and chat.fut_key_fp == action.key_fingerprint:
                await self._storage.update_chat(
                    chat,
                    a=None,
                    exchange_id=None,
                    key=chat.fut_key,
                    key_fp=chat.fut_key_fp,
                    key_used=0,
                    key_created_at=int(time()),
                    fut_key=None,  # TODO: set to old key?
                    fut_key_fp=None,  # TODO: set to old key fp?
                )
            else:
                await self._storage.update_chat(chat, exchange_id=None, a=None, fut_key=None, fut_key_fp=None)
                return await self._send_abort_key(chat.id, action.exchange_id)
        elif isinstance(action, DecryptedMessageActionAbortKey):
            await self._storage.update_chat(chat, exchange_id=None, a=None, fut_key=None, fut_key_fp=None)
        elif isinstance(action, DecryptedMessageActionDeleteMessages):
            secret_chat = await self.get_chat(chat.id)
            for handler in self._on_messages_deleted_handlers:
                self._client.loop.create_task(handler(secret_chat, action.random_ids))
        elif isinstance(action, DecryptedMessageActionFlushHistory):
            secret_chat = await self.get_chat(chat.id)
            for handler in self._on_history_deleted_handlers:
                self._client.loop.create_task(handler(secret_chat))
        elif isinstance(action, DecryptedMessageActionNoop):
            ...
        elif isinstance(action, DecryptedMessageActionNotifyLayer):
            if chat.peer_layer >= action.layer:
                return
            await self._storage.update_chat(chat, peer_layer=action.layer)
        elif isinstance(action, DecryptedMessageActionReadMessages):
            ...
        elif isinstance(action, DecryptedMessageActionResend):
            ...
        elif isinstance(action, DecryptedMessageActionScreenshotMessages):
            ...
        elif isinstance(action, DecryptedMessageActionSetMessageTTL):
            ...
        elif isinstance(action, DecryptedMessageActionTyping):
            ...
        else:
            raise ValueError(f"Excepted DecryptedMessageAction, got {action.__class__.__name__}")

    async def _handle_encrypted_message(
            self, chat_id: int,
            message: DecryptedMessage_8 | DecryptedMessage_17 | DecryptedMessage_45 | DecryptedMessage_73,
    ) -> None:
        if isinstance(message, (DecryptedMessage_73, DecryptedMessage_45)):
            reply_to = message.reply_to_random_id
            entities = message.entities
        else:
            reply_to = None
            entities = []

        secret_chat = await self.get_chat(chat_id)
        new_message = SecretMessage(
            random_id=message.random_id,
            chat=secret_chat,
            from_id=secret_chat.peer_id,
            text=message.message,
            entities=entities,
            reply_to_random_id=reply_to,
            _client=self,
        )

        for handler in self._on_new_message_handlers:
            self._client.loop.create_task(handler(new_message))

    async def get_chat(self, chat_id: int) -> TypesSecretChat | None:
        chat = await self._storage.get_chat(chat_id)
        if chat is None:
            return None

        return TypesSecretChat(
            chat_id=chat.id,
            peer_id=chat.participant_id if chat.originator else chat.admin_id,
            originator=chat.originator,
            created_at=chat.created_at,
            sent_messages=chat.out_seq_no,
            recv_messages=chat.in_seq_no,
            state=chat.state,
            _client=self,
        )

    _pyrogram_entities_mapping = {
        PyroEntityBold: MessageEntityBold,
        PyroEntityItalic: MessageEntityItalic,
        PyroEntityUnderline: MessageEntityUnderline,
        PyroEntityStrike: MessageEntityStrike,
        PyroEntityBlockquote: MessageEntityBlockquote,
        PyroEntityCode: MessageEntityCode,
        PyroEntityPre: MessageEntityPre,
        PyroEntitySpoiler: MessageEntitySpoiler,
        PyroEntityTextUrl: MessageEntityTextUrl,
        PyroEntityCustomEmoji: MessageEntityCustomEmoji,
    }

    _entities_min_layers = {
        MessageEntityUnderline: 144,
        MessageEntityStrike: 144,
        MessageEntityBlockquote: 144,
        MessageEntitySpoiler: 144,
        MessageEntityCustomEmoji: 144,
    }

    @classmethod
    def _get_entities_with_layer(cls, entities: list[...], peer_layer: int) -> list[MessageEntity]:
        if peer_layer < 45:
            return []

        result = []
        for entity in entities:
            secret_entity_cls = cls._pyrogram_entities_mapping.get(type(entity))
            if secret_entity_cls is None:
                continue
            if cls._entities_min_layers.get(secret_entity_cls, 0) > peer_layer:
                continue

            kwargs = {}
            for slot in entity.__slots__:
                kwargs[slot] = getattr(entity, slot)

            result.append(secret_entity_cls(**kwargs))

        return result

    # TODO: allow sending by user id
    async def send_text_message(
            self,
            chat_id: int,
            text: str,
            ttl: int = 0,
            disable_web_page_preview: bool = False,
            disable_notification: bool = False,
            via_bot_name: str | None = None,
            reply_to_message_id: int | None = None,
            parse_mode: ParseMode | None = None,
    ) -> SecretMessage:
        chat = await self._storage.get_chat(chat_id)
        if chat.state is not ChatState.READY:
            raise SecretChatNotReadyException

        parse_result = await self._client.parser.parse(text, parse_mode)
        message = parse_result["message"]
        entities = self._get_entities_with_layer(parse_result["entities"], chat.peer_layer)

        random_id = int.from_bytes(urandom(8), "little", signed=True)
        if chat.peer_layer >= 73:
            request = DecryptedMessage_73(
                random_id=random_id,
                message=message,
                entities=entities or None,
                ttl=ttl,
                no_webpage=disable_web_page_preview,
                via_bot_name=via_bot_name,
                reply_to_random_id=reply_to_message_id,
            )
        elif chat.peer_layer >= 45:
            request = DecryptedMessage_45(
                random_id=random_id,
                message=message,
                entities=entities or None,
                ttl=ttl,
                via_bot_name=via_bot_name,
                reply_to_random_id=reply_to_message_id,
            )
        elif chat.peer_layer >= 17:
            reply_to_message_id = None
            request = DecryptedMessage_17(
                random_id=random_id,
                message=message,
                ttl=ttl,
                media=DecryptedMessageMediaEmpty(),
            )
        elif chat.peer_layer >= 8:
            reply_to_message_id = None
            request = DecryptedMessage_8(
                random_id=random_id,
                message=message,
                random_bytes=urandom(16),
                media=DecryptedMessageMediaEmpty(),
            )
        else:
            raise SecretLayerException("messages (?)", chat.peer_layer, 8)

        await self._send_message(chat_id, request, random_id, silent=disable_notification)

        return SecretMessage(
            random_id=random_id,
            chat=await self.get_chat(chat.id),
            from_id=chat.admin_id if chat.originator else chat.participant_id,
            text=message,
            entities=entities,
            reply_to_random_id=reply_to_message_id,
            _client=self,
        )
