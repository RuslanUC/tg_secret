from __future__ import annotations

import io
import sys
from contextlib import ExitStack
from hashlib import sha1, md5
from io import BytesIO, IOBase
from os import urandom
from os.path import basename
from pathlib import Path, PurePath
from random import randint
from time import time
from typing import Awaitable, Any, Callable, cast, BinaryIO, AsyncGenerator

from .aes import ige256_encrypt, ige256_decrypt
from .client_adapters.base_adapter import DhConfigA, DhConfigNotModifiedA, InputEncryptedChatA, EncryptedMessageA, \
    EncryptedMessageServiceA, EncryptedChatA, EncryptedChatRequestedA, SecretClientAdapter, InputFileA, InputFileBigA, \
    EncryptedFileA, InputExistingFileA
from .client_adapters.pyrogram_adapter import PyrogramClientAdapter
from .encrypted_file_wrapper import EncryptedFileWrapper
from .enums import ChatState, ChatRequestResult, ParseMode, GapsStrategy
from .exceptions import SecretChatNotReadyException, SecretLayerException, SecretSecurityException
from .raw import SecretTLObject
from .raw.all import layer
from .raw.base import DecryptedMessageAction, MessageEntity, DecryptedMessageMedia, DecryptedMessage, \
    DecryptedMessageInst
from .raw.types import DecryptedMessageService_17, DecryptedMessageActionNotifyLayer, DecryptedMessageLayer, \
    DecryptedMessageService_8, DecryptedMessage_17, DecryptedMessage_45, DecryptedMessage_73, DecryptedMessage_8, \
    DecryptedMessageActionAbortKey, DecryptedMessageActionAcceptKey, DecryptedMessageActionCommitKey, \
    DecryptedMessageActionDeleteMessages, DecryptedMessageActionFlushHistory, DecryptedMessageActionNoop, \
    DecryptedMessageActionReadMessages, DecryptedMessageActionRequestKey, DecryptedMessageActionResend, \
    DecryptedMessageActionScreenshotMessages, DecryptedMessageActionSetMessageTTL, DecryptedMessageActionTyping, \
    DecryptedMessageMediaEmpty, DecryptedMessageMediaDocument_143, DocumentAttributeFilename, \
    DecryptedMessageMediaDocument_45, DecryptedMessageMediaDocument_8
from .storage import MemoryStorage, FileStorage, DhConfig as SecretDhConfig, SecretChat
from .types import SecretChat as TypesSecretChat, SecretMessage
from .utils import msg_key_v2, kdf_v2, read_long, write_int, write_long, read_int

# TODO: logging

ChatRequestFuncT = Callable[[TypesSecretChat], Awaitable[ChatRequestResult]]
ChatReadyFuncT = Callable[[TypesSecretChat], Awaitable[Any]]
NewMessageFuncT = Callable[[SecretMessage], Awaitable[Any]]
MessagesDeletedFuncT = Callable[[TypesSecretChat, list[int]], Awaitable[Any]]
ChatDeletedFuncT = Callable[[TypesSecretChat, bool], Awaitable[Any]]
HistoryDeletedFuncT = Callable[[TypesSecretChat], Awaitable[Any]]

decrypted_message_clss = (DecryptedMessage_8, DecryptedMessage_17, DecryptedMessage_45, DecryptedMessage_73)
decrypted_message_service_clss = (DecryptedMessageService_8, DecryptedMessageService_17)


class TelegramSecretClient:
    def __init__(
            self,
            client_adapter: SecretClientAdapter,
            session_name: str | None = None,
            workdir: Path = Path(sys.argv[0]).parent,
            in_memory: bool = False,
            gaps_strategy: GapsStrategy = GapsStrategy.FILL,
    ) -> None:
        self._adapter = client_adapter

        self._loop = client_adapter.get_event_loop()
        self._name = session_name or client_adapter.get_session_name()
        self._workdir = workdir
        self._gaps_strategy = gaps_strategy

        if in_memory or self._name == ":memory:":
            self._storage = MemoryStorage(self._name)
        else:
            self._storage = FileStorage(self._name, self._workdir)

        # TODO: pyrogram executes update handlers as separate tasks, find a way to ensure that updates
        #  are processed sequentially (maybe asyncio.Lock?)

        self._adapter.set_encrypted_message_handler(self._on_new_encrypted_message_handler)
        self._adapter.set_chat_update_handler(self._on_chat_updated_handler)
        self._adapter.set_chat_requested_handler(self._on_chat_requested_handler)
        self._adapter.set_chat_discarded_handler(self._on_chat_discarded_handler)

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
        from pyrogram import Client, idle

        if not isinstance(self._adapter, PyrogramClientAdapter) or not isinstance(self._adapter.client, Client):
            raise RuntimeError("TelegramSecretClient.pyrogram_start() must be called only with pyrogram client!")

        async with self:
            await self._adapter.client.start()
            await idle()
            await self._adapter.client.stop()

    async def _on_new_encrypted_message_handler(
            self, message: EncryptedMessageA | EncryptedMessageServiceA, qts: int,
    ) -> None:
        await self._handle_encrypted_update(message)
        await self._adapter.ack_qts(qts)

    async def _on_chat_updated_handler(self, chat: EncryptedChatA) -> None:
        local_chat = await self._storage.get_chat(chat.id)
        if local_chat.state is not ChatState.WAITING:
            return

        dh_config = await self._storage.get_dh_config(local_chat.dh_config_version)

        dh_prime = int.from_bytes(dh_config.p, "big")
        g_b = int.from_bytes(chat.g_a_or_b, "big")
        a = int.from_bytes(local_chat.a, "big")
        key = pow(g_b, a, dh_prime).to_bytes(2048 // 8, "big")
        key_fingerprint = sha1(key).digest()[-8:]
        key_fingerprint = read_long(key_fingerprint)

        if key_fingerprint != chat.key_fingerprint:
            await self.discard_chat(chat.id)
            return

        await self._storage.update_chat(
            local_chat,
            key=key,
            key_fp=key_fingerprint,
            key_used=0,
            key_created_at=int(time()),
            state=ChatState.READY,
            this_layer=layer,
        )

        await self._notify_about_layer(local_chat.id)

        secret_chat = await self.get_chat(local_chat.id)
        for handler in self._on_ready_handlers:
            self._loop.create_task(handler(secret_chat))

    async def _on_chat_requested_handler(self, chat: EncryptedChatRequestedA) -> None:
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

        secret_chat = await self.get_chat(chat.id)

        for handler in self._on_requested_handlers:
            result = await handler(secret_chat)
            if result is ChatRequestResult.ACCEPT:
                await self._accept_chat(chat)
                return
            elif result is ChatRequestResult.DISCARD:
                await self.discard_chat(chat.id)

    async def _on_chat_discarded_handler(self, chat_id: int, history_deleted: bool) -> None:
        secret_chat = await self.get_chat(chat_id)
        await self._storage.delete_chat(chat_id)
        if secret_chat is None:
            return

        for handler in self._on_chat_deleted_handlers:
            self._loop.create_task(handler(secret_chat, history_deleted))

    async def _check_and_set_dh_values(self, version: int, p: bytes, g: int) -> None:
        dh_prime = int.from_bytes(p, "big")
        SecretSecurityException.check(2 <= g <= 7, "2 <= g <= 7")
        SecretSecurityException.check(2 ** 2047 < dh_prime < 2 ** 2048, "2 ** 2047 < dh_prime < 2 ** 2048")
        x = dh_prime % (4 * g)
        SecretSecurityException.check(x < (4 * g), "x < (4 * g)")
        if g == 2:
            SecretSecurityException.check(x == 7, "x == 7")
        elif g == 3:
            SecretSecurityException.check((x % 3) == 2, "(x % 3) == 2")
        elif g == 5:
            SecretSecurityException.check((x % 5) in (1, 4), "(x % 5) in (1, 4)")
        elif g == 6:
            SecretSecurityException.check(x in (19, 23), "x in (19, 23)")
        elif g == 7:
            SecretSecurityException.check((x % 7) in (3, 5, 6), "(x % 7) in (3, 5, 6)")

        # TODO: check if both dh_prime and (dh_prime - 1) / 2 are prime numbers

        await self._storage.set_dh_config(version, p, g)

    async def _get_dh_config(self) -> SecretDhConfig:
        local_config = await self._storage.get_dh_config(None)
        dh_version = local_config.version if local_config is not None else 0

        dh_config = await self._adapter.get_dh_config(dh_version)
        if isinstance(dh_config, DhConfigA):
            await self._check_and_set_dh_values(dh_config.version, dh_config.p, dh_config.g)
            return await self._storage.get_dh_config(dh_config.version)

        if isinstance(dh_config, DhConfigNotModifiedA):
            if local_config is not None:
                return local_config

            dh_config = await self._adapter.get_dh_config(dh_version - 1)
            if not isinstance(dh_config, DhConfigA):
                raise ValueError("Client does not have dh values locally and server still returns NotModified")

            await self._check_and_set_dh_values(dh_config.version, dh_config.p, dh_config.g)
            return await self._storage.get_dh_config(dh_config.version)

        raise RuntimeError(f"Expected DhConfig or DhConfigNotModified, got {dh_config}")

    async def _gen_key_from_g_a(self, dh_version: int | None, g_a_bytes: bytes) -> tuple[bytes, bytes, int, int]:
        if dh_version is None:
            dh = await self._get_dh_config()
        else:
            dh = await self._storage.get_dh_config(dh_version)

        dh_prime = int.from_bytes(dh.p, "big")
        g_a = int.from_bytes(g_a_bytes, "big")

        SecretSecurityException.check(1 < g_a < dh_prime - 1, "1 < g_a < dh_prime - 1")
        SecretSecurityException.check(
            2 ** (2048 - 64) < g_a < dh_prime - 2 ** (2048 - 64),
            "2 ** (2048 - 64) < g_a < dh_prime - 2 ** (2048 - 64)"
        )

        b = int.from_bytes(urandom(2048 // 8), "big")
        g_b = pow(dh.g, b, dh_prime).to_bytes(256, "big")
        key = pow(g_a, b, dh_prime).to_bytes(256, "big")
        key_fingerprint = sha1(key).digest()[-8:]
        key_fingerprint = read_long(key_fingerprint)

        return g_b, key, key_fingerprint, dh.version

    async def _accept_chat(self, chat: EncryptedChatRequestedA) -> None:
        g_b, key, key_fingerprint, dh_version = await self._gen_key_from_g_a(None, chat.g_a)

        new_chat = await self._adapter.accept_encryption(chat.id, chat.access_hash, g_b, key_fingerprint)

        SecretSecurityException.check(
            new_chat.g_a_or_b == chat.g_a, "new_chat.g_a_or_b == chat.g_a",
        )
        SecretSecurityException.check(
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
            self._loop.create_task(handler(secret_chat))

    async def discard_chat(self, chat_id: int, delete_history: bool = False) -> None:
        await self._adapter.discard_encryption(chat_id, delete_history)
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
        exchange_id = read_long(urandom(8))

        await self._storage.update_chat(chat, a=a_bytes, exchange_id=exchange_id)
        await self._send_service_message(chat_id, DecryptedMessageActionRequestKey(exchange_id=exchange_id, g_a=g_a))

    async def _send_service_message(self, chat_id: int, action: DecryptedMessageAction) -> None:
        random_id = read_long(urandom(8))
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
        if (chat.key_used > 10 or (time() - chat.key_created_at) > 86400 * 7) and chat.exchange_id is None:
            await self.rekey(chat.id)

    async def _just_send_message(
            self,
            chat: SecretChat,
            message: DecryptedMessageLayer,
            random_id: int,
            file: InputFileA | InputFileBigA | InputExistingFileA | None,
            file_key_fp: int | None,
            silent: bool,
    ) -> EncryptedFileA | None:
        key = await self._get_or_switch_chat_key(chat)

        message_to_encrypt = message.write()
        to_encrypt = (
                write_int(len(message_to_encrypt))
                + message_to_encrypt
                + urandom(randint(12, 512) // 4 * 4)
        )
        to_encrypt += b"\x00" * (-len(to_encrypt) % 16)

        msg_key = msg_key_v2(key, to_encrypt, chat.originator)
        aes_key, aes_iv = kdf_v2(key, msg_key, chat.originator)
        encrypted_payload = ige256_encrypt(to_encrypt, aes_key, aes_iv)

        final_payload = write_long(chat.key_fp) + msg_key + encrypted_payload

        peer = InputEncryptedChatA(chat_id=chat.id, access_hash=chat.access_hash)
        if isinstance(message.message, decrypted_message_service_clss):
            await self._adapter.send_encrypted_service(peer, random_id, final_payload)
        elif isinstance(message.message, decrypted_message_clss):
            if file is not None and file_key_fp is not None:
                return await self._adapter.send_encrypted_file(
                    peer, random_id, final_payload, silent, file, file_key_fp,
                )
            else:
                await self._adapter.send_encrypted(peer, random_id, final_payload, silent)
        else:
            raise ValueError(
                f"Expected DecryptedMessage or DecryptedMessageService, got {message.message.__class__.__name__}"
            )

    async def _send_message(
            self,
            chat_id: int,
            decrypted_message: SecretTLObject,
            random_id: int,
            file: InputFileA | InputFileBigA | None = None,
            file_key_fp: int | None = None,
            *,
            silent: bool = False,
    ) -> EncryptedFileA | None:
        chat = await self._storage.get_chat(chat_id)
        if chat.state is not ChatState.READY:
            raise SecretChatNotReadyException

        await self._storage.update_chat(chat, key_used=chat.key_used + 1)
        old_out_seq = await self._storage.inc_chat_out_seq_no(chat_id)

        message = DecryptedMessageLayer(
            random_bytes=urandom(randint(16, 32)),
            layer=min(chat.this_layer, max(46, chat.peer_layer)),
            in_seq_no=self._gen_in_out_seq_no(chat.in_seq_no, False, chat.originator),
            out_seq_no=self._gen_in_out_seq_no(old_out_seq, True, chat.originator),
            message=decrypted_message,
        )

        file_maybe = await self._just_send_message(chat, message, random_id, file, file_key_fp, silent)
        file_id = file_maybe.id if file_maybe else None
        file_hash = file_maybe.access_hash if file_maybe else None

        await self._storage.store_out_message(
            chat.id, message.out_seq_no, message.write(), file_id, file_hash, file_key_fp, silent
        )
        await self._maybe_start_rekeying(chat)

        return file_maybe

    @staticmethod
    def _get_file_key_fp(key: bytes, iv: bytes) -> int:
        key_digest = md5(key + iv).digest()
        key_fp_bytes = bytes(a ^ b for a, b in zip(key_digest[:4], key_digest[4:8]))
        return read_int(key_fp_bytes)

    async def _handle_encrypted_update(self, message: EncryptedMessageA | EncryptedMessageServiceA) -> None:
        if isinstance(message, EncryptedMessageServiceA):
            message = cast(EncryptedMessageServiceA, message)
            is_service = True
            chat_id = message.chat_id
            data = message.bytes
            file = None
        elif isinstance(message, EncryptedMessageA):
            # For some reason pycharm cant understand that if isinstance check succeeded,
            #  then `message` is EncryptedMessage and still thinks that `message` is "base" type,
            #  so doing typing-cast here.
            # It can be removed after pycharm stops complaining about
            #  "Unresolved attribute reference '...' for class 'EncryptedMessage'"
            message = cast(EncryptedMessageA, message)
            is_service = False
            chat_id = message.chat_id
            data = message.bytes
            file = message.file
        else:
            raise ValueError(
                f"Expected EncryptedMessage or EncryptedMessageService, got {message.__class__.__name__}"
            )

        chat = await self._storage.get_chat(chat_id)
        key_fp = read_long(data)
        key = await self._get_or_switch_chat_key(chat, key_fp)

        data = data[8:]
        msg_key = data[:128 // 8]
        data = data[128 // 8:]

        aes_key, aes_iv = kdf_v2(key, msg_key, not chat.originator)
        decrypted_payload = ige256_decrypt(data, aes_key, aes_iv)

        length = read_int(decrypted_payload)
        decrypted_payload = decrypted_payload[4:]
        # Payload type + random bytes (at least 128 bits) + layer + in_seq_no + out_seq_no + message type + padding (at least 12 bytes)
        if length < (4 + 128 // 8 + 4 + 4 + 4 + 4 + 12) or len(decrypted_payload) < length:
            return

        payload = decrypted_payload[:length]
        obj = SecretTLObject.read(BytesIO(payload))
        if not isinstance(obj, DecryptedMessageLayer):
            return

        remote_x_out = 1 if not chat.originator else 0
        if obj.out_seq_no % 2 != remote_x_out:
            await self.discard_chat(chat_id, False)
            return

        remote_local_out_seq_no = (obj.out_seq_no - remote_x_out) // 2
        if remote_local_out_seq_no < chat.in_seq_no:
            return
        elif remote_local_out_seq_no > chat.in_seq_no:
            if self._gaps_strategy is GapsStrategy.IGNORE:
                await self._storage.update_chat(chat, in_seq_no=remote_local_out_seq_no)
            elif self._gaps_strategy is GapsStrategy.FILL:
                await self._storage.store_in_message(
                    chat_id=chat.id,
                    out_seq_no=remote_local_out_seq_no,
                    data=obj.message.write(),
                    file_id=file.id if file is not None else None,
                    file_dc=file.dc_id if file is not None else None,
                    file_size=file.size if file is not None else None,
                    file_hash=file.access_hash if file is not None else None,
                    file_key_fp=file.key_fingerprint if file is not None else None,
                    is_service=is_service,
                )

                await self._send_resend_request(chat.id, chat.in_seq_no, remote_local_out_seq_no - 1)
                return

        await self._storage.update_chat(chat, key_used=chat.key_used + 1)
        await self._storage.inc_chat_in_seq_no(chat_id)
        await self._process_decrypted_message(chat, obj.message, is_service, file)

        remote_out_seq_no = remote_local_out_seq_no + 1
        while (in_message := await self._storage.get_and_delete_in_message(chat.id, remote_out_seq_no)) is not None:
            new_message = SecretTLObject.read(BytesIO(in_message.message))
            if not isinstance(new_message, DecryptedMessageInst):
                await self._storage.update_chat(chat, in_seq_no=remote_out_seq_no)
                continue

            file = EncryptedFileA(
                id=in_message.file_id,
                access_hash=in_message.file_hash,
                size=in_message.file_size,
                dc_id=in_message.file_dc,
                key_fingerprint=in_message.file_key_fp,
            ) if in_message.file_id is not None else None

            await self._storage.update_chat(chat, key_used=chat.key_used + 1)
            await self._storage.inc_chat_in_seq_no(chat_id)
            await self._process_decrypted_message(chat, new_message, in_message.is_service, file)

            remote_out_seq_no += 1

        await self._maybe_start_rekeying(chat)

    async def _process_decrypted_message(
            self, chat: SecretChat, message: DecryptedMessage, is_service: bool, file: EncryptedFileA,
    ) -> None:
        if is_service:
            if not isinstance(message, decrypted_message_service_clss):
                raise ValueError(
                    f"Expected DecryptedMessageService, got {message.__class__.__name__}"
                )
            await self._handle_encrypted_service_message(chat.id, message)
        else:
            if not isinstance(message, decrypted_message_clss):
                raise ValueError(
                    f"Expected DecryptedMessage, got {message.__class__.__name__}"
                )
            await self._handle_encrypted_message(chat.id, message, file)

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

    async def _send_resend_request(self, chat_id: int, start_seq_no: int, end_seq_no: int) -> None:
        await self._send_service_message(chat_id, DecryptedMessageActionResend(
            start_seq_no=start_seq_no,
            end_seq_no=end_seq_no,
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
            except SecretSecurityException:
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
            key_fingerprint = read_long(key_fingerprint)

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
                    fut_key=None,
                    fut_key_fp=None,
                )
            else:
                await self._storage.update_chat(chat, exchange_id=None, a=None, fut_key=None, fut_key_fp=None)
                return await self._send_abort_key(chat.id, action.exchange_id)
        elif isinstance(action, DecryptedMessageActionAbortKey):
            await self._storage.update_chat(chat, exchange_id=None, a=None, fut_key=None, fut_key_fp=None)
        elif isinstance(action, DecryptedMessageActionDeleteMessages):
            secret_chat = await self.get_chat(chat.id)
            for handler in self._on_messages_deleted_handlers:
                self._loop.create_task(handler(secret_chat, action.random_ids))
        elif isinstance(action, DecryptedMessageActionFlushHistory):
            secret_chat = await self.get_chat(chat.id)
            for handler in self._on_history_deleted_handlers:
                self._loop.create_task(handler(secret_chat))
        elif isinstance(action, DecryptedMessageActionNoop):
            ...
        elif isinstance(action, DecryptedMessageActionNotifyLayer):
            if chat.peer_layer >= action.layer:
                return
            await self._storage.update_chat(chat, peer_layer=action.layer)
        elif isinstance(action, DecryptedMessageActionReadMessages):
            ...
        elif isinstance(action, DecryptedMessageActionResend):
            start = action.start_seq_no
            end = action.end_seq_no
            if start > end or start < 0 or end < 0:
                return

            for out_message in await self._storage.get_out_messages(chat.id, start, end):
                message = SecretTLObject.read(BytesIO(out_message.message))
                if not isinstance(message, DecryptedMessageLayer):
                    continue

                random_id = read_long(urandom(8))

                file = InputExistingFileA(
                    id=out_message.file_id,
                    access_hash=out_message.file_hash,
                ) if out_message.file_id is not None and out_message.file_hash is not None else None

                await self._just_send_message(
                    chat, message, random_id, file, out_message.file_key_fp, out_message.silent,
                )
        elif isinstance(action, DecryptedMessageActionScreenshotMessages):
            ...
        elif isinstance(action, DecryptedMessageActionSetMessageTTL):
            ...
        elif isinstance(action, DecryptedMessageActionTyping):
            ...
        else:
            raise ValueError(f"Excepted DecryptedMessageAction, got {action.__class__.__name__}")

    async def _handle_encrypted_message(
            self,
            chat_id: int,
            message: DecryptedMessage_8 | DecryptedMessage_17 | DecryptedMessage_45 | DecryptedMessage_73,
            file: EncryptedFileA | None,
    ) -> None:
        if isinstance(message, (DecryptedMessage_73, DecryptedMessage_45)):
            reply_to = message.reply_to_random_id
            entities = message.entities
        else:
            reply_to = None
            entities = []

        media = message.media if not isinstance(message.media, DecryptedMessageMediaEmpty) else None

        if media is None:
            media_has_key = False
        else:
            _media = cast(DecryptedMessageMediaDocument_8, media)
            media_has_key = "key" in _media.__slots__ and "iv" in _media.__slots__
        SecretSecurityException.check((file is not None) == media_has_key, "(file is not None) == media_has_key")

        if media_has_key:
            _media = cast(DecryptedMessageMediaDocument_8, media)
            key_fp = self._get_file_key_fp(_media.key, _media.iv)
            SecretSecurityException.check(file.key_fingerprint == key_fp, "file.key_fingerprint == key_fp")

        secret_chat = await self.get_chat(chat_id)
        new_message = SecretMessage(
            random_id=message.random_id,
            chat=secret_chat,
            from_id=secret_chat.peer_id,
            text=message.message,
            entities=entities,
            reply_to_random_id=reply_to,
            media=media,
            file=file,
            _client=self,
        )

        for handler in self._on_new_message_handlers:
            self._loop.create_task(handler(new_message))

    async def get_chat(self, chat_id: int) -> TypesSecretChat | None:
        chat = await self._storage.get_chat(chat_id)
        if chat is None:
            return None

        return TypesSecretChat._from_storage_chat(chat, self)

    async def delete_messages(self, chat_id: int, random_id: int | list[int]) -> None:
        await self._send_service_message(chat_id, DecryptedMessageActionDeleteMessages(
            random_ids=random_id if isinstance(random_id, list) else [random_id],
        ))

    async def delete_chat_history(self, chat_id: int) -> None:
        await self._send_service_message(chat_id, DecryptedMessageActionFlushHistory())

    async def _send_chat_message(
            self,
            chat: SecretChat,
            text: str,
            file: InputFileA | InputFileBigA | None,
            file_key_fp: int | None,
            media: DecryptedMessageMedia | None,
            entities: list[MessageEntity],
            ttl: int,
            disable_web_page_preview: bool,
            disable_notification: bool,
            via_bot_name: str | None,
            reply_to_random_id: int | None,
    ) -> ...:
        random_id = read_long(urandom(8))
        if chat.peer_layer >= 73:
            request = DecryptedMessage_73(
                random_id=random_id,
                message=text,
                entities=entities or None,
                ttl=ttl,
                no_webpage=disable_web_page_preview,
                via_bot_name=via_bot_name,
                reply_to_random_id=reply_to_random_id,
                media=media,
            )
        elif chat.peer_layer >= 45:
            request = DecryptedMessage_45(
                random_id=random_id,
                message=text,
                entities=entities or None,
                ttl=ttl,
                via_bot_name=via_bot_name,
                reply_to_random_id=reply_to_random_id,
                media=media,
            )
        elif chat.peer_layer >= 17:
            reply_to_random_id = None
            request = DecryptedMessage_17(
                random_id=random_id,
                message=text,
                ttl=ttl,
                media=media or DecryptedMessageMediaEmpty(),
            )
        elif chat.peer_layer >= 8:
            reply_to_random_id = None
            request = DecryptedMessage_8(
                random_id=random_id,
                message=text,
                random_bytes=urandom(16),
                media=media or DecryptedMessageMediaEmpty(),
            )
        else:
            raise SecretLayerException("messages (?)", chat.peer_layer, 8)

        file_maybe = await self._send_message(
            chat.id, request, random_id, file, file_key_fp, silent=disable_notification,
        )

        return SecretMessage(
            random_id=random_id,
            chat=await self.get_chat(chat.id),
            from_id=chat.admin_id if chat.originator else chat.participant_id,
            text=text,
            entities=entities,
            reply_to_random_id=reply_to_random_id,
            media=media,
            file=file_maybe,
            _client=self,
        )

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

        message, entities = await self._adapter.parse_entities_for_layer(text, chat.peer_layer, parse_mode)

        return await self._send_chat_message(
            chat, message, None, None, None, entities, ttl, disable_web_page_preview, disable_notification,
            via_bot_name, reply_to_message_id,
        )

    async def send_document(
            self,
            chat_id: int,
            file: str | BinaryIO,
            caption: str | None = None,
            ttl: int = 0,
            disable_web_page_preview: bool = False,
            disable_notification: bool = False,
            via_bot_name: str | None = None,
            reply_to_message_id: int | None = None,
            parse_mode: ParseMode | None = None,
            file_name: str | None = None,
    ) -> SecretMessage:
        chat = await self._storage.get_chat(chat_id)
        if chat.state is not ChatState.READY:
            raise SecretChatNotReadyException

        key = urandom(32)
        iv = urandom(32)

        key_fp = self._get_file_key_fp(key, iv)

        with ExitStack() as exit_stack:
            if isinstance(file, (str, PurePath)):
                fp = open(file, "rb")
                exit_stack.enter_context(fp)
                file_name = file_name or basename(file)
            elif isinstance(file, IOBase):
                fp = file
                file_name = file_name or getattr(file, "name", "unknown.bin")
            else:
                raise ValueError("Invalid file. Expected a file path as string or a binary (not text) file pointer")

            fp.seek(0, io.SEEK_END)
            file_size = fp.tell()
            fp.seek(0)

            wrapper = EncryptedFileWrapper(fp, key, iv, True)
            input_file = await self._adapter.upload_file(wrapper)

        if caption:
            message, entities = await self._adapter.parse_entities_for_layer(caption, chat.peer_layer, parse_mode)
        else:
            message = ""
            entities = []

        mime_type = await self._adapter.get_file_mime(file_name, fp)
        fp.seek(0)

        if chat.peer_layer >= 143:
            media = DecryptedMessageMediaDocument_143(
                # TODO: document thumbnail
                thumb=b"",
                thumb_w=0,
                thumb_h=0,
                mime_type=mime_type,
                size=file_size,
                key=key,
                iv=iv,
                attributes=[DocumentAttributeFilename(file_name=file_name)],
                caption=message,
            )
        elif chat.peer_layer >= 45:
            media = DecryptedMessageMediaDocument_45(
                # TODO: document thumbnail
                thumb=b"",
                thumb_w=0,
                thumb_h=0,
                mime_type=mime_type,
                size=file_size,
                key=key,
                iv=iv,
                attributes=[DocumentAttributeFilename(file_name=file_name)],
                caption=message,
            )
        elif chat.peer_layer >= 8:
            media = DecryptedMessageMediaDocument_8(
                # TODO: document thumbnail
                thumb=b"",
                thumb_w=0,
                thumb_h=0,
                file_name=file_name,
                mime_type=mime_type,
                size=file_size,
                key=key,
                iv=iv,
            )
        else:
            raise SecretLayerException("media", chat.peer_layer, 8)

        return await self._send_chat_message(
            chat, message, input_file, key_fp, media, entities, ttl, disable_web_page_preview, disable_notification,
            via_bot_name, reply_to_message_id,
        )

    # TODO: sending photos, audios, videos, contacts
    # TODO: downloading media

    async def get_chat_ids(self) -> list[int]:
        return await self._storage.get_chat_ids()

    async def iter_chats(self) -> AsyncGenerator[SecretChat, None, None]:
        for chat_id in await self.get_chat_ids():
            yield await self._storage.get_chat(chat_id)

    async def get_chats(self) -> list[SecretChat]:
        return list(chat async for chat in self.iter_chats())

    async def get_chat_by_user(self, peer_id: int) -> SecretChat | None:
        chat = await self._storage.get_chat_by_peer(peer_id)
        if chat is None:
            return None

        return TypesSecretChat._from_storage_chat(chat, self)

    async def request_encryption(self, peer_id: int | str) -> TypesSecretChat | None:
        dh = await self._get_dh_config()
        dh_prime = int.from_bytes(dh.p, "big")

        a_bytes = urandom(2048 // 8)
        a = int.from_bytes(a_bytes, "big")
        g_a = pow(dh.g, a, dh_prime).to_bytes(2048 // 8, "big")

        peer = await self._adapter.resolve_user(peer_id)
        if peer is None:
            raise ValueError("Unknown user!")

        chat = await self._adapter.request_encryption(peer, read_long(urandom(4)), g_a)
        if chat is None:
            return None

        await self._storage.add_chat(
            chat.id,
            access_hash=chat.access_hash,
            created_at=chat.date,
            admin_id=chat.admin_id,
            participant_id=chat.participant_id,
            state=ChatState.WAITING,
            originator=True,
            peer_layer=46,
            this_layer=46,
        )

        await self._storage.update_chat(chat.id, a=a_bytes)

        return await self.get_chat(chat.id)
