from __future__ import annotations

from hashlib import sha1
from io import BytesIO
from os import urandom
from pathlib import Path
from random import randint
from typing import TYPE_CHECKING, Awaitable, Any, Callable, cast

from pyrogram.errors import SecurityCheckMismatch
from pyrogram.methods.utilities.idle import idle
from pyrogram.raw.core import Int
from pyrogram.raw.functions.messages import DiscardEncryption, GetDhConfig, AcceptEncryption, SendEncryptedService, \
    SendEncrypted
from pyrogram.raw.types import User, UpdateEncryption, EncryptedChatRequested, InputEncryptedChat, EncryptedChat, \
    EncryptedChatDiscarded, UpdateNewEncryptedMessage, EncryptedMessageService, EncryptedMessage
from pyrogram.raw.types.messages import DhConfig, DhConfigNotModified
from tgcrypto import ige256_encrypt, ige256_decrypt

from .enums import ChatState, ChatRequestResult
from .raw import SecretTLObject
from .raw.all import layer
from .raw.types import DecryptedMessageService_17, DecryptedMessageActionNotifyLayer, DecryptedMessageLayer, \
    DecryptedMessageService_8, DecryptedMessage_17, DecryptedMessage_45, DecryptedMessage_73, DecryptedMessage_8, \
    DecryptedMessageActionAbortKey, DecryptedMessageActionAcceptKey, DecryptedMessageActionCommitKey, \
    DecryptedMessageActionDeleteMessages, DecryptedMessageActionFlushHistory, DecryptedMessageActionNoop, \
    DecryptedMessageActionReadMessages, DecryptedMessageActionRequestKey, DecryptedMessageActionResend, \
    DecryptedMessageActionScreenshotMessages, DecryptedMessageActionSetMessageTTL, DecryptedMessageActionTyping
from .storage import MemoryStorage, FileStorage
from .utils import msg_key_v2, kdf_v2

if TYPE_CHECKING:
    from pyrogram import Client

# TODO: replace client.log_out to also remove secret database file
# TODO: allow using same session file as pyrogram
# TODO: wrap EncryptedChat into class that stores user/chat info not in raw format, adds methods like ".send_message", etc.

ChatRequestFuncT = Callable[[EncryptedChatRequested, User], Awaitable[ChatRequestResult]]
ChatReadyFuncT = Callable[[EncryptedChat], Awaitable[Any]]

decrypted_message_clss = (DecryptedMessage_8, DecryptedMessage_17, DecryptedMessage_45, DecryptedMessage_73)
decrypted_message_service_clss = (DecryptedMessageService_8, DecryptedMessageService_17)


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
            await self._storage.set_chat(
                chat.id,
                access_hash=chat.access_hash,
                created_at=chat.date,
                admin_id=chat.admin_id,
                participant_id=chat.participant_id,
                state=ChatState.REQUESTED,
                originator=False,
                peer_layer=0,
                this_layer=0,
                in_seq_no=0,
                out_seq_no=0,
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
        key_fingerprint = int.from_bytes(key_fingerprint, "little", signed=True)

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

        await self._storage.set_chat(
            new_chat.id,
            access_hash=new_chat.access_hash,
            created_at=new_chat.date,
            admin_id=new_chat.admin_id,
            participant_id=new_chat.participant_id,
            state=ChatState.READY,
            originator=False,
            peer_layer=0,
            this_layer=layer,
            in_seq_no=0,
            out_seq_no=0,
        )

        await self._storage.add_key(new_chat.id, key)

        await self._notify_about_layer(new_chat.id)

        for handler in self._on_ready_handlers:
            await handler(new_chat)

    async def _discard_chat(self, chat: EncryptedChatRequested) -> None:
        await self._client.invoke(DiscardEncryption(chat_id=chat.id))
        await self._storage.delete_chat(chat.id)

    async def _notify_about_layer(self, chat_id: int) -> None:
        await self._send_message(
            chat_id,
            DecryptedMessageService_17(
                random_id=int.from_bytes(urandom(8), "little", signed=True),
                action=DecryptedMessageActionNotifyLayer(
                    layer=layer,
                ),
            )
        )

    @staticmethod
    def _gen_in_out_seq_no(seq_no: int, out: bool, originator: bool):
        return seq_no * 2 + (1 if out == originator else 0)

    # TODO: SendEncryptedFile
    async def _send_message(self, chat_id: int, decrypted_message: SecretTLObject) -> None:
        # TODO: check if state is READY
        chat = await self._storage.get_chat(chat_id)
        key_id, key, _ = await self._storage.get_key(chat.id)

        await self._storage.inc_key(key_id)
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

        key_fingerprint = sha1(key).digest()[-8:]
        final_payload = key_fingerprint + msg_key + encrypted_payload

        peer = InputEncryptedChat(chat_id=chat_id, access_hash=chat.hash)

        if isinstance(decrypted_message, decrypted_message_service_clss):
            request = SendEncryptedService(
                peer=peer,
                random_id=int.from_bytes(urandom(8), "little", signed=True),
                data=final_payload,
            )
        elif isinstance(decrypted_message, decrypted_message_clss):
            request = SendEncrypted(
                peer=peer,
                random_id=int.from_bytes(urandom(8), "little", signed=True),
                data=final_payload,
                # TODO: silent
            )
        else:
            raise ValueError(
                f"Expected DecryptedMessage or DecryptedMessageService, got {decrypted_message.__class__.__name__}"
            )

        await self._client.invoke(request)

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

        # TODO: check if state is READY
        chat = await self._storage.get_chat(chat_id)
        key_id, key, _ = await self._storage.get_key(chat.id, data[:8])

        key_fingerprint = sha1(key).digest()[-8:]
        if data[:8] != key_fingerprint:
            return

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

        # TODO: check seq_no

        await self._storage.inc_key(key_id)
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

    async def _handle_encrypted_service_message(
            self, chat_id: int, message: DecryptedMessageService_8 | DecryptedMessageService_17
    ) -> None:
        action = message.action

        if isinstance(action, DecryptedMessageActionAbortKey):
            ...  # TODO: re-keying
        elif isinstance(action, DecryptedMessageActionAcceptKey):
            ...  # TODO: re-keying
        elif isinstance(action, DecryptedMessageActionCommitKey):
            ...  # TODO: re-keying
        elif isinstance(action, DecryptedMessageActionRequestKey):
            ...  # TODO: re-keying
        elif isinstance(action, DecryptedMessageActionDeleteMessages):
            ...
        elif isinstance(action, DecryptedMessageActionFlushHistory):
            ...
        elif isinstance(action, DecryptedMessageActionNoop):
            ...
        elif isinstance(action, DecryptedMessageActionNotifyLayer):
            chat = await self._storage.get_chat(chat_id)
            if chat.peer_layer >= action.layer:
                return
            await self._storage.set_chat(chat_id, peer_layer=action.layer)
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
        print(f"{chat_id}: {message.message}")
        await self.send_text_message(chat_id, message.message)

    # TODO: return message object
    # TODO: allow sending by user id
    async def send_text_message(self, chat_id: int, text: str) -> None:
        await self._send_message(
            chat_id,
            DecryptedMessage_73(
                random_id=int.from_bytes(urandom(8), "little", signed=True),
                message=text,
                ttl=0,
            )
        )








