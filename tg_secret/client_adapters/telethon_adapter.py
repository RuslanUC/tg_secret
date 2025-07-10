import warnings
from typing import cast, BinaryIO

from pyrogram.raw.functions.messages import RequestEncryption
from telethon import TelegramClient, events
from telethon.tl.functions.messages import GetDhConfigRequest, AcceptEncryptionRequest, DiscardEncryptionRequest, \
    SendEncryptedRequest, SendEncryptedServiceRequest, SendEncryptedFileRequest, ReceivedQueueRequest, \
    RequestEncryptionRequest
from telethon.tl.types import EncryptedChat, InputEncryptedChat, InputEncryptedFileUploaded, \
    InputEncryptedFileBigUploaded, MessageEntityBold, MessageEntityItalic, MessageEntityUnderline, MessageEntityStrike, \
    MessageEntityBlockquote, MessageEntityCode, MessageEntityPre, MessageEntitySpoiler, MessageEntityTextUrl, \
    MessageEntityCustomEmoji, UpdateEncryption, UpdateNewEncryptedMessage, EncryptedMessage, EncryptedMessageService, \
    EncryptedFileEmpty, EncryptedFile, EncryptedChatRequested, EncryptedChatDiscarded, InputFile, InputFileBig, \
    InputEncryptedFile, InputPeerUser, EncryptedChatWaiting, InputUser
from telethon.tl.types.messages import DhConfig, DhConfigNotModified, SentEncryptedFile
from telethon.utils import get_attributes

from tg_secret.client_adapters.base_adapter import SecretClientAdapter, DhConfigA, \
    DhConfigNotModifiedA, EncryptedChatA, InputEncryptedChatA, ParseModeA, NewEncryptedMessageFuncT, EncryptedMessageA, \
    EncryptedMessageServiceA, EncryptedFileA, NewChatUpdateFuncT, NewChatRequestedFuncT, NewChatDiscardedFuncT, \
    EncryptedChatRequestedA, InputFileA, InputFileBigA, InputExistingFileA, InputPeerUserA, EncryptedChatWaitingA
from tg_secret.encrypted_file_wrapper import EncryptedFileWrapper
from tg_secret.raw.base import MessageEntity
from tg_secret.raw.types import MessageEntityBold as SecretEntityBold, MessageEntityItalic as SecretEntityItalic, \
    MessageEntityUnderline as SecretEntityUnderline, MessageEntityStrike as SecretEntityStrike, \
    MessageEntityBlockquote as SecretEntityBlockquote, MessageEntityCode as SecretEntityCode, \
    MessageEntityPre as SecretEntityPre, MessageEntitySpoiler as SecretEntitySpoiler, \
    MessageEntityTextUrl as SecretEntityTextUrl, MessageEntityCustomEmoji as SecretEntityCustomEmoji

_parse_mode_a_to_telethon = {
    ParseModeA.DISABLED: None,
    ParseModeA.DEFAULT: (),
    ParseModeA.MARKDOWN: "markdown",
    ParseModeA.HTML: "html",
}


_entities_mapping = {
    MessageEntityBold: SecretEntityBold,
    MessageEntityItalic: SecretEntityItalic,
    MessageEntityUnderline: SecretEntityUnderline,
    MessageEntityStrike: SecretEntityStrike,
    MessageEntityBlockquote: SecretEntityBlockquote,
    MessageEntityCode: SecretEntityCode,
    MessageEntityPre: SecretEntityPre,
    MessageEntitySpoiler: SecretEntitySpoiler,
    MessageEntityTextUrl: SecretEntityTextUrl,
    MessageEntityCustomEmoji: SecretEntityCustomEmoji,
}

_entities_min_layers = {
    SecretEntityUnderline: 144,
    SecretEntityStrike: 144,
    SecretEntityBlockquote: 144,
    SecretEntitySpoiler: 144,
    SecretEntityCustomEmoji: 144,
}

def _get_entities_with_layer(entities: list[...], peer_layer: int) -> list[MessageEntity]:
    if peer_layer < 45 or not entities:
        return []

    result = []
    for entity in entities:
        secret_entity_cls = _entities_mapping.get(type(entity))
        if secret_entity_cls is None:
            continue
        if _entities_min_layers.get(secret_entity_cls, 0) > peer_layer:
            continue

        kwargs = {}
        for slot in secret_entity_cls.__slots__:
            kwargs[slot] = getattr(entity, slot)

        result.append(secret_entity_cls(**kwargs))

    return result


class TelethonClientAdapter(SecretClientAdapter):
    __slots__ = (
        "client", "new_message_handler", "chat_update_handler", "chat_requested_handler", "chat_discarded_handler",
        "raw_handler_set",
    )

    def __init__(self, client: TelegramClient):
        # TODO: remove warning when telethon adapter is tested
        warnings.warn("Telethon client adapter is not tested yet, it may work incorrectly or be completely broken.")

        self.client = client
        self.new_message_handler: NewEncryptedMessageFuncT | None = None
        self.chat_update_handler: NewChatUpdateFuncT | None = None
        self.chat_requested_handler: NewChatRequestedFuncT | None = None
        self.chat_discarded_handler: NewChatDiscardedFuncT | None = None
        self.raw_handler_set = False

    async def get_dh_config(self, version: int) -> DhConfigA | DhConfigNotModifiedA | None:
        dh_config: DhConfig = await self.client(GetDhConfigRequest(version=version, random_length=0))
        if isinstance(dh_config, DhConfig):
            return DhConfigA(version=dh_config.version, p=dh_config.p, g=dh_config.g)
        if isinstance(dh_config, DhConfigNotModified):
            return DhConfigNotModifiedA()

    async def accept_encryption(
            self, chat_id: int, access_hash: int, g_b: bytes, key_fingerprint: int,
    ) -> EncryptedChatA | None:
        accepted_chat: EncryptedChat = await self.client(AcceptEncryptionRequest(
            peer=InputEncryptedChat(chat_id=chat_id, access_hash=access_hash),
            g_b=g_b,
            key_fingerprint=key_fingerprint,
        ))

        if not isinstance(accepted_chat, EncryptedChat):
            raise ValueError(f"Expected server to return EncryptedChat, got {accepted_chat.__class__.__name__}")

        return EncryptedChatA(
            id=accepted_chat.id,
            g_a_or_b=accepted_chat.g_a_or_b,
            key_fingerprint=accepted_chat.key_fingerprint,
        )

    async def discard_encryption(self, chat_id: int, delete_history: bool) -> None:
        await self.client(DiscardEncryptionRequest(chat_id=chat_id, delete_history=delete_history))

    async def send_encrypted(self, peer: InputEncryptedChatA, random_id: int, data: bytes, silent: bool) -> None:
        await self.client(SendEncryptedRequest(
            peer=InputEncryptedChat(chat_id=peer.chat_id, access_hash=peer.access_hash),
            random_id=random_id,
            data=data,
            silent=silent,
        ))

    async def send_encrypted_service(self, peer: InputEncryptedChatA, random_id: int, data: bytes) -> None:
        await self.client(SendEncryptedServiceRequest(
            peer=InputEncryptedChat(chat_id=peer.chat_id, access_hash=peer.access_hash),
            random_id=random_id,
            data=data,
        ))

    async def send_encrypted_file(
            self, peer: InputEncryptedChatA, random_id: int, data: bytes, silent: bool,
            file: InputFileA | InputFileBigA | InputExistingFileA, key_fingerprint: int,
    ) -> EncryptedFileA:
        if isinstance(file, InputFileA):
            input_file = InputEncryptedFileUploaded(
                id=file.id,
                parts=file.parts,
                md5_checksum=file.md5_checksum,
                key_fingerprint=key_fingerprint,
            )
        elif isinstance(file, InputFileBigA):
            input_file = InputEncryptedFileBigUploaded(
                id=file.id,
                parts=file.parts,
                key_fingerprint=key_fingerprint,
            )
        elif isinstance(file, InputExistingFileA):
            input_file = InputEncryptedFile(
                id=file.id,
                access_hash=file.access_hash,
            )
        else:
            raise ValueError(
                f"Expected InputFileUploadedA, or InputFileBigUploadedA, or InputExistingFileA, "
                f"got {file.__class__.__name__}"
            )

        sent_message: SentEncryptedFile = await self.client(SendEncryptedFileRequest(
            peer=InputEncryptedChat(chat_id=peer.chat_id, access_hash=peer.access_hash),
            random_id=random_id,
            data=data,
            file=input_file,
            silent=silent,
        ))

        if not isinstance(sent_message, SentEncryptedFile):
            raise ValueError(f"Excepted SentEncryptedFile, got {sent_message.__class__.__name__}")
        encrypted_file = cast(EncryptedFile, sent_message.file)
        if not isinstance(encrypted_file, EncryptedFile):
            raise ValueError(f"Excepted EncryptedFile, got {encrypted_file.__class__.__name__}")

        return EncryptedFileA(
            id=encrypted_file.id,
            access_hash=encrypted_file.access_hash,
            size=encrypted_file.size,
            dc_id=encrypted_file.dc_id,
            key_fingerprint=encrypted_file.key_fingerprint,
        )

    async def parse_entities_for_layer(
            self, text: str, layer: int, mode: ParseModeA,
    ) -> tuple[str, list[MessageEntity]]:
        parse_mode = _parse_mode_a_to_telethon.get(mode, ())

        message, entities = await self.client._parse_message_text(text, parse_mode)
        entities = _get_entities_with_layer(entities, layer)

        return message, entities

    async def upload_file(self, file: EncryptedFileWrapper) -> InputFileA | InputFileBigA:
        # TODO: telethon supports files encryption for secret chats,
        #  maybe let libraries handle encryption (if supported)
        input_file: InputFile | InputFileBig = await self.client.upload_file(file)
        if isinstance(input_file, InputFile):
            return InputFileA(
                id=input_file.id,
                parts=input_file.parts,
                md5_checksum=input_file.md5_checksum,
            )
        elif isinstance(input_file, InputFileBig):
            return InputFileBigA(
                id=input_file.id,
                parts=input_file.parts,
            )

        raise ValueError(f"Expected server to return InputFile or InputFileBig, got {input_file.__class__.__name__}")

    async def get_file_mime(self, file_name: str, file: BinaryIO) -> str:
        _, mime = get_attributes(file)
        return mime

    async def ack_qts(self, qts: int) -> None:
        await self.client(ReceivedQueueRequest(max_qts=qts))

    async def resolve_user(self, user_id: int | str) -> InputPeerUserA | None:
        entity = await self.client.get_input_entity(user_id)
        if entity is None:
            return None
        if not isinstance(entity, InputPeerUser):
            return None
        return InputPeerUserA(
            id=entity.user_id,
            access_hash=entity.access_hash,
        )

    async def request_encryption(
            self, peer: InputPeerUserA, random_id: int, g_a: bytes,
    ) -> EncryptedChatWaitingA | None:
        chat: EncryptedChatWaiting | EncryptedChatDiscarded = await self.client(RequestEncryptionRequest(
            user_id=InputUser(user_id=peer.id, access_hash=peer.access_hash),
            random_id=random_id,
            g_a=g_a,
        ))

        if isinstance(chat, EncryptedChatWaiting):
            return EncryptedChatWaitingA(
                id=chat.id,
                access_hash=chat.access_hash,
                date=int(chat.date.timestamp()),
                admin_id=chat.admin_id,
                participant_id=chat.participant_id,
            )
        elif isinstance(chat, EncryptedChatDiscarded):
            return None

        raise ValueError(
            f"Expected server to return EncryptedChatWaiting or EncryptedChatDiscarded, "
            f"got {chat.__class__.__name__}"
        )

    async def _raw_updates_handler(self, _, update: UpdateEncryption | UpdateNewEncryptedMessage, _users, _chats) -> None:
        if isinstance(update, UpdateNewEncryptedMessage):
            if self.new_message_handler is None:
                return

            enc_message: EncryptedMessage | EncryptedMessageService = update.message
            if isinstance(enc_message, EncryptedMessage):
                enc_file: EncryptedFile | EncryptedFileEmpty = enc_message.file
                message = EncryptedMessageA(
                    random_id=enc_message.random_id,
                    chat_id=enc_message.chat_id,
                    date=int(enc_message.date.timestamp()),
                    bytes=enc_message.bytes,
                    file=EncryptedFileA(
                        id=enc_file.id,
                        access_hash=enc_file.access_hash,
                        size=enc_file.size,
                        dc_id=enc_file.dc_id,
                        key_fingerprint=enc_file.key_fingerprint,
                    ) if isinstance(enc_file, EncryptedFile) else None,
                )
            elif isinstance(enc_message, EncryptedMessageService):
                message = EncryptedMessageServiceA(
                    random_id=enc_message.random_id,
                    chat_id=enc_message.chat_id,
                    date=int(enc_message.date.timestamp()),
                    bytes=enc_message.bytes,
                )
            else:
                return

            return await self.new_message_handler(message, update.qts)

        if not isinstance(update, UpdateEncryption):
            return

        chat = update.chat
        if isinstance(chat, EncryptedChatRequested):
            if self.chat_requested_handler is None:
                return

            return await self.chat_requested_handler(EncryptedChatRequestedA(
                id=chat.id,
                access_hash=chat.access_hash,
                date=int(chat.date.timestamp()),
                admin_id=chat.admin_id,
                participant_id=chat.participant_id,
                g_a=chat.g_a,
            ))
        elif isinstance(chat, EncryptedChatDiscarded):
            if self.chat_discarded_handler is None:
                return

            return await self.chat_discarded_handler(chat.id, chat.history_deleted)
        elif isinstance(chat, EncryptedChat):
            if self.chat_discarded_handler is None:
                return

            chat = cast(EncryptedChat, chat)
            return await self.chat_update_handler(EncryptedChatA(
                id=chat.id,
                g_a_or_b=chat.g_a_or_b,
                key_fingerprint=chat.key_fingerprint,
            ))

    def _register_raw_handler_maybe(self) -> None:
        if not self.raw_handler_set:
            self.client.on(events.Raw(UpdateEncryption))(self._raw_updates_handler)
            self.client.on(events.Raw(UpdateNewEncryptedMessage))(self._raw_updates_handler)
            self.raw_handler_set = True

    def set_encrypted_message_handler(self, func: NewEncryptedMessageFuncT) -> None:
        self.new_message_handler = func
        self._register_raw_handler_maybe()

    def set_chat_update_handler(self, func: NewChatUpdateFuncT) -> None:
        self.chat_update_handler = func
        self._register_raw_handler_maybe()

    def set_chat_requested_handler(self, func: NewChatRequestedFuncT) -> None:
        self.chat_requested_handler = func
        self._register_raw_handler_maybe()

    def set_chat_discarded_handler(self, func: NewChatDiscardedFuncT) -> None:
        self.chat_discarded_handler = func
        self._register_raw_handler_maybe()

    def get_event_loop(self) -> ...:
        return self.client.loop

    def get_session_name(self) -> str:
        return "telethon"
