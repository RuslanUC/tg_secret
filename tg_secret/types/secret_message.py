from __future__ import annotations

from typing import TYPE_CHECKING

from tg_secret.enums import MessageMediaType
from tg_secret.raw.types import DecryptedMessageMediaEmpty, DecryptedMessageMediaAudio_8, DecryptedMessageMediaAudio_17, \
    DecryptedMessageMediaDocument_8, DecryptedMessageMediaDocument_45, DecryptedMessageMediaDocument_143, \
    DecryptedMessageMediaPhoto_8, DecryptedMessageMediaPhoto_45, DecryptedMessageMediaVideo_8, \
    DecryptedMessageMediaVideo_17, DecryptedMessageMediaVideo_45, DecryptedMessageMediaContact, \
    DecryptedMessageMediaGeoPoint, DecryptedMessageMediaVenue, DecryptedMessageMediaWebPage

if TYPE_CHECKING:
    from tg_secret import TelegramSecretClient, SecretChat, ParseMode
    from tg_secret.raw.base import MessageEntity, DecryptedMessageMedia
    from tg_secret.client_adapters.base_adapter import EncryptedFileA


class SecretMessage:
    # TODO: convert entities to pyrogram/telethon entities ??
    # TODO: media

    def __init__(
            self, random_id: int, chat: SecretChat, from_id: int, text: str, entities: list[MessageEntity],
            reply_to_random_id: int | None, media: DecryptedMessageMedia | None, file: EncryptedFileA | None,
            *, _client: TelegramSecretClient,
    ):
        self.id = random_id
        self.chat = chat
        self.from_id = from_id
        self.text = text
        self.entities = entities
        self.reply_to_id = reply_to_random_id

        self._media = media
        self._file = file
        self._client = _client

    async def delete(self) -> None:
        await self._client.delete_messages(self.chat.id, self.id)

    async def reply(
            self,
            text: str,
            ttl: int = 0,
            disable_web_page_preview: bool = False,
            disable_notification: bool = False,
            via_bot_name: str | None = None,
            parse_mode: ParseMode | None = None,
    ) -> SecretMessage:
        return await self.chat.send_message(
            text, ttl, disable_web_page_preview, disable_notification, via_bot_name, self.id, parse_mode,
        )

    @property
    def media(self) -> MessageMediaType | None:
        if self._media is None or isinstance(self._media, DecryptedMessageMediaEmpty):
            return None

        # TODO: DecryptedMessageMediaExternalDocument

        if isinstance(self._media, (DecryptedMessageMediaAudio_8, DecryptedMessageMediaAudio_17)):
            return MessageMediaType.AUDIO
        if isinstance(self._media, (DecryptedMessageMediaDocument_8, DecryptedMessageMediaDocument_45, DecryptedMessageMediaDocument_143)):
            return MessageMediaType.DOCUMENT
        if isinstance(self._media, (DecryptedMessageMediaPhoto_8, DecryptedMessageMediaPhoto_45)):
            return MessageMediaType.PHOTO
        if isinstance(self._media, (DecryptedMessageMediaVideo_8, DecryptedMessageMediaVideo_17, DecryptedMessageMediaVideo_45)):
            return MessageMediaType.VIDEO
        if isinstance(self._media, DecryptedMessageMediaContact):
            return MessageMediaType.CONTACT
        if isinstance(self._media, DecryptedMessageMediaGeoPoint):
            return MessageMediaType.LOCATION
        if isinstance(self._media, DecryptedMessageMediaVenue):
            return MessageMediaType.VENUE
        if isinstance(self._media, DecryptedMessageMediaWebPage):
            return MessageMediaType.WEB_PAGE
