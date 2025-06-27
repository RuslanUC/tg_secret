from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tg_secret import TelegramSecretClient, SecretChat, ParseMode
    from tg_secret.raw.base import MessageEntity


class SecretMessage:
    # TODO: convert entities to pyrogram/telethon entities ??
    # TODO: media

    def __init__(
            self, random_id: int, chat: SecretChat, from_id: int, text: str, entities: list[MessageEntity],
            reply_to_random_id: int | None,
            *, _client: TelegramSecretClient,
    ):
        self.id = random_id
        self.chat = chat
        self.from_id = from_id
        self.text = text
        self.entities = entities
        self.reply_to_id = reply_to_random_id
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
