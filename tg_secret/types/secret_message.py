from __future__ import annotations

from typing import TYPE_CHECKING

from tg_secret.raw.base import MessageEntity

if TYPE_CHECKING:
    from tg_secret import TelegramSecretClient, SecretChat


class SecretMessage:
    # TODO: convert entities to pyrogram entities
    def __init__(
            self, random_id: int, chat: SecretChat, from_id: int, text: str, entities: list[MessageEntity],
            *, _client: TelegramSecretClient,
    ):
        self.id = random_id
        self.chat = chat
        self.from_id = from_id
        self.text = text
        self.entities = entities
        self._client = _client

    async def delete(self) -> None:
        ...  # TODO: delete message

    async def reply(self, ) -> SecretMessage:
        ...  # TODO: reply to message
