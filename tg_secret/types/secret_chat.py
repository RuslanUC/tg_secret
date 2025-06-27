from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tg_secret import TelegramSecretClient, SecretMessage, ChatState, ParseMode
    from tg_secret.storage.base_storage import SecretChat as StorageSecretChat


class SecretChat:
    def __init__(
            self, chat_id: int, peer_id: int, originator: bool, created_at: int, sent_messages: int,
            recv_messages: int, state: ChatState,
            *, _client: TelegramSecretClient,
    ):
        self.id = chat_id
        self.peer_id = peer_id
        self.originator = originator
        self.created_at = created_at
        self.sent_messages = sent_messages
        self.recv_messages = recv_messages
        self.state = state
        self._client = _client

    async def send_message(
            self,
            text: str,
            ttl: int = 0,
            disable_web_page_preview: bool = False,
            disable_notification: bool = False,
            via_bot_name: str | None = None,
            reply_to_message_id: int | None = None,
            parse_mode: ParseMode | None = None,
    ) -> SecretMessage:
        return await self._client.send_text_message(
            self.id, text, ttl, disable_web_page_preview, disable_notification, via_bot_name, reply_to_message_id,
            parse_mode,
        )

    async def rekey(self) -> None:
        await self._client.rekey(self.id)

    async def delete(self, delete_history: bool = False) -> None:
        await self._client.discard_chat(self.id, delete_history)

    async def delete_message(self, random_id: int | list[int]) -> None:
        await self._client.delete_messages(self.id, random_id)

    async def delete_history(self) -> None:
        await self._client.delete_chat_history(self.id)

    @classmethod
    def _from_storage_chat(cls, chat: StorageSecretChat, client: TelegramSecretClient) -> SecretChat:
        return cls(
            chat_id=chat.id,
            peer_id=chat.participant_id if chat.originator else chat.admin_id,
            originator=chat.originator,
            created_at=chat.created_at,
            sent_messages=chat.out_seq_no,
            recv_messages=chat.in_seq_no,
            state=chat.state,
            _client=client,
        )
