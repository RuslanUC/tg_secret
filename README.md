# tg-secret

This library provides secret chat support for pyrogram.
It is work-in-progress and not recommended to use in production yet.
Currently, following critical features are not implemented:
 - Proper gaps handling: if gaps were detected locally, they are just ignored; also DecryptedMessageActionResend is ignored, so if remote detected gaps, it won't be able to fill them
 - Media handling
 - Some security checks (check if dh_config.p is safe prime, inconsistent seq_no in terms of parity)


### Example
```python
from pyrogram import Client
from pyrogram.raw.types import EncryptedChatRequested, User

from tg_secret import ChatRequestResult, SecretChat, SecretMessage
from tg_secret.client import TelegramSecretClient

client = Client(
    "secret_client",
    api_id=...,  # Your api id
    api_hash=...,  # Your api hash
)
secret = TelegramSecretClient(client)


@secret.on_request
async def secret_chat_request(chat: EncryptedChatRequested, user: User) -> ChatRequestResult:
    print(f"Accepting new secret chat from {user.first_name} ({user.id})")
    return ChatRequestResult.ACCEPT


@secret.on_chat_ready
async def secret_chat_ready(chat: SecretChat) -> None:
    print(f"Secret chat with {chat.peer_id} is ready!")
    await chat.send_message("Hello!")


@secret.on_new_message
async def new_secret_message(message: SecretMessage) -> None:
    print(f"New message from {message.chat.peer_id}: {message.text}")
    if message.text == "/delete_chat":
        await message.reply("Discarding chat...")
        await message.chat.delete(delete_history=False)
        return 
    
    await message.reply(f"**{message.text}**")


@secret.on_messages_deleted
async def secret_messages_deleted(chat: SecretChat, random_ids: list[int]):
    print(f"Messages were deleted: {random_ids} in chat with {chat.peer_id}")


@secret.on_chat_deleted
async def secret_chat_deleted(chat: SecretChat):
    print(f"Secret chat with {chat.peer_id} was deleted")


if __name__ == "__main__":
    client.run(secret.pyrogram_start())
```