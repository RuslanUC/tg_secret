# tg-secret

This library provides secret chat support for python Telegram (MTProto) client libraries.
Currently, tg-secret supports [Pyrogram](https://github.com/pyrogram/pyrogram) and [Telethon](https://github.com/LonamiWebs/Telethon) (not tested), 
but any library can be supported by creating client adapter implementing tg_secret.SecretClientAdapter class.

It is work-in-progress and not recommended to use in production yet.
Currently, following critical features are not implemented:
 - Media downloading
 - Some security checks (check if dh_config.p is safe prime, inconsistent seq_no in terms of parity)


### Example with pyrogram
```python
from asyncio import sleep
from io import BytesIO

from pyrogram import Client, filters
from pyrogram.types import User, Message

from tg_secret import TelegramSecretClient, ChatRequestResult, SecretChat, SecretMessage
from tg_secret.client_adapters.pyrogram_adapter import PyrogramClientAdapter

client = Client(
    "secret_client",
    api_id=...,  # Your api id
    api_hash=...,  # Your api hash
)
secret = TelegramSecretClient(PyrogramClientAdapter(client))


@client.on_message(filters.private & filters.command("start_secret_chat"))
async def on_user_requested_secret_chat(_: Client, message: Message):
    print(f"Requesting new secret chat with {message.from_user.first_name} ({message.from_user.id})")
    await secret.request_encryption(message.from_user.id)


@secret.on_request
async def secret_chat_request(chat: SecretChat) -> ChatRequestResult:
    user: User = await client.get_users(chat.peer_id)
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
    elif message.text == "/file":
        await secret.send_document(
            message.chat.id, BytesIO(b"test 123"), caption="Here's your file", file_name="test.txt"
        )
        return
    elif message.text == "/delete_message":
        message_to_delete = await message.reply("This message will be deleted in 5 seconds")
        await sleep(5)
        await message_to_delete.delete()
        return
    elif message.text == "/delete_history":
        await message.chat.delete_history()
        await message.chat.send_message("History was deleted")
        return

    await message.reply(f"**{message.text}**")


@secret.on_messages_deleted
async def secret_messages_deleted(chat: SecretChat, random_ids: list[int]):
    print(f"Messages were deleted: {random_ids} in chat with {chat.peer_id}")


@secret.on_chat_deleted
async def secret_chat_deleted(chat: SecretChat, history_deleted: bool):
    print(f"Secret chat with {chat.peer_id} was deleted, with history: {history_deleted}")


if __name__ == "__main__":
    client.run(secret.pyrogram_start())
```