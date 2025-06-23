import sqlite3
from abc import abstractmethod
from hashlib import sha1
from time import time

from .base_storage import BaseStorage, SecretChat
from ..enums import ChatState

migrations = [
    f"""
    CREATE TABLE `secret_version`(
        `_id` INTEGER PRIMARY KEY,
        `number` INTEGER
    );
    """,
    f"""
    CREATE TABLE `dh_config`(
        `_id` INTEGER PRIMARY KEY,
        `version` BIGINT,
        `p` BLOB(256),
        `g` BIGINT
    );
    """,
    f"""
    CREATE TABLE `secret_chats`(
        `id` BIGINT PRIMARY KEY,
        `hash` BIGINT NOT NULL,
        `date` BIGINT NOT NULL,
        `admin_id` BIGINT NOT NULL,
        `participant_id` BIGINT NOT NULL,
        `state` INTEGER NOT NULL,
        `originator` BOOLEAN NOT NULL,
        `peer_layer` INTEGER NOT NULL,
        `this_layer` INTEGER NOT NULL,
        `in_seq_no` BIGINT NOT NULL,
        `out_seq_no` BIGINT NOT NULL
    );
    """,
    f"""
    CREATE TABLE `encryption_keys`(
        `id` BIGINT PRIMARY KEY,
        `chat_id` BIGINT NOT NULL,
        `fingerprint_hex` VARCHAR(16) NOT NULL,
        `key` BLOB(256) DEFAULT NULL,
        `created_at` BIGINT NOT NULL,
        `used` INTEGER NOT NULL,
        FOREIGN KEY (`chat_id`) REFERENCES `secret_chats`(`id`)
    );
    """,
    # TODO: store messages (at least outgoing so they can be re-sent)
]


class SQLiteStorage(BaseStorage):
    # TODO: run sqlite queries in thread executor

    def __init__(self, name: str) -> None:
        self.name = name
        self.conn: sqlite3.Connection | None = None

    async def _get_version(self) -> int:
        table_exists = self.conn.execute(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE `type`='table' AND `name`='secret_version');"
        ).fetchone()[0]
        if not table_exists:
            return 0

        return self.conn.execute(
            "SELECT `number` FROM `secret_version` WHERE `_id`=1;"
        ).fetchone()[0]

    async def _create_or_update(self):
        start_version = await self._get_version()

        for idx, migration in enumerate(migrations[start_version:], start=start_version):
            if migration is None:
                continue
            with self.conn:
                self.conn.executescript(migration)
                self.conn.execute(
                    "REPLACE INTO `secret_version`(`_id`, `number`) VALUES (1, ?)",
                    (idx + 1,)
                )

    @abstractmethod
    async def open(self) -> None:
        ...

    async def save(self) -> None:
        self.conn.commit()

    async def close(self) -> None:
        self.conn.close()
        self.conn = None

    @abstractmethod
    async def delete(self) -> None:
        ...

    async def set_dh_values(self, version: int, p: bytes, g: int) -> None:
        self.conn.execute(
            "REPLACE INTO `dh_config`(`_id`, `version`, `p`, `g`) VALUES (1, ?, ?, ?)",
            (version, p, g,)
        )

    async def get_dh_version(self) -> int:
        version = self.conn.execute(
            "SELECT `version` FROM `dh_config` WHERE `_id`=1;"
        ).fetchone()

        return version[0] if version else 0

    async def get_dh_values(self) -> tuple[bytes, int] | tuple[None, None]:
        values = self.conn.execute(
            "SELECT `p`, `g` FROM `dh_config` WHERE `_id`=1;"
        ).fetchone()

        return values if values else (None, None)

    async def set_chat(
            self, chat_id: int, *,
            access_hash: int | None = None,
            created_at: int | None = None,
            admin_id: int | None = None,
            participant_id: int | None = None,
            state: ChatState | None = None,
            originator: bool | None = None,
            peer_layer: int | None = None,
            this_layer: int | None = None,
            in_seq_no: int | None = None,
            out_seq_no: int | None = None,
    ) -> None:
        fields = ["id"]
        params = [chat_id]

        if access_hash is not None:
            fields.append("hash")
            params.append(access_hash)
        if created_at is not None:
            fields.append("date")
            params.append(created_at)
        if admin_id is not None:
            fields.append("admin_id")
            params.append(admin_id)
        if participant_id is not None:
            fields.append("participant_id")
            params.append(participant_id)
        if state is not None:
            fields.append("state")
            params.append(state)
        if originator is not None:
            fields.append("originator")
            params.append(originator)
        if peer_layer is not None:
            fields.append("peer_layer")
            params.append(peer_layer)
        if this_layer is not None:
            fields.append("this_layer")
            params.append(this_layer)
        if in_seq_no is not None:
            fields.append("in_seq_no")
            params.append(in_seq_no)
        if out_seq_no is not None:
            fields.append("out_seq_no")
            params.append(out_seq_no)

        if len(fields) == 1:
            return

        if await self.get_chat(chat_id) is None:
            fields_str = ", ".join([f"`{field_name}`" for field_name in fields])
            params_str = ", ".join(["?" for _ in fields])
            self.conn.execute(
                f"INSERT INTO `secret_chats`({fields_str}) VALUES ({params_str});", tuple(params)
            )
        else:
            fields_str = ", ".join([f"`{field_name}`=?" for field_name in fields[1:]])
            self.conn.execute(
                f"UPDATE `secret_chats` SET {fields_str} WHERE `id`=?;", (*params[1:], params[0])
            )

    async def inc_chat_in_seq_no(self, chat_id: int) -> int:
        with self.conn:
            chat = await self.get_chat(chat_id)
            await self.set_chat(chat_id, in_seq_no=chat.in_seq_no + 1)

        return chat.in_seq_no

    async def inc_chat_out_seq_no(self, chat_id: int) -> int:
        with self.conn:
            chat = await self.get_chat(chat_id)
            await self.set_chat(chat_id, out_seq_no=chat.out_seq_no + 1)

        return chat.out_seq_no

    async def get_chat(self, chat_id: int) -> SecretChat | None:
        cursor = self.conn.execute("SELECT * FROM `secret_chats` WHERE `id`=?;", (chat_id,))
        row = cursor.fetchone()
        if not row:
            return None

        cols = next(zip(*cursor.description))
        return SecretChat(**dict(zip(cols, row)))

    async def delete_chat(self, chat_id: int) -> None:
        self.conn.execute("DELETE FROM `secret_chats` WHERE `id`=?;", (chat_id,))

    async def get_key(self, chat_id: int, fingerprint: bytes | None = None) -> tuple[int, bytes, int] | None:
        if fingerprint is None:
            result = self.conn.execute(
                "SELECT `id`, `key`, `used` FROM `encryption_keys` WHERE `chat_id`=? ORDER BY `id` DESC LIMIT 1",
                (chat_id,)
            ).fetchone()
        else:
            result = self.conn.execute(
                "SELECT `id`, `key`, `used` FROM `encryption_keys` WHERE `chat_id`=? AND `fingerprint_hex`=?",
                (chat_id, fingerprint.hex(),)
            ).fetchone()

        return result if result else None

    async def add_key(self, chat_id: int, key: bytes) -> None:
        fingerprint = sha1(key).digest()[-8:]
        self.conn.execute(
            f"INSERT INTO `encryption_keys`(`chat_id`, `fingerprint_hex`, `key`, `created_at`, `used`) VALUES (?, ?, ?, ?, ?);",
            (chat_id, fingerprint.hex(), key, int(time()), 0,)
        )

    async def inc_key(self, key_id: int) -> None:
        self.conn.execute(
            f"UPDATE `encryption_keys` SET `used`=`used`+1 WHERE `id`=?",
            (key_id,)
        )

    async def delete_key(self, key_id: int) -> None:
        self.conn.execute("DELETE FROM `encryption_keys` WHERE `id`=?;", (key_id,))
