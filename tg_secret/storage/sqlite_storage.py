import sqlite3
from abc import abstractmethod
from time import time

from .base_storage import BaseStorage, SecretChat, DhConfig
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
        `version` BIGINT PRIMARY KEY,
        `date` BIGINT NOT NULL,
        `p` BLOB(256) NOT NULL,
        `g` BIGINT NOT NULL
    );
    """,
    f"""
    CREATE TABLE `secret_chats`(
        `id` BIGINT PRIMARY KEY,
        `access_hash` BIGINT NOT NULL,
        `created_at` BIGINT NOT NULL,
        `admin_id` BIGINT NOT NULL,
        `participant_id` BIGINT NOT NULL,
        `state` INTEGER NOT NULL,
        `originator` BOOLEAN NOT NULL,
        `peer_layer` INTEGER NOT NULL DEFAULT 46,
        `this_layer` INTEGER NOT NULL DEFAULT 46,
        `in_seq_no` BIGINT NOT NULL DEFAULT 0,
        `out_seq_no` BIGINT NOT NULL DEFAULT 0,
        `dh_config_version` BIGINT DEFAULT NULL,
        `a` BLOB(256) DEFAULT NULL,
        `exchange_id` BIGINT DEFAULT NULL,
        `key` BLOB(256) DEFAULT NULL,
        `key_fp` BIGINT DEFAULT NULL,
        `fut_key` BLOB(256) DEFAULT NULL,
        `fut_key_fp` BIGINT DEFAULT NULL,
        `key_used` INTEGER NOT NULL DEFAULT 0,
        `key_created_at` INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY (`dh_config_version`) REFERENCES `dh_config`(`version`)
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

    async def get_dh_config(self, version: int | None) -> DhConfig | None:
        if version is not None:
            cursor = self.conn.execute(
                "SELECT * FROM `dh_config` WHERE `version`=?",
                (version,)
            )
        else:
            cursor = self.conn.execute(
                "SELECT * FROM `dh_config` ORDER BY `date` DESC LIMIT 1",
            )

        row = cursor.fetchone()
        if not row:
            return None

        cols = next(zip(*cursor.description))
        return DhConfig(**dict(zip(cols, row)))

    async def set_dh_config(self, version: int, p: bytes, g: int) -> None:
        if await self.get_dh_config(version) is not None:
            self.conn.execute("UPDATE `dh_config` SET `date`=? WHERE `version`=?;", (int(time()), version,))
        else:
            self.conn.execute(
                "INSERT INTO `dh_config`(`version`, `date`, `p`, `g`) VALUES (?, ?, ?, ?)",
                (version, int(time()), p, g,)
            )

    async def add_chat(
            self, chat_id: int, *,
            access_hash: int,
            created_at: int,
            admin_id: int,
            participant_id: int,
            state: ChatState,
            originator: bool,
            peer_layer: int,
            this_layer: int,
    ) -> None:
        self.conn.execute(
            f"INSERT INTO `secret_chats`(`id`, `access_hash`, `created_at`, `admin_id`, `participant_id`, `state`, `originator`, `peer_layer`, `this_layer`) "
            f"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);",
            (chat_id, access_hash, created_at, admin_id, participant_id, state, originator, peer_layer, this_layer)
        )

    async def update_chat(self, chat: int | SecretChat, **kwargs) -> None:
        fields = []
        params = []

        for key, value in kwargs.items():
            if key not in SecretChat.__slots__:
                print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                print(f"Passed unknown argument \"{key}\" ({value})")
                print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                continue
            fields.append(key)
            params.append(value)
            if isinstance(chat, SecretChat):
                setattr(chat, key, value)

        if not fields:
            return

        fields.append("id")
        params.append(chat.id if isinstance(chat, SecretChat) else chat)

        fields_str = ", ".join([f"`{field_name}`=?" for field_name in fields[:-1]])
        self.conn.execute(
            f"UPDATE `secret_chats` SET {fields_str} WHERE `id`=?;", tuple(params)
        )

    async def inc_chat_in_seq_no(self, chat_id: int) -> int:
        with self.conn:
            chat = await self.get_chat(chat_id)
            await self.update_chat(chat_id, in_seq_no=chat.in_seq_no + 1)

        return chat.in_seq_no

    async def inc_chat_out_seq_no(self, chat_id: int) -> int:
        with self.conn:
            chat = await self.get_chat(chat_id)
            await self.update_chat(chat_id, out_seq_no=chat.out_seq_no + 1)

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
