import sqlite3
from abc import abstractmethod
from time import time

from .base_storage import BaseStorage, SecretChat, DhConfig, SentMessage, RecvMessage
from ..enums import ChatState

migrations = [
    """
    CREATE TABLE `secret_version`(
        `_id` INTEGER PRIMARY KEY,
        `number` INTEGER
    );
    """,

    """
    CREATE TABLE `dh_config`(
        `version` BIGINT PRIMARY KEY,
        `date` BIGINT NOT NULL,
        `p` BLOB(256) NOT NULL,
        `g` BIGINT NOT NULL
    );
    """,

    """
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

    """
    CREATE TABLE `out_messages`(
        `id` BIGINT PRIMARY KEY,
        `chat_id` BIGINT NOT NULL,
        `out_seq_no` BIGINT NOT NULL,
        `message` BLOB(4194304) NOT NULL, /* 4mb */
        `file_id` BIGINT DEFAULT NULL,
        `file_hash` BIGINT DEFAULT NULL,
        `file_key_fp` BIGINT DEFAULT NULL,
        `silent` BOOLEAN DEFAULT FALSE,
        FOREIGN KEY (`chat_id`) REFERENCES `secret_chats`(`id`)
    );
    """,

    """
    CREATE TABLE `in_messages`(
        `id` BIGINT PRIMARY KEY,
        `chat_id` BIGINT NOT NULL,
        `remote_out_seq_no` BIGINT NOT NULL,
        `message` BLOB(4194304) NOT NULL, /* 4mb */
        `file_id` BIGINT DEFAULT NULL,
        `file_dc` BIGINT DEFAULT NULL,
        `file_hash` BIGINT DEFAULT NULL,
        `file_size` BIGINT DEFAULT NULL,
        `file_key_fp` BIGINT DEFAULT NULL,
        `is_service` BOOLEAN NOT NULL,
        FOREIGN KEY (`chat_id`) REFERENCES `secret_chats`(`id`)
    );
    """,
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

    async def get_chat_by_peer(self, peer_id: int) -> SecretChat | None:
        cursor = self.conn.execute(
            "SELECT * FROM `secret_chats` WHERE (`admin_id`=? AND `originator`=0) OR (`participant_id`=? AND `originator`=1);",
            (peer_id, peer_id,))
        row = cursor.fetchone()
        if not row:
            return None

        cols = next(zip(*cursor.description))
        return SecretChat(**dict(zip(cols, row)))

    async def delete_chat(self, chat_id: int) -> None:
        self.conn.execute("DELETE FROM `secret_chats` WHERE `id`=?;", (chat_id,))

    async def get_chat_ids(self) -> list[int]:
        rows = self.conn.execute("SELECT `id` FROM `secret_chats`;", ()).fetchall()
        return [row[0] for row in rows]

    async def store_out_message(
            self, chat_id: int, out_seq_no: int, data: bytes, file_id: int | None, file_hash: int | None,
            file_key_fp: int | None, silent: bool,
    ) -> None:
        self.conn.execute(
            "INSERT INTO `out_messages`(`chat_id`, `out_seq_no`, `message`, `file_id`, `file_hash`, `file_key_fp`, `silent`) VALUES (?, ?, ?, ?, ?, ?, ?);",
            (chat_id, out_seq_no, data, file_id, file_hash, file_key_fp, silent,),
        )

    async def get_out_messages(self, chat_id: int, start_seq_no: int, end_seq_no: int) -> list[SentMessage]:
        cursor = self.conn.execute(
            "SELECT * FROM `out_messages` WHERE `chat_id`=? AND `out_seq_no` BETWEEN ? AND ?;",
            (chat_id, start_seq_no, end_seq_no,),
        )

        rows = cursor.fetchall()
        cols = next(zip(*cursor.description))

        return [
            SentMessage(**dict(zip(cols, row)))
            for row in rows
        ]

    async def store_in_message(
            self, chat_id: int, out_seq_no: int, data: bytes, file_id: int | None, file_dc: int | None,
            file_hash: int | None, file_size: int | None, file_key_fp: int | None, is_service: bool,
    ) -> None:
        self.conn.execute(
            "INSERT INTO `in_messages`(`chat_id`, `remote_out_seq_no`, `message`, `file_id`, `file_dc`, `file_hash`, `file_size`, `file_key_fp`, `is_service`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);",
            (chat_id, out_seq_no, data, file_id, file_dc, file_hash, file_size, file_key_fp, is_service,),
        )

    async def get_and_delete_in_message(self, chat_id: int, seq_no: int) -> RecvMessage | None:
        cursor = self.conn.execute(
            "SELECT * FROM `in_messages` WHERE `chat_id`=? AND `remote_out_seq_no`=?;",
            (chat_id, seq_no,))
        row = cursor.fetchone()
        if not row:
            return None

        cols = next(zip(*cursor.description))
        message = RecvMessage(**dict(zip(cols, row)))

        self.conn.execute("DELETE FROM `in_messages` WHERE `id`=?;", (message.id,))

        return message
