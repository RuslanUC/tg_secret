import sqlite3
from abc import abstractmethod

from .base_storage import BaseStorage
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
        `encryption_key` BLOB(256) DEFAULT NULL
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

    async def set_dh_values(self, version: int, p: bytes, g: int) -> None:
        self.conn.execute(
            "REPLACE INTO `dh_config`(`_id`, `version`, `p`, `g`) VALUES (1, ?, ?, ?)",
            (version, p, g,)
        )

    async def get_dh_version(self) -> int:
        version = self.conn.execute(
            "SELECT `version` FROM `dh_config` WHERE `_id`=1;"
        ).fetchone()

        return version if version else 0

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
            encryption_key: bytes | None = None,
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
        if encryption_key is not None:
            fields.append("encryption_key")
            params.append(encryption_key)

        if len(fields) == 1:
            return

        fields_str = ", ".join([f"`{field_name}`" for field_name in fields])
        params_str = ", ".join(["?" for _ in fields])

        self.conn.execute(
            f"REPLACE INTO `secret_chats`({fields_str}) VALUES ({params_str});", tuple(params)
        )

    async def get_chat(self, chat_id: int) -> tuple[int, int, int, int, ChatState, bytes | None] | None:
        values = self.conn.execute(
            "SELECT `hash`, `date`, `admin_id`, `participant_id`, `state`, `encryption_key` "
            "FROM `secret_chats` "
            "WHERE `id`=?;",
            (chat_id,)
        ).fetchone()

        return values if values else None

    async def delete_chat(self, chat_id: int) -> None:
        self.conn.execute("DELETE FROM `secret_chats` WHERE `id`=?;", (chat_id,))
