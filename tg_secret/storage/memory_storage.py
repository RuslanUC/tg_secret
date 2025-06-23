import sqlite3

from .sqlite_storage import SQLiteStorage


class MemoryStorage(SQLiteStorage):
    async def open(self) -> None:
        if self.conn is not None:
            return

        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        await self._create_or_update()

    async def delete(self) -> None:
        ...
