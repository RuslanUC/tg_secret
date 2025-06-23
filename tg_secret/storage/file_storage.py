import os
import sqlite3
from pathlib import Path

from .sqlite_storage import SQLiteStorage


class FileStorage(SQLiteStorage):
    FILE_EXTENSION = ".secret-session"

    def __init__(self, name: str, workdir: Path):
        super().__init__(name)
        self.db_path = workdir / f"{self.name}{self.FILE_EXTENSION}"

    async def open(self) -> None:
        if self.conn is not None:
            return

        self.conn = sqlite3.connect(str(self.db_path), timeout=1, check_same_thread=False)
        await self._create_or_update()

        with self.conn:
            self.conn.execute("VACUUM")

    async def delete(self) -> None:
        os.remove(self.db_path)
