"""
database.py — SQLite3 数据库初始化与操作封装
"""
import sqlite3
import os
from contextlib import contextmanager

DB_PATH = os.environ.get("MEMSCOPE_DB", os.path.join(os.path.dirname(__file__), "memscope.db"))


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def db_conn():
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """创建数据库表（若不存在）"""
    with db_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS images (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT    NOT NULL,
                path        TEXT    NOT NULL,
                os_type     TEXT    DEFAULT 'auto',
                arch        TEXT    DEFAULT '',
                status      TEXT    DEFAULT 'pending',
                created_at  TEXT    DEFAULT (datetime('now','localtime')),
                finished_at TEXT    DEFAULT NULL,
                result_path TEXT    DEFAULT NULL,
                error_msg   TEXT    DEFAULT NULL
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_images_status ON images(status)
        """)
