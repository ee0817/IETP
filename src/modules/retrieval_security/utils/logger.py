"""审计日志模块（最简实现）。

将每次检测的 SecurityEvent 写入本地 SQLite 数据库，用于审计与溯源。
数据库文件路径：data/audit.db
使用 Python 标准库 sqlite3，不引入 ORM。
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path

from schemas import SecurityEvent

# 数据库文件默认路径
DEFAULT_DB_PATH = Path("data/audit.db")

# 建表 SQL（system_prompt.md 第 3.6 节）
_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS security_event_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stage TEXT NOT NULL,
    chunk_id TEXT,
    source TEXT,
    risk_score REAL,
    risk_type TEXT,
    confidence REAL,
    action_taken TEXT,
    raw_event TEXT,
    created_at TEXT NOT NULL
);
"""


def _get_connection(db_path: str | Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """获取 SQLite 连接，确保目录与表存在。"""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.execute(_CREATE_TABLE_SQL)
    conn.commit()
    return conn


def write_log(
    event: SecurityEvent,
    chunk_id: str | None = None,
    source: str | None = None,
) -> int:
    """将 SecurityEvent 写入 SQLite，返回 log_id。

    action_taken 暂时留空字符串，由下游回填。
    raw_event 用 json.dumps 存整个 event 的字段。
    created_at 用 datetime.utcnow().isoformat()。
    """
    conn = _get_connection()
    try:
        cursor = conn.execute(
            """
            INSERT INTO security_event_log
                (stage, chunk_id, source, risk_score, risk_type, confidence,
                 action_taken, raw_event, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.stage,
                chunk_id,
                source,
                event.risk_score,
                event.risk_type,
                event.confidence,
                "",  # action_taken 留空
                json.dumps(event.model_dump(), ensure_ascii=False),
                datetime.utcnow().isoformat(),
            ),
        )
        conn.commit()
        return int(cursor.lastrowid)
    finally:
        conn.close()
