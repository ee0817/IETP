"""审计日志模块（最简实现）。

将每次检测的 SecurityEvent 写入本地 SQLite 数据库，用于审计与溯源。
数据库文件路径：data/audit.db
使用 Python 标准库 sqlite3，不引入 ORM。

PR4 修复：
- P1: 审计写入失败不再静默吞掉，改为 logging.warning 告警（写日志失败
  不应阻断主流程，但必须留有痕迹，避免攻击者通过使 DB 不可用抹去痕迹）。
- P1: 每行写入附带 SHA-256 哈希链（prev_hash + 本行内容），
  任何对历史行的篡改/删除都会破坏链式校验，可用 verify_chain() 检测。
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from schemas import SecurityEvent

logger = logging.getLogger(__name__)

# 数据库文件默认路径
DEFAULT_DB_PATH = Path("data/audit.db")

# 建表 SQL（system_prompt.md 第 3.6 节 + prev_hash/row_hash 哈希链列）
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
    created_at TEXT NOT NULL,
    prev_hash TEXT,
    row_hash TEXT
);
"""

# 哈希链的创世值
_GENESIS_HASH = "0" * 64


def _resolve_db_path(db_path: str | Path | None) -> Path:
    """运行时解析 DB 路径，允许测试通过修改 DEFAULT_DB_PATH 重定向。"""
    return Path(db_path) if db_path is not None else Path(DEFAULT_DB_PATH)


def _get_connection(db_path: str | Path | None = None) -> sqlite3.Connection:
    """获取 SQLite 连接，确保目录与表存在（旧表自动补列）。"""
    path = _resolve_db_path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.execute(_CREATE_TABLE_SQL)
    # 旧版本表无 prev_hash/row_hash 列，尝试补列（已存在则忽略）
    for col in ("prev_hash TEXT", "row_hash TEXT"):
        try:
            conn.execute(f"ALTER TABLE security_event_log ADD COLUMN {col}")
        except sqlite3.OperationalError:
            pass
    conn.commit()
    return conn


def _last_hash(conn: sqlite3.Connection) -> str:
    """取最后一行的 row_hash 作为哈希链前驱；空表返回创世值。"""
    row = conn.execute(
        "SELECT row_hash FROM security_event_log ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return row[0] if row and row[0] else _GENESIS_HASH


def _row_hash(prev_hash: str, payload: tuple) -> str:
    """计算本行哈希：sha256(prev_hash + 序列化行内容)。"""
    h = hashlib.sha256()
    h.update(prev_hash.encode("utf-8"))
    h.update(json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8"))
    return h.hexdigest()


def write_log(
    event: SecurityEvent,
    chunk_id: str | None = None,
    source: str | None = None,
) -> int:
    """将 SecurityEvent 写入 SQLite（带哈希链），返回 log_id。

    action_taken 暂时留空字符串，由下游回填。
    raw_event 用 json.dumps 存整个 event 的字段。
    created_at 用 timezone-aware 的 UTC ISO 时间戳。
    """
    conn = _get_connection()
    try:
        payload = (
            event.stage,
            chunk_id,
            source,
            event.risk_score,
            event.risk_type,
            event.confidence,
            "",  # action_taken 留空
            json.dumps(event.model_dump(), ensure_ascii=False),
            datetime.now(timezone.utc).isoformat(),
        )
        prev = None
        rh = None
        # N2 修复：BEGIN IMMEDIATE 事务包住"读末行哈希 + 插入"，
        # 防止并发写入读到同一 prev_hash 导致哈希链分叉
        conn.execute("BEGIN IMMEDIATE")
        prev = _last_hash(conn)
        rh = _row_hash(prev, payload)
        cursor = conn.execute(
            """
            INSERT INTO security_event_log
                (stage, chunk_id, source, risk_score, risk_type, confidence,
                 action_taken, raw_event, created_at, prev_hash, row_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (*payload, prev, rh),
        )
        conn.commit()
        return int(cursor.lastrowid)
    except Exception as exc:  # noqa: BLE001
        # 写日志失败不阻断主流程，但必须告警留痕（防止攻击者借 DB 故障抹除审计痕迹）
        logger.warning("audit log write failed: %s: %s", type(exc).__name__, exc)
        return -1
    finally:
        conn.close()


def verify_chain(db_path: str | Path | None = None) -> bool:
    """校验审计日志哈希链完整性。

    逐行重算 row_hash 并与存储值比对，同时校验 prev_hash 衔接。
    任何历史行被篡改或删除都会使校验失败。

    Returns:
        True 表示链完整；False 表示存在篡改或表不存在。
    """
    path = _resolve_db_path(db_path)
    if not path.exists():
        return False
    conn = sqlite3.connect(str(path))
    try:
        rows = conn.execute(
            """
            SELECT stage, chunk_id, source, risk_score, risk_type, confidence,
                   action_taken, raw_event, created_at, prev_hash, row_hash
            FROM security_event_log ORDER BY id
            """
        ).fetchall()
    except sqlite3.OperationalError:
        return False
    finally:
        conn.close()

    prev = _GENESIS_HASH
    for row in rows:
        payload = row[:9]
        stored_prev, stored_hash = row[9], row[10]
        if stored_prev != prev:
            return False
        if _row_hash(prev, payload) != stored_hash:
            return False
        prev = stored_hash
    return True
