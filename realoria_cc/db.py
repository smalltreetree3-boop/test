"""SQLite ストア。接続は操作ごとに開く (スレッド安全・Windows でもロック解放が確実)。"""
from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator

SCHEMA_VERSION = 1

SCHEMA = r"""
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS system_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS principals (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('human', 'ai', 'system')),
    display_name TEXT NOT NULL,
    password_hash TEXT,
    roles TEXT NOT NULL DEFAULT '[]',
    clearance INTEGER NOT NULL DEFAULT 0 CHECK (clearance BETWEEN 0 AND 3),
    enabled INTEGER NOT NULL DEFAULT 1,
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until REAL NOT NULL DEFAULT 0,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL REFERENCES principals(id),
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sources (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    version TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('official', 'reference', 'unverified')),
    classification INTEGER NOT NULL CHECK (classification BETWEEN 0 AND 3),
    content TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    registered_by TEXT NOT NULL,
    registered_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    idempotency_key TEXT UNIQUE,
    kind TEXT NOT NULL,
    function_id TEXT NOT NULL,
    payload TEXT NOT NULL,
    classification INTEGER NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN
        ('queued', 'running', 'paused', 'held', 'succeeded', 'failed', 'cancelled')),
    control TEXT,                 -- 実行中ジョブへの要求: 'pause' | 'cancel'
    retry_safe INTEGER NOT NULL DEFAULT 1,
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL,
    next_run_at REAL NOT NULL DEFAULT 0,
    lease_owner TEXT,             -- 試行ID (attempt_id)
    lease_token INTEGER NOT NULL DEFAULT 0,  -- フェンシングトークン (単調増加)
    lease_expires REAL,
    stop_generation INTEGER NOT NULL DEFAULT 0,
    hold_reason TEXT,
    result TEXT,
    error TEXT,
    created_by TEXT NOT NULL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS jobs_claim ON jobs (state, next_run_at);

CREATE TABLE IF NOT EXISTS proposals (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES jobs(id),
    function_id TEXT NOT NULL,
    kind TEXT NOT NULL,           -- 'analysis' | 'signal'
    status TEXT NOT NULL,         -- 'draft' | 'needs_review'
    content TEXT NOT NULL,        -- JSON
    grounding TEXT NOT NULL,      -- JSON (根拠検査結果)
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS model_calls (
    id TEXT PRIMARY KEY,
    job_id TEXT,
    attempt_id TEXT,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    locality TEXT NOT NULL,
    classification INTEGER NOT NULL,
    prompt_sha256 TEXT NOT NULL,
    prompt_chars INTEGER NOT NULL,
    output_chars INTEGER NOT NULL DEFAULT 0,
    input_tokens INTEGER,
    output_tokens INTEGER,
    tokens_estimated INTEGER NOT NULL DEFAULT 1,
    cost_usd REAL,
    status TEXT NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    level TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at REAL NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS worker_heartbeats (
    worker_id TEXT PRIMARY KEY,
    last_seen REAL NOT NULL,
    status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    seq INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    detail TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL,
    mac TEXT NOT NULL
);

-- 監査ログは追記専用。ファイル直接改変はハッシュ鎖・HMAC・外部アンカーで検知する。
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
"""


class Store:
    def __init__(self, path: Path | str, clock: Callable[[], float] = time.time):
        self.path = str(path)
        self.now = clock

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 30000")
        conn.execute("PRAGMA synchronous = FULL")
        return conn

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        """BEGIN IMMEDIATE で書込みを直列化。例外時は全体をロールバック。"""
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            else:
                conn.execute("COMMIT")
        finally:
            conn.close()

    @contextmanager
    def read(self) -> Iterator[sqlite3.Connection]:
        conn = self.connect()
        try:
            yield conn
        finally:
            conn.close()

    def migrate(self) -> None:
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        conn = self.connect()
        try:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.executescript(SCHEMA)
            conn.execute(
                "INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            for k, v in (("halted", "0"), ("stop_generation", "0"), ("halt_reason", "")):
                conn.execute(
                    "INSERT OR IGNORE INTO system_state (key, value) VALUES (?, ?)", (k, v)
                )
        finally:
            conn.close()


def get_state(conn: sqlite3.Connection, key: str) -> str:
    row = conn.execute("SELECT value FROM system_state WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else ""


def set_state(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO system_state (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )
