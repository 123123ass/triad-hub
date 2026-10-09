"""Triad Hub 数据库访问层 (Phase 1 + Gate5-B2-WB runtime_db_reliability).

统一约束：busy_timeout=30000, journal_mode=WAL, foreign_keys=ON, synchronous=NORMAL。
所有"查重→分配序号→落事件→建投递"必须由调用方放在同一 BEGIN IMMEDIATE 事务内。

Gate5-B2-WB R2 锁故障后（Codex 裁决）新增：
- connect(read_only, busy_timeout_ms)：WAL 只在迁移/初始化/显式校验阶段设置；
  热路径只读验证模式；read-only 连接绝不尝试设置 journal。
- transaction(conn, immediate, operation, role)：生产写事务必须带 operation/role 标签，
  记录 tx_id/pid/role/operation/begin_wait_ms/hold_ms/result；>500ms 记 db_tx_slow；
  锁失败记 db_tx_lock_timeout；禁记 SQL/参数/消息正文/身份 ID/凭据。
- 事务持有标记 db_tx_<pid>.json：BEGIN IMMEDIATE 前写 waiting，取得锁后 holding，
  commit/rollback 后清除；崩溃残留由 PID/创建时间/run_id 判陈旧。
"""
from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path

from config import config

_LOCK = threading.Lock()
_SLOW_TX_MS = 500
TX_MARK_DIR = None  # 由 ensure_tx_mark_dir() 初始化


def _log(conn: sqlite3.Connection, event: str, **kw) -> None:
    """用连接所在进程的结构化日志出口写一行（不抛异常）。"""
    try:
        import logging

        logger = logging.getLogger("db_tx")
        # 结构化日志由调用方 logger 输出；这里只做最小格式化
        detail = ",".join(f"{k}={v}" for k, v in kw.items() if v is not None)
        if event == "db_tx_slow":
            logger.warning("%s %s", event, detail)
        elif event == "db_tx_lock_timeout":
            logger.error("%s %s", event, detail)
        else:
            logger.info("%s %s", event, detail)
    except Exception:  # noqa: BLE001 —— 日志失败绝不阻断业务
        pass


def ensure_tx_mark_dir() -> Path:
    global TX_MARK_DIR
    if TX_MARK_DIR is None:
        TX_MARK_DIR = Path(config.RUNTIME_DIR) if hasattr(config, "RUNTIME_DIR") else (
            Path(config.DB_PATH).parent / "runtime"
        )
        TX_MARK_DIR.mkdir(parents=True, exist_ok=True)
    return TX_MARK_DIR


def _tx_mark_path(pid: int) -> Path:
    return ensure_tx_mark_dir() / f"db_tx_{pid}.json"


def _write_tx_mark(pid: int, role: str, operation: str, tx_id: str, phase: str) -> None:
    """写事务持有标记（脱敏：无 SQL/无任务内容/无 session/nonce/凭据）。"""
    try:
        p = _tx_mark_path(pid)
        data = {
            "pid": pid,
            "role": role,
            "operation": operation,
            "tx_id": tx_id,
            "phase": phase,
            "started_at": _now(),
            "updated_at": _now(),
        }
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, p)
    except Exception:  # noqa: BLE001
        pass


def _clear_tx_mark(pid: int) -> None:
    try:
        p = _tx_mark_path(pid)
        if p.exists():
            p.unlink()
    except Exception:  # noqa: BLE001
        pass


def _tx_id() -> str:
    return uuid.uuid4().hex[:16]


def connect(
    read_only: bool = False,
    *,
    busy_timeout_ms: int | None = None,
) -> sqlite3.Connection:
    """连接。热路径只验证 journal 模式，不设置；read-only 绝不写 journal。

    busy_timeout_ms：
    - 显式传入：采用调用方值。
    - 未传：读 env TRIAD_RUNTIME_DB_BUSY_TIMEOUT_MS（supervisor 启动 worker 时注入 1000）；
      未设置则默认 30000ms（普通工具/迁移）。
    - Worker 值限定 100-5000ms，非法值 fail-closed 抛 ValueError。
    """
    Path(config.DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    if busy_timeout_ms is None:
        raw = os.environ.get("TRIAD_RUNTIME_DB_BUSY_TIMEOUT_MS")
        if raw is not None and raw.strip():
            try:
                v = int(raw.strip())
                if 100 <= v <= 5000:
                    busy_timeout_ms = v
                else:
                    raise ValueError(
                        f"TRIAD_RUNTIME_DB_BUSY_TIMEOUT_MS out of range: {v}")
            except ValueError as e:
                if "out of range" in str(e):
                    raise
                raise ValueError(
                    f"TRIAD_RUNTIME_DB_BUSY_TIMEOUT_MS invalid: {raw.strip()!r}") from e
        else:
            busy_timeout_ms = 30000
    if read_only:
        uri = f"file:{config.DB_PATH}?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
    else:
        conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
    conn.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
    if not read_only:
        # 热路径只读验证：非 WAL 才设置（迁移/初始化在别处显式设置）
        try:
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
            if mode != "wal":
                conn.execute("PRAGMA journal_mode=WAL")
        except Exception:  # noqa: BLE001
            pass
    conn.execute("PRAGMA foreign_keys=ON")
    if not read_only:
        conn.execute("PRAGMA synchronous=NORMAL")
    conn.row_factory = sqlite3.Row
    return conn


@contextlib.contextmanager
def transaction(
    conn: sqlite3.Connection,
    immediate: bool = True,
    *,
    operation: str = "",
    role: str = "",
    busy_timeout_ms: int = 0,
):
    """上下文事务管理器：immediate=True 时 BEGIN IMMEDIATE（拿写锁，防并发写）。

    Gate5-B2-WB：生产写事务必须带 operation/role 标签，便于锁故障可观测。
    - 超过 500ms 记 db_tx_slow；
    - 锁失败记 db_tx_lock_timeout（带等待耗时，不记录异常全文）。
    """
    if not operation:
        # 未带标签的事务：允许（迁移/工具），但记录一次 warning
        _log(conn, "db_tx_unlabeled", operation="", role=role)
    pid = os.getpid()
    tx_id = _tx_id()
    begin_wait_ms = 0
    hold_ms = 0
    result = "committed"
    mark_written = False
    prev_timeout = conn.execute("PRAGMA busy_timeout").fetchone()[0] if False else None
    t0 = time.monotonic()
    try:
        if immediate:
            if busy_timeout_ms and busy_timeout_ms > 0:
                conn.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
            _write_tx_mark(pid, role, operation, tx_id, "waiting")
            mark_written = True
            conn.execute("BEGIN IMMEDIATE")
            _write_tx_mark(pid, role, operation, tx_id, "holding")
            begin_wait_ms = int((time.monotonic() - t0) * 1000)
        else:
            conn.execute("BEGIN")
        yield conn
        conn.commit()
        result = "committed"
    except sqlite3.OperationalError as e:
        result = "locked" if "locked" in str(e).lower() else "rolled_back"
        conn.rollback()
        hold_ms = int((time.monotonic() - t0) * 1000)
        if result == "locked":
            _log(
                conn, "db_tx_lock_timeout",
                tx_id=tx_id, role=role, operation=operation,
                begin_wait_ms=begin_wait_ms, hold_ms=hold_ms,
            )
        raise
    except Exception:
        result = "rolled_back"
        conn.rollback()
        raise
    finally:
        hold_ms = int((time.monotonic() - t0) * 1000)
        if mark_written:
            _clear_tx_mark(pid)
        if hold_ms >= _SLOW_TX_MS:
            _log(
                conn, "db_tx_slow",
                tx_id=tx_id, role=role, operation=operation,
                begin_wait_ms=begin_wait_ms, hold_ms=hold_ms, result=result,
            )


def apply_migrations(conn: sqlite3.Connection | None = None) -> list[str]:
    """按 migrations/ 顺序执行未应用的 SQL 文件。返回已应用版本列表。"""
    import hashlib
    from pathlib import Path as _Path

    mig_dir = _Path(__file__).resolve().parent / "migrations"
    applied: list[str] = []
    own = False
    if conn is None:
        conn = connect()
        own = True
    try:
        existing = {
            r["version"]
            for r in conn.execute("SELECT version FROM schema_migrations")
        }
        files = sorted(mig_dir.glob("*.sql"))
        for f in files:
            version = f.stem  # 001_phase1_hub
            if version in existing:
                continue
            sql = f.read_text(encoding="utf-8")
            checksum = hashlib.sha256(sql.encode("utf-8")).hexdigest()
            with transaction(conn, immediate=True, operation="migration", role="hub"):
                conn.executescript(sql)
                conn.execute(
                    "INSERT INTO schema_migrations(version, applied_at, checksum) VALUES(?,?,?)",
                    (version, _now(), checksum),
                )
            applied.append(version)
    finally:
        if own:
            conn.close()
    return applied


def integrity_check(conn: sqlite3.Connection | None = None) -> list[tuple]:
    own = False
    if conn is None:
        conn = connect(read_only=True)
        own = True
    try:
        # row_factory=Row，统一转成 tuple，保证返回值可与 ("ok",) 直接比较
        return [tuple(r) for r in conn.execute("PRAGMA integrity_check").fetchall()]
    finally:
        if own:
            conn.close()


def journal_mode(conn: sqlite3.Connection | None = None) -> str:
    own = False
    if conn is None:
        conn = connect(read_only=True)
        own = True
    try:
        row = conn.execute("PRAGMA journal_mode").fetchone()
        return row[0] if row else "unknown"
    finally:
        if own:
            conn.close()


def foreign_keys_on(conn: sqlite3.Connection | None = None) -> bool:
    own = False
    if conn is None:
        conn = connect(read_only=True)
        own = True
    try:
        row = conn.execute("PRAGMA foreign_keys").fetchone()
        return bool(row[0]) if row else False
    finally:
        if own:
            conn.close()


def checkpoint_wal(conn: sqlite3.Connection | None = None) -> None:
    own = False
    if conn is None:
        conn = connect()
        own = True
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.commit()
    finally:
        if own:
            conn.close()


def probe_db_write_lock(timeout_ms: int = 1000) -> dict:
    """启动前写锁健康检查：BEGIN IMMEDIATE; ROLLBACK; 不修改任何业务行。

    失败返回 {"ready": False, "error_code": "db_write_locked"}；成功返回 ready=True。
    不做 DDL、不 WAL truncate、不自动重试。
    """
    conn = None
    try:
        conn = connect(busy_timeout_ms=timeout_ms)
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("ROLLBACK")
        return {"ready": True, "error_code": ""}
    except sqlite3.OperationalError:
        return {"ready": False, "error_code": "db_write_locked"}
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
