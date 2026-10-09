"""Triad Hub 迁移脚本。

- 迁移前自动备份 triad.db（含 -wal/-shm）。
- 001_phase1_hub：旧表改名 _legacy_20260807 -> 数据映射 -> 写 schema_migrations。
- 增量迁移（002_step5_feishu、003_step6_context ...）：由 db.apply_migrations 按 schema_migrations
  跳过已应用版本、幂等、写 checksum；应用前同样自动备份。
- 任一事务失败整体回滚。
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import sqlite3
import time
from pathlib import Path

from config import config
from db import connect, transaction

LEGACY_SUFFIX = "_legacy_20260807"
MIG_VERSION = "001_phase1_hub"
OLD_TABLES = ["events", "identities", "messages", "tasks"]


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())


_SAFE_SESSION_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def _logical_session_case() -> str:
    """由 config.LOGICAL_SESSIONS 生成 agent -> logical_session 的 SQL CASE 分支。

    Gate3 Q5（Codex 裁决）：迁移脚本不得提供公开硬编码的会话字面量。逻辑会话名统一
    引用 config 单一事实源；物理会话 id 始终取 legacy 表的 physical_session 列，
    迁移脚本本身永不产生任何物理 id 默认值。

    只做常量拼接（非外部输入），仍强制字符白名单，杜绝任何注入面。
    """
    parts = []
    for agent, logical in config.LOGICAL_SESSIONS.items():
        if not _SAFE_SESSION_RE.match(str(agent)) or not _SAFE_SESSION_RE.match(str(logical)):
            raise ValueError(f"unsafe logical session mapping for agent={agent!r}")
        parts.append(f"WHEN '{agent}' THEN '{logical}'")
    if not parts:
        raise ValueError("config.LOGICAL_SESSIONS is empty")
    return " ".join(parts)


def _backup_before_migrate(conn: sqlite3.Connection) -> str:
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.commit()
    src = config.DB_PATH
    ts = time.strftime("%Y%m%d_%H%M%S")
    dst = str(Path(src).parent / f"backups/migration_pre_{ts}.db")
    Path(dst).parent.mkdir(parents=True, exist_ok=True)
    for suf in ("", "-wal", "-shm"):
        s = src + suf
        if os.path.exists(s):
            shutil.copy2(s, dst + suf)
    return dst


def _split_sql(sql: str):
    out = []
    for part in sql.split(";"):
        p = part.strip()
        if p:
            out.append(p)
    return out


def _old_counts(conn: sqlite3.Connection) -> dict:
    c = {}
    for t in OLD_TABLES:
        try:
            c[t] = conn.execute(f'SELECT count(*) FROM "{t}"').fetchone()[0]
        except Exception:
            c[t] = 0
    return c


def _pending_versions(conn: sqlite3.Connection) -> list:
    """尚未应用（不在 schema_migrations）的迁移版本，按文件名排序。"""
    mig_dir = Path(__file__).parent / "migrations"
    existing = {r["version"] for r in conn.execute("SELECT version FROM schema_migrations")}
    files = sorted(mig_dir.glob("*.sql"))
    return [f.stem for f in files if f.stem not in existing]


def _apply_001_legacy(conn: sqlite3.Connection) -> dict:
    """执行 001 旧表改名 + 数据映射（非 dry-run 专用）。"""
    sql_path = Path(__file__).parent / "migrations" / "001_phase1_hub.sql"
    sql = sql_path.read_text(encoding="utf-8")
    checksum = hashlib.sha256(sql.encode("utf-8")).hexdigest()
    old_counts = _old_counts(conn)
    stmts = _split_sql(sql)
    pragmas = [s for s in stmts if s.upper().startswith("PRAGMA")]
    ddls = [s for s in stmts if not s.upper().startswith("PRAGMA")]
    for p in pragmas:
        try:
            conn.execute(p)
        except Exception as e:
            print(f"[migrate] pragma skipped: {e}")
    with transaction(conn, immediate=True, operation="_apply_001_legacy", role="hub"):
        for t in OLD_TABLES:
            conn.execute(f'ALTER TABLE "{t}" RENAME TO "{t}{LEGACY_SUFFIX}"')
        for d in ddls:
            conn.execute(d)
        conn.execute(
            f"""INSERT INTO agent_bindings(agent, logical_session, actual_session_id, adapter, status, binding_version, verified_at, metadata_json)
               SELECT agent,
                 CASE agent {_logical_session_case()} ELSE agent END,
                 physical_session, kind, status, 1, datetime('now'), '{{}}'
               FROM identities_legacy_20260807"""
        )
        conn.execute(
            """INSERT INTO events(event_seq, event_id, source_agent, message_type, text, payload_json, created_at)
               SELECT event_seq, event_id, source, type, '', payload, ts FROM events_legacy_20260807"""
        )
        conn.execute(
            """INSERT INTO messages(message_id, event_seq, speaker, text, created_at)
               SELECT 'm'||id, event_seq, agent, text, ts FROM messages_legacy_20260807"""
        )
        conn.execute(
            """INSERT INTO tasks(task_id, owner, objective, acceptance_criteria, trace_id, state, result_ref, evidence_refs_json, revision, created_at, updated_at)
               SELECT task_id, owner, objective, acceptance_criteria, trace_id, state, result_ref,
                 CASE WHEN evidence_refs IS NULL OR evidence_refs='' THEN '[]' ELSE '["'||evidence_refs||'"]' END,
                 0, created_ts, created_ts
               FROM tasks_legacy_20260807"""
        )
        conn.execute(
            "INSERT INTO schema_migrations(version, applied_at, checksum) VALUES(?,?,?)",
            (MIG_VERSION, _now(), checksum),
        )
    new_counts = {
        "agent_bindings": conn.execute("SELECT count(*) FROM agent_bindings").fetchone()[0],
        "events": conn.execute("SELECT count(*) FROM events").fetchone()[0],
        "messages": conn.execute("SELECT count(*) FROM messages").fetchone()[0],
        "tasks": conn.execute("SELECT count(*) FROM tasks").fetchone()[0],
    }
    return {"old_counts": old_counts, "new_counts": new_counts, "checksum": checksum}


def migrate_apply(dry_run: bool = False) -> dict:
    import db

    conn = connect()
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations(version TEXT PRIMARY KEY, applied_at TEXT NOT NULL, checksum TEXT)"
        )
        already_001 = conn.execute(
            "SELECT 1 FROM schema_migrations WHERE version=?", (MIG_VERSION,)
        ).fetchone()
        tables = {
            row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        legacy_present = set(OLD_TABLES) & tables
        fresh = not already_001 and tables <= {"schema_migrations"}
        if not already_001 and not fresh and legacy_present != set(OLD_TABLES):
            raise RuntimeError("unsupported_partial_schema")
        pending = _pending_versions(conn)

        if dry_run:
            print(f"[migrate DRY-RUN] already_001={bool(already_001)}")
            print(f"[migrate DRY-RUN] pending_migrations={pending}")
            if not already_001:
                print("[migrate DRY-RUN] would create fresh schema" if fresh
                      else "[migrate DRY-RUN] would run 001_phase1_hub legacy rename+map")
            return {"dry_run": True, "already_001": bool(already_001),
                    "fresh": fresh, "pending": pending}

        if fresh:
            applied = db.apply_migrations(conn)
            print(f"[migrate] fresh schema applied={applied}")
            return {"fresh": True, "applied_incremental": applied}

        if not already_001:
            res = _apply_001_legacy(conn)
            print("[migrate] APPLIED 001_phase1_hub (legacy rename+map)")
            print(f"  old_counts={res['old_counts']}")
            print(f"  new_counts={res['new_counts']}")
            print(f"  checksum={res['checksum']}")

        pending = _pending_versions(conn)
        if pending:
            backup = _backup_before_migrate(conn)
            applied = db.apply_migrations(conn)
            print(f"[migrate] incremental applied={applied}")
            print(f"  backup={backup}")
            return {"applied_incremental": applied, "backup": backup}
        return {"nothing_to_apply": True}
    except Exception as e:
        print(f"[migrate] FAILED, rolled back: {e}")
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    import sys

    dry = "--dry-run" in sys.argv
    migrate_apply(dry_run=dry)
