"""Offline tests suitable for the curated public beta package."""
from __future__ import annotations

import hashlib
import sqlite3

import pytest

from services.project_memory import ProjectMemoryError, initialize, publish_reviewed, read_snapshot


def test_core_modules_import_without_credentials():
    import adapters.feishu  # noqa: F401
    import adapters.wb_cli  # noqa: F401
    import context_builder  # noqa: F401
    import main  # noqa: F401
    import run_triad_runtime  # noqa: F401


def test_reviewed_checkpoint_is_shared_and_fails_on_tamper(tmp_path):
    root = tmp_path / "checkpoint"
    initialize(root)
    evidence = root / "evidence" / "review.md"
    evidence.parent.mkdir()
    evidence.write_text("Synthetic review evidence only.", encoding="utf-8")
    refs = [{"path": "evidence/review.md", "sha256": hashlib.sha256(evidence.read_bytes()).hexdigest()}]
    published = publish_reviewed(root, "demo", body="Verified synthetic project fact.", evidence=refs,
                                 expected_revision=0, expected_digest="0" * 64)
    snapshots = [read_snapshot(root, "demo", agent) for agent in ("codex", "hermes", "workbuddy")]
    assert snapshots[0] == snapshots[1] == snapshots[2]
    assert snapshots[0]["revision"] == published["revision"] == 1
    evidence.write_text("Changed after review.", encoding="utf-8")
    with pytest.raises(ProjectMemoryError, match="project_memory_evidence_changed"):
        read_snapshot(root, "demo", "codex")


def test_fresh_database_migrates_without_legacy_tables(tmp_path, monkeypatch):
    import db
    import migrate
    from config import config

    path = tmp_path / "triad.db"
    monkeypatch.setattr(config, "DB_PATH", str(path))
    monkeypatch.setattr(config, "RUNTIME_DIR", str(tmp_path / "runtime"), raising=False)
    monkeypatch.setattr(db, "TX_MARK_DIR", None)
    result = migrate.migrate_apply()
    assert result["fresh"] is True
    with sqlite3.connect(path) as conn:
        assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert conn.execute("SELECT count(*) FROM schema_migrations").fetchone()[0] == 8
