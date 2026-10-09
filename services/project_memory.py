"""Explicitly reviewed project checkpoints, independent of any run database.

Local controller publishes; agents only receive a read-only snapshot. This is not
an OS security boundary between processes running as the same Windows user.
Never import personal chats, credentials, or model suggestions automatically.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import stat
from contextlib import closing
from pathlib import Path

from redaction import contains_secret, for_evidence

AGENTS = frozenset({"codex", "hermes", "workbuddy"})
MAX_BODY = 6000
SCHEMA = "triad-project-checkpoint-v1"


class ProjectMemoryError(ValueError):
    """Stable code only; never embed content or database exception text."""


def _encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(value):
    return hashlib.sha256(_encode(value).encode("utf-8")).hexdigest()


def _is_reparse_point(path):
    """Reject symlinks and Windows junctions on Python 3.11 as well as 3.12+."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    return path.is_symlink() or bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _root(root):
    try:
        p = Path(root)
        if not p.is_absolute() or any(_is_reparse_point(x) for x in (p, *p.parents)):
            raise ProjectMemoryError("project_memory_root_invalid")
        return p.resolve()
    except (OSError, TypeError, ValueError):
        raise ProjectMemoryError("project_memory_root_invalid")


def _project(project):
    if not isinstance(project, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", project):
        raise ProjectMemoryError("project_memory_project_invalid")


def _evidence(root, refs):
    if not isinstance(refs, list) or not 1 <= len(refs) <= 16:
        raise ProjectMemoryError("project_memory_evidence_required")
    for ref in refs:
        if not isinstance(ref, dict) or set(ref) != {"path", "sha256"}:
            raise ProjectMemoryError("project_memory_evidence_invalid")
        rel = Path(ref["path"])
        if (rel.is_absolute() or ".." in rel.parts or not rel.parts
                or rel.parts[0] != "evidence" or rel.suffix not in {".md", ".json", ".txt"}
                or not re.fullmatch(r"[a-f0-9]{64}", ref["sha256"])):
            raise ProjectMemoryError("project_memory_evidence_invalid")
        p = root / rel
        if any(_is_reparse_point(x) for x in (p, *p.parents)):
            raise ProjectMemoryError("project_memory_evidence_invalid")
        if not p.resolve().is_relative_to(root) or not p.is_file() or p.stat().st_size > 1_000_000:
            raise ProjectMemoryError("project_memory_evidence_invalid")
        blob = p.read_bytes()
        if hashlib.sha256(blob).hexdigest() != ref["sha256"]:
            raise ProjectMemoryError("project_memory_evidence_changed")
        text = blob.decode("utf-8")
        if contains_secret(text) or for_evidence(text) != text:
            raise ProjectMemoryError("project_memory_secret_detected")


def _validate(root, document):
    if set(document) != {"schema", "project_id", "revision", "previous_digest", "body", "evidence", "reviewed_by"}:
        raise ProjectMemoryError("project_memory_schema_invalid")
    _project(document["project_id"])
    if (document["schema"] != SCHEMA or document["reviewed_by"] != "local_controller"
            or type(document["revision"]) is not int or document["revision"] < 1
            or not re.fullmatch(r"[a-f0-9]{64}", document["previous_digest"])):
        raise ProjectMemoryError("project_memory_schema_invalid")
    body = document["body"]
    if not isinstance(body, str) or not body.strip() or len(body) > MAX_BODY:
        raise ProjectMemoryError("project_memory_body_invalid")
    if contains_secret(document) or for_evidence(body) != body:
        raise ProjectMemoryError("project_memory_secret_detected")
    _evidence(root, document["evidence"])


def _connect(root, *, writable=False):
    p = root / "project_memory.sqlite3"
    if not p.is_file() or _is_reparse_point(p):
        raise ProjectMemoryError("project_memory_unavailable")
    conn = sqlite3.connect(p.as_uri() + ("?mode=rw" if writable else "?mode=ro"), uri=True, timeout=2)
    if not writable:
        conn.execute("PRAGMA query_only=ON")
    return conn


def initialize(root):
    """Explicit creation only. Reads never create a missing database."""
    root = _root(root)
    root.mkdir(parents=True, exist_ok=True)
    p = root / "project_memory.sqlite3"
    # Exclusive reservation, including a concurrent initialization attempt.
    with p.open("xb"):
        pass
    with closing(sqlite3.connect(p)) as conn, conn:
        conn.execute("CREATE TABLE checkpoints (project_id TEXT NOT NULL, revision INTEGER NOT NULL, "
                     "digest TEXT NOT NULL, document TEXT NOT NULL, PRIMARY KEY(project_id,revision))")
    return root


def publish_reviewed(root, project_id, *, body, evidence, expected_revision, expected_digest):
    """Append one controller-reviewed checkpoint, compare-and-swap under SQLite lock.

    No agent adapter or HTTP endpoint exposes this write operation. Caller must
    review content and evidence; hash matching proves provenance, not truth.
    """
    root = _root(root)
    _project(project_id)
    if type(expected_revision) is not int or expected_revision < 0:
        raise ProjectMemoryError("project_memory_revision_invalid")
    if not isinstance(expected_digest, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_digest):
        raise ProjectMemoryError("project_memory_digest_invalid")
    doc = {"schema": SCHEMA, "project_id": project_id, "revision": expected_revision + 1,
           "previous_digest": expected_digest, "body": body, "evidence": evidence,
           "reviewed_by": "local_controller"}
    try:
        _validate(root, doc)
        with closing(_connect(root, writable=True)) as conn, conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT revision,digest FROM checkpoints WHERE project_id=? "
                               "ORDER BY revision DESC LIMIT 1", (project_id,)).fetchone()
            if (row or (0, "0" * 64)) != (expected_revision, expected_digest):
                raise ProjectMemoryError("project_memory_revision_conflict")
            digest = _digest(doc)
            conn.execute("INSERT INTO checkpoints VALUES(?,?,?,?)",
                         (project_id, doc["revision"], digest, _encode(doc)))
        return {"project_id": project_id, "revision": doc["revision"], "digest": digest}
    except ProjectMemoryError:
        raise
    except (OSError, sqlite3.Error, TypeError, ValueError, KeyError):
        raise ProjectMemoryError("project_memory_publish_failed") from None


def read_snapshot(root, project_id, agent):
    if agent not in AGENTS:
        raise ProjectMemoryError("project_memory_agent_denied")
    root = _root(root)
    _project(project_id)
    try:
        with closing(_connect(root)) as conn, conn:
            row = conn.execute("SELECT revision,digest,document FROM checkpoints WHERE project_id=? "
                               "ORDER BY revision DESC LIMIT 1", (project_id,)).fetchone()
            if not row:
                raise ProjectMemoryError("project_memory_checkpoint_missing")
            doc = json.loads(row[2])
            _validate(root, doc)
            if doc["project_id"] != project_id or doc["revision"] != row[0] or _digest(doc) != row[1]:
                raise ProjectMemoryError("project_memory_digest_mismatch")
            predecessor = conn.execute("SELECT digest FROM checkpoints WHERE project_id=? AND revision=?",
                                       (project_id, row[0] - 1)).fetchone()
            if doc["previous_digest"] != (predecessor[0] if predecessor else "0" * 64):
                raise ProjectMemoryError("project_memory_history_invalid")
        return {**doc, "digest": row[1]}
    except ProjectMemoryError:
        raise
    except (OSError, sqlite3.Error, TypeError, ValueError, KeyError):
        raise ProjectMemoryError("project_memory_unavailable") from None
