-- Triad Hub Phase 1 数据库结构 (version 001)
-- 单一事实源：事件/投递/调用/游标/任务/审计全部落库，WAL 模式。

PRAGMA busy_timeout=30000;
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA synchronous=NORMAL;

-- 迁移记录
CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL,
    checksum TEXT
);

-- 事件（统一 envelope 入站契约）
CREATE TABLE IF NOT EXISTS events (
    event_seq      INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id       TEXT UNIQUE NOT NULL,
    idempotency_key TEXT UNIQUE,
    trace_id       TEXT,
    parent_event_id TEXT,
    root_event_id  TEXT,
    source_agent   TEXT,
    source_type    TEXT,
    source_id      TEXT,
    message_type   TEXT,
    text           TEXT,
    mentions_json  TEXT,
    refs_json      TEXT,
    payload_json   TEXT,
    hop_count      INTEGER DEFAULT 0,
    max_hops       INTEGER DEFAULT 2,
    created_at     TEXT,
    received_at    TEXT
);

-- 内容签名去重（仅 120s 窗口，不永久唯一）
CREATE TABLE IF NOT EXISTS event_dedup (
    signature     TEXT PRIMARY KEY,
    first_event_id TEXT,
    expires_at    TEXT
);

-- 消息（四方可见原文）
CREATE TABLE IF NOT EXISTS messages (
    message_id      TEXT PRIMARY KEY,
    event_seq       INTEGER UNIQUE,
    speaker         TEXT,
    text            TEXT,
    feishu_message_id TEXT,
    visible_state   TEXT DEFAULT 'visible',
    created_at      TEXT,
    FOREIGN KEY(event_seq) REFERENCES events(event_seq)
);

-- Agent 绑定（物理会话隔离）
CREATE TABLE IF NOT EXISTS agent_bindings (
    agent            TEXT PRIMARY KEY,
    logical_session  TEXT UNIQUE,
    actual_session_id TEXT,
    adapter          TEXT,
    status           TEXT,
    binding_version  INTEGER DEFAULT 1,
    verified_at      TEXT,
    metadata_json    TEXT
);

-- 消费游标（记忆注入核心）
CREATE TABLE IF NOT EXISTS consumer_cursors (
    agent            TEXT PRIMARY KEY,
    last_consumed_event_seq INTEGER NOT NULL DEFAULT 0,
    updated_at       TEXT,
    FOREIGN KEY(agent) REFERENCES agent_bindings(agent)
);

-- 共享摘要
CREATE TABLE IF NOT EXISTS shared_summaries (
    summary_id     TEXT PRIMARY KEY,
    from_event_seq INTEGER,
    to_event_seq   INTEGER,
    summary_text   TEXT,
    status         TEXT,
    proposed_by    TEXT,
    verified_by    TEXT,
    created_at     TEXT,
    UNIQUE(from_event_seq, to_event_seq)
);

CREATE TABLE IF NOT EXISTS summary_evidence (
    summary_id TEXT,
    event_seq  INTEGER,
    PRIMARY KEY(summary_id, event_seq),
    FOREIGN KEY(summary_id) REFERENCES shared_summaries(summary_id),
    FOREIGN KEY(event_seq) REFERENCES events(event_seq)
);

-- 任务状态机
CREATE TABLE IF NOT EXISTS tasks (
    task_id            TEXT PRIMARY KEY,
    owner              TEXT,
    objective          TEXT,
    acceptance_criteria TEXT,
    trace_id           TEXT UNIQUE,
    state              TEXT,
    result_ref         TEXT,
    evidence_refs_json TEXT,
    revision           INTEGER DEFAULT 0,
    created_at         TEXT,
    updated_at         TEXT
);

CREATE TABLE IF NOT EXISTS task_events (
    task_event_id      TEXT PRIMARY KEY,
    task_id            TEXT,
    revision           INTEGER,
    from_state         TEXT,
    to_state           TEXT,
    actor              TEXT,
    evidence_refs_json TEXT,
    created_at         TEXT,
    UNIQUE(task_id, revision),
    FOREIGN KEY(task_id) REFERENCES tasks(task_id)
);

-- 调用尝试（真实性元数据）
CREATE TABLE IF NOT EXISTS call_attempts (
    call_id            TEXT PRIMARY KEY,
    event_seq          TEXT,
    agent              TEXT,
    idempotency_key    TEXT UNIQUE,
    state              TEXT,
    requested_session_id TEXT,
    actual_session_id  TEXT,
    command_mode       TEXT,
    trace_id           TEXT,
    attempt_no         INTEGER,
    lease_expires_at   TEXT,
    started_at         TEXT,
    completed_at       TEXT,
    exit_code          INTEGER,
    stdout_ref         TEXT,
    error_code         TEXT,
    error_message_redacted TEXT,
    FOREIGN KEY(event_seq) REFERENCES events(event_seq)
);

-- Agent 租约（单会话单 writer）
CREATE TABLE IF NOT EXISTS agent_leases (
    agent       TEXT PRIMARY KEY,
    holder_id   TEXT,
    call_id     TEXT,
    acquired_at TEXT,
    expires_at  TEXT,
    FOREIGN KEY(agent) REFERENCES agent_bindings(agent)
);

-- 投递（每条消息每目标一次）
CREATE TABLE IF NOT EXISTS deliveries (
    delivery_id     TEXT PRIMARY KEY,
    event_seq       INTEGER,
    destination     TEXT,
    bot_identity    TEXT,
    state           TEXT,
    attempt_no      INTEGER DEFAULT 0,
    next_attempt_at TEXT,
    external_message_id TEXT,
    last_error_redacted TEXT,
    UNIQUE(event_seq, destination, bot_identity),
    FOREIGN KEY(event_seq) REFERENCES events(event_seq)
);

-- 出站（可靠 at-least-once）
CREATE TABLE IF NOT EXISTS outbox (
    outbox_id    TEXT PRIMARY KEY,
    event_seq    INTEGER,
    bot_identity TEXT,
    payload_json TEXT,
    state        TEXT,
    attempt_no   INTEGER DEFAULT 0,
    next_attempt_at TEXT,
    created_at   TEXT,
    sent_at      TEXT,
    FOREIGN KEY(event_seq) REFERENCES events(event_seq)
);

-- 死信
CREATE TABLE IF NOT EXISTS dead_letters (
    dead_letter_id TEXT PRIMARY KEY,
    source_table   TEXT,
    source_id      TEXT,
    reason_code    TEXT,
    payload_ref    TEXT,
    created_at     TEXT,
    resolved_at    TEXT
);

-- trace 控制（pause/stop）
CREATE TABLE IF NOT EXISTS trace_controls (
    trace_id   TEXT PRIMARY KEY,
    state      TEXT,
    changed_by TEXT,
    changed_at TEXT
);

-- 审计（脱敏）
CREATE TABLE IF NOT EXISTS audit_events (
    audit_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    action    TEXT,
    actor     TEXT,
    trace_id  TEXT,
    object_type TEXT,
    object_id TEXT,
    metadata_redacted_json TEXT,
    created_at TEXT
);
