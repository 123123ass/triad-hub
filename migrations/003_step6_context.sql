-- Triad Hub Step 6 数据库结构 (version 003_step6_context)
-- 共享上下文与摘要机制。
-- 仅增量、可重复应用（apply_migrations 按 schema_migrations 跳过已应用版本）。
-- 上下文包只保存范围/哈希/证据序号，不保存完整 prompt 或原始事件全文。

PRAGMA busy_timeout=30000;
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA synchronous=NORMAL;

-- shared_summaries 扩充：facts / digest / 验证时间 / 脱敏拒绝原因
ALTER TABLE shared_summaries ADD COLUMN facts_json TEXT;
ALTER TABLE shared_summaries ADD COLUMN source_digest TEXT;
ALTER TABLE shared_summaries ADD COLUMN verified_at TEXT;
ALTER TABLE shared_summaries ADD COLUMN rejection_reason_redacted TEXT;

-- events 增加 task_id（003 前 events 无独立 task_id 列）
ALTER TABLE events ADD COLUMN task_id TEXT;
CREATE INDEX IF NOT EXISTS idx_events_task ON events(task_id, event_seq);

-- 上下文包审计（每给 Agent 注入一次上下文一条）
CREATE TABLE IF NOT EXISTS context_packets (
    packet_id TEXT PRIMARY KEY,
    agent TEXT NOT NULL,
    trigger_event_seq INTEGER NOT NULL,
    last_consumed_event_seq INTEGER NOT NULL,
    through_event_seq INTEGER NOT NULL,
    summary_id TEXT,
    summary_from_seq INTEGER,
    summary_to_seq INTEGER,
    delta_from_seq INTEGER,
    delta_to_seq INTEGER,
    required_event_seqs_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    delivered_at TEXT,
    consumed_at TEXT,
    failure_code TEXT,
    FOREIGN KEY(agent) REFERENCES agent_bindings(agent),
    FOREIGN KEY(trigger_event_seq) REFERENCES events(event_seq),
    FOREIGN KEY(summary_id) REFERENCES shared_summaries(summary_id)
);

-- 游标历史（consumed 才新增一条，delivered/failed/build 不新增）
CREATE TABLE IF NOT EXISTS consumer_cursor_history (
    cursor_event_id TEXT PRIMARY KEY,
    agent TEXT NOT NULL,
    packet_id TEXT NOT NULL,
    previous_event_seq INTEGER NOT NULL,
    new_event_seq INTEGER NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(agent, packet_id),
    FOREIGN KEY(agent) REFERENCES agent_bindings(agent),
    FOREIGN KEY(packet_id) REFERENCES context_packets(packet_id)
);

CREATE INDEX IF NOT EXISTS idx_summary_verified_range
ON shared_summaries(status, to_event_seq DESC);

CREATE INDEX IF NOT EXISTS idx_context_agent_state
ON context_packets(agent, state, created_at);

CREATE INDEX IF NOT EXISTS idx_context_trigger
ON context_packets(trigger_event_seq);

CREATE INDEX IF NOT EXISTS idx_cursor_history_agent
ON consumer_cursor_history(agent, created_at);
