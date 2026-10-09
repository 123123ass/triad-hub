-- Triad Hub Step 7 数据库结构 (version 004_step7_adapters_call)
-- 三 Adapter 调用队列 + call worker 支持。
-- 仅增量、可重复应用（apply_migrations 按 schema_migrations 跳过已应用版本）。

PRAGMA busy_timeout=30000;
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA synchronous=NORMAL;

-- deliveries：调用队列所需字段（claim/waiting/blocked/result_unknown 等状态机）
ALTER TABLE deliveries ADD COLUMN trace_id TEXT;
ALTER TABLE deliveries ADD COLUMN task_id TEXT;
ALTER TABLE deliveries ADD COLUMN claimed_by TEXT;
ALTER TABLE deliveries ADD COLUMN claimed_at TEXT;
ALTER TABLE deliveries ADD COLUMN call_id TEXT;
ALTER TABLE deliveries ADD COLUMN completed_at TEXT;

-- call_attempts：commit_agent_reply 原子提交所需扩展字段
ALTER TABLE call_attempts ADD COLUMN delivery_id TEXT;
ALTER TABLE call_attempts ADD COLUMN context_packet_id TEXT;
ALTER TABLE call_attempts ADD COLUMN claimed_by TEXT;
ALTER TABLE call_attempts ADD COLUMN claimed_at TEXT;
ALTER TABLE call_attempts ADD COLUMN result_ref TEXT;
ALTER TABLE call_attempts ADD COLUMN response_event_seq INTEGER;
ALTER TABLE call_attempts ADD COLUMN result_unknown_at TEXT;

-- agent_bindings：preverified 标记（Hermes 未回显 session 时由 adapter 标记）
ALTER TABLE agent_bindings ADD COLUMN preverified INTEGER DEFAULT 0;

-- 索引
CREATE INDEX IF NOT EXISTS idx_deliveries_claim
    ON deliveries(destination, state, claimed_by, next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_call_attempts_agent_state
    ON call_attempts(agent, state);
