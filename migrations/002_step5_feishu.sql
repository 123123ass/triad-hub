-- 002_step5_feishu：可靠出站字段补齐（Step 5.1.1）
-- 仅新增列与索引，不改动既有数据。

ALTER TABLE outbox ADD COLUMN external_message_id TEXT;
ALTER TABLE outbox ADD COLUMN last_error_redacted TEXT;
ALTER TABLE outbox ADD COLUMN claimed_by TEXT;
ALTER TABLE outbox ADD COLUMN claimed_at TEXT;
ALTER TABLE outbox ADD COLUMN delivery_unknown_at TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_outbox_event_bot
ON outbox(event_seq, bot_identity);

CREATE INDEX IF NOT EXISTS idx_outbox_claim
ON outbox(state, next_attempt_at, created_at);

CREATE INDEX IF NOT EXISTS idx_delivery_claim
ON deliveries(state, next_attempt_at, event_seq);
