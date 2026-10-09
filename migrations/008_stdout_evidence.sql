-- 008_stdout_evidence.sql：Agent 原始 stdout 证据登记（Gate5-B2 阶段一 v3）
--
-- 设计（Codex 2026-08-12 裁决）：
-- - 两阶段登记：pending → verified（原子发布后）→ failed / quarantined；
-- - 唯一幂等键：UNIQUE(idempotency_hash)（agent + idempotency_key 的不可逆哈希），
--   并发同 key 同内容复用同一记录；同 key 不同内容判 idempotency_conflict；
-- - raw_ref 指向 owner-only 原件（evidence/private/raw/stdout/...，规范化相对路径）；
-- - reviewed_ref 指向真正脱敏副本（evidence/reviewed/stdout/...，非 raw 区）；
-- - raw 与 reviewed 是两个不同文件、两个不同 SHA；
-- - ACL 验证状态、脱敏次数、保留说明均登记；manifest 不含正文/session/prompt/凭据。

CREATE TABLE IF NOT EXISTS stdout_evidence (
    evidence_id         TEXT PRIMARY KEY,
    agent               TEXT NOT NULL,
    raw_ref             TEXT NOT NULL,          -- 相对 evidence/private/raw 的规范化 POSIX 路径
    reviewed_ref        TEXT NOT NULL,          -- 相对 evidence/reviewed 的规范化 POSIX 路径
    raw_sha256          TEXT NOT NULL CHECK (length(raw_sha256) = 64),
    reviewed_sha256     TEXT NOT NULL CHECK (length(reviewed_sha256) = 64),
    idempotency_hash    TEXT NOT NULL UNIQUE,   -- sha256(agent \0 idempotency_key) 前 32 位
    status              TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'verified', 'failed', 'quarantined')),
    acl_verified        INTEGER NOT NULL DEFAULT 0,
    redaction_count     INTEGER NOT NULL DEFAULT 0,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    note                TEXT
);

CREATE INDEX IF NOT EXISTS ix_stdout_evidence_status
    ON stdout_evidence(status);

CREATE INDEX IF NOT EXISTS ix_stdout_evidence_idempotency
    ON stdout_evidence(idempotency_hash);
