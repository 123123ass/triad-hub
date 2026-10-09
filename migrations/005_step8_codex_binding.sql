-- Step 8: 绑定验真表（triad-codex-main 专用 Codex 任务建立过程的真实性证据）
-- 版本：005_step8_codex_binding
-- 审计铁律：已应用迁移（001–004）不可修改；本文件为新增迁移，应用前自动备份。

CREATE TABLE IF NOT EXISTS binding_verifications (
    verification_id     TEXT PRIMARY KEY,
    agent               TEXT NOT NULL,
    logical_session     TEXT NOT NULL,
    requested_session_id TEXT,
    actual_session_id   TEXT,
    verification_type   TEXT NOT NULL,   -- fresh_create | resume_nonce | continuity_check | binding_commit
    command_mode        TEXT NOT NULL,   -- fresh | resume
    nonce_hash          TEXT,
    bootstrap_manifest_hash TEXT,
    exit_code           INTEGER,
    evidence_ref        TEXT,            -- 仅存相对路径（evidence/bindings/...）
    status              TEXT NOT NULL,   -- created | verified | failed | orphaned_unbound | superseded
    error_code          TEXT,
    created_at          TEXT NOT NULL,
    FOREIGN KEY(agent) REFERENCES agent_bindings(agent)
);

CREATE INDEX IF NOT EXISTS idx_binding_verification_agent
    ON binding_verifications(agent, created_at);

CREATE INDEX IF NOT EXISTS idx_binding_verification_session
    ON binding_verifications(agent, actual_session_id, status);
