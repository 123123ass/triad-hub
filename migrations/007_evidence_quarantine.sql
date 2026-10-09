-- Step 8 安全收尾（c）：历史 evidence 隔离迁移记录
-- 版本：007_evidence_quarantine
--
-- 背景：Step 8 live 阶段两份 binding evidence 中，Codex 按引导 cat 共享协议文档时，
--       文档正文里"逻辑身份↔物理会话"章节的物理 session 明文被原样回显进 stdout，
--       随 evidence 落盘。属非调用泄露（我方命令从未含该 ID），但公开面不得留明文。
--
-- 处置铁律：历史 evidence **不直接改写**。
--   1) 原文件先算 SHA-256（raw_evidence_sha256）；
--   2) 原文件整体移入只限本机审计访问的 evidence/private/raw/（private_raw_ref）；
--   3) 在原路径生成同名脱敏副本（sanitized_evidence_ref），DB / 报告只引脱敏副本；
--   4) 本表逐条留痕（quarantined_at），使"原始 → 隔离 → 脱敏"三段可复验。
--
-- 设计取舍：不在 binding_verifications 上做 UPDATE 加列写值——那会触碰"验真记录
--   一经写入不可变"的铁律。改为独立 append-only 侧表，通过 original_ref 关联。

CREATE TABLE IF NOT EXISTS evidence_quarantine (
    quarantine_id           TEXT PRIMARY KEY,
    artifact_kind           TEXT NOT NULL,      -- binding_evidence | doc | log
    original_ref            TEXT NOT NULL,      -- 相对 HUB 的原路径
    raw_evidence_sha256     TEXT NOT NULL,      -- 隔离前原始字节的 sha256
    private_raw_ref         TEXT NOT NULL,      -- 隔离区内的相对路径
    sanitized_evidence_ref  TEXT NOT NULL,      -- 脱敏副本（公开面）相对路径
    sanitized_sha256        TEXT NOT NULL,      -- 脱敏副本的 sha256
    redaction_count         INTEGER NOT NULL DEFAULT 0,  -- 被替换的明文会话出现次数
    session_hashes_json     TEXT NOT NULL DEFAULT '[]',  -- 涉及的 session_id_hash 列表（不含明文）
    verification_id         TEXT,               -- 关联的 binding_verifications（可空）
    quarantined_at          TEXT NOT NULL,
    note                    TEXT,
    CHECK (artifact_kind IN ('binding_evidence', 'doc', 'log')),
    CHECK (length(raw_evidence_sha256) = 64),
    CHECK (length(sanitized_sha256) = 64)
);

-- 同一原路径只允许一条隔离记录（幂等键）
CREATE UNIQUE INDEX IF NOT EXISTS uq_evidence_quarantine_original
    ON evidence_quarantine(original_ref);

CREATE INDEX IF NOT EXISTS ix_evidence_quarantine_verification
    ON evidence_quarantine(verification_id);
