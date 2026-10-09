-- Step 8 恢复协议：为 binding_verifications 增加审计父引用
-- 版本：006_binding_recovery_parent
-- 背景：live --create 因解析器不兼容 codex `item.completed → agent_message` 信封
--       误判 bootstrap_reply_mismatch。原失败记录必须保持 failed 且禁止 UPDATE，
--       恢复以"新增一条带父引用的 created 记录"方式完成，保留完整审计链。
-- 审计铁律：已应用迁移（001–005）不可修改；本文件为新增迁移，应用前自动备份。

ALTER TABLE binding_verifications ADD COLUMN parent_verification_id TEXT;

-- 幂等键：一条失败记录最多只能派生一条恢复记录，重复恢复不得新增第二条。
CREATE UNIQUE INDEX IF NOT EXISTS uq_binding_verification_parent
    ON binding_verifications(parent_verification_id)
    WHERE parent_verification_id IS NOT NULL;
