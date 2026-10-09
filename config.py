"""Triad Hub 配置（Phase 1 / Step 4）。

安全红线：
- 所有敏感配置仅从环境变量 / 本机 .env 读取，绝不硬编码、绝不进日志与仓库。
- 不得硬编码任何 Codex 物理 task id；物理会话 id 只能从 agent_bindings 表读取。
- 配置缺失只报告字段名，永不打印字段值。
"""
from __future__ import annotations

import os
from pathlib import Path

# 支持从项目内 .env 读取本机安全配置（.env 不进版本控制）
try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:
    pass


def _env(name: str, default: str = "") -> str:
    """读环境变量。空串视为"未设置"，回落默认值。

    根因修复：.env / .env.example 中形如 `TRIAD_DB_PATH=` 的空行曾把 DB_PATH
    覆盖为空串，导致连到空库。此处统一兜底。
    """
    val = os.environ.get(name)
    if val is None or val.strip() == "":
        return default
    return val.strip()


def _env_int(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)))
    except ValueError:
        return default


class Config:
    # Opt-in independent CLI transport; legacy deployments remain unchanged.
    WB_TRANSPORT = _env("TRIAD_WB_TRANSPORT", "gateway_http")
    WB_CLI_ENTRY = _env("TRIAD_WB_CLI_ENTRY", "")
    WB_CLI_PROFILE = _env("TRIAD_WB_CLI_PROFILE", "")
    WB_CLI_CWD = _env("TRIAD_WB_CLI_CWD", "")
    WB_CLI_MODEL = _env("TRIAD_WB_CLI_MODEL", "hy3")
    WB_CLI_EDIT_GRANTS = _env("TRIAD_WB_CLI_EDIT_GRANTS", "")
    WB_CLI_GIT_BASH = _env("TRIAD_WB_CLI_GIT_BASH", "")
    # ---- WB 网关（route B，已通过 6 项验收）----
    WB_GATEWAY_URL = _env("TRIAD_WB_GATEWAY_URL", "http://127.0.0.1:8800")
    WB_GATEWAY_PASSWORD = _env("TRIAD_WB_GATEWAY_PASSWORD", "")  # 本机受限配置提供

    # ---- Hub 绑定（安全红线：只监听回环）----
    HOST = _env("TRIAD_HUB_HOST", "127.0.0.1")
    PORT = _env_int("TRIAD_HUB_PORT", 8900)
    LOOPBACK_ONLY = True
    ALLOWED_BIND_HOSTS = ("127.0.0.1", "localhost", "::1")

    # ---- 飞书：3 个独立机器人（凭据仅本机安全配置）----
    FEISHU_WB_APP_ID = _env("FEISHU_WB_APP_ID", "")
    FEISHU_WB_APP_SECRET = _env("FEISHU_WB_APP_SECRET", "")
    FEISHU_CODEX_APP_ID = _env("FEISHU_CODEX_APP_ID", "")
    FEISHU_CODEX_APP_SECRET = _env("FEISHU_CODEX_APP_SECRET", "")
    FEISHU_HERMES_APP_ID = _env("FEISHU_HERMES_APP_ID", "")
    FEISHU_HERMES_APP_SECRET = _env("FEISHU_HERMES_APP_SECRET", "")
    FEISHU_CHAT_ID = _env("FEISHU_CHAT_ID", "")
    # 旧环境变量仅作迁移回退；新名称优先，不复制旧身份到公开示例配置。
    FEISHU_OPERATOR_USER_ID = _env(
        "FEISHU_OPERATOR_USER_ID", _env("FEISHU_YANGGE_USER_ID", "")
    )
    # union_id 跨应用稳定；open_id 按应用隔离。
    FEISHU_OPERATOR_UNION_ID = _env(
        "FEISHU_OPERATOR_UNION_ID", _env("FEISHU_YANGGE_UNION_ID", "")
    )

    # ---- 飞书 Bot 身份 Open ID（非密码，但属系统身份配置，禁止硬编码）----
    FEISHU_WB_OPEN_ID = _env("FEISHU_WB_OPEN_ID", "")
    FEISHU_CODEX_OPEN_ID = _env("FEISHU_CODEX_OPEN_ID", "")
    FEISHU_HERMES_OPEN_ID = _env("FEISHU_HERMES_OPEN_ID", "")
    # Explicit single-mention collaboration tasks; ordinary chat remains one-agent.
    FEISHU_TASKS_ENABLED = _env("TRIAD_FEISHU_TASKS_ENABLED", "false").casefold() == "true"

    # 默认跟随 HOST/PORT（端口隔离时 Hub 内部地址自动一致）；显式设置仍可覆盖
    HUB_URL = _env("TRIAD_HUB_URL", "") or f"http://{HOST}:{PORT}"
    BRIDGE_DRY_RUN = _env(
        "TRIAD_BRIDGE_DRY_RUN",
        "true",
    ).casefold() == "true"

    OUTBOX_RETRY_DELAYS = tuple(
        int(item.strip())
        for item in _env(
            "TRIAD_OUTBOX_RETRY_DELAYS",
            "5,15,60",
        ).split(",")
        if item.strip()
    )

    # ---- 身份：逻辑会话名（可硬编码，非敏感、非物理 id）----
    # 物理会话 id 一律从 agent_bindings.actual_session_id 读取，禁止在源码出现。
    WB_LOGICAL_SESSION = "triad-wb-main"
    CODEX_LOGICAL_SESSION = "triad-codex-main"
    HERMES_LOGICAL_SESSION = "triad-hermes-main"
    LOGICAL_SESSIONS = {
        "workbuddy": WB_LOGICAL_SESSION,
        "codex": CODEX_LOGICAL_SESSION,
        "hermes": HERMES_LOGICAL_SESSION,
        "operator": "human",
    }

    # ---- 防循环（Codex 决断冻结）----
    MAX_HOPS = 2
    MAX_AUTO_REPLIES = 1

    # ---- 内部鉴权：HMAC-SHA256 ----
    HUB_INTERNAL_HMAC_SECRET = _env("TRIAD_HUB_HMAC_SECRET", "")
    HMAC_TIMESTAMP_SKEW_SEC = _env_int("TRIAD_HMAC_SKEW_SEC", 60)

    # ---- 管理端 ----
    HUB_ADMIN_TOKEN = _env("TRIAD_HUB_ADMIN_TOKEN", "")
    ADMIN_COMMANDS = ("/pause", "/stop", "/resume")
    ADMIN_ONLY_AGENT = "operator"  # 三个管理命令仅指定操作员可执行

    # ---- 调用超时 / 租约 / 重试 ----
    CALL_TIMEOUT_SEC = _env_int("TRIAD_CALL_TIMEOUT_SEC", 300)
    CALL_TIMEOUT_BY_AGENT = {
        "workbuddy": _env_int("TRIAD_CALL_TIMEOUT_WB_SEC", 300),
        "codex": _env_int("TRIAD_CALL_TIMEOUT_CODEX_SEC", 600),
        "hermes": _env_int("TRIAD_CALL_TIMEOUT_HERMES_SEC", 600),
    }
    AGENT_LEASE_TTL_SEC = _env_int("TRIAD_LEASE_TTL_SEC", 900)
    CALL_CLAIM_TTL_SEC = _env_int("TRIAD_CLAIM_TTL_SEC", 900)
    CALL_MAX_ATTEMPTS = _env_int("TRIAD_CALL_MAX_ATTEMPTS", 3)
    OUTBOX_MAX_ATTEMPTS = _env_int(
        "TRIAD_OUTBOX_MAX_ATTEMPTS",
        3,
    )
    DEDUP_TTL_SEC = _env_int("TRIAD_DEDUP_TTL_SEC", 120)

    # ---- 共享上下文上限 ----
    CONTEXT_MAX_CHARS = _env_int("TRIAD_CONTEXT_MAX_CHARS", 12000)
    CONTEXT_MAX_DELTA_EVENTS = _env_int("TRIAD_CONTEXT_MAX_DELTA_EVENTS", 30)
    # Opt-in cross-run project checkpoint; never read personal agent memories.
    PROJECT_MEMORY_ROOT = os.getenv("TRIAD_PROJECT_MEMORY_ROOT", "")
    PROJECT_MEMORY_ID = os.getenv("TRIAD_PROJECT_MEMORY_ID", "")
    SUMMARY_MAX_CHARS = _env_int("TRIAD_SUMMARY_MAX_CHARS", 4000)
    VERBATIM_MAX_CHARS = _env_int("TRIAD_VERBATIM_MAX_CHARS", 3000)

    # ---- 摘要稳定错误码（reject 只写码，不写 Hermes 原始错误全文）----
    SUMMARY_REJECTION_CODES = (
        "digest_mismatch",
        "evidence_missing",
        "evidence_out_of_range",
        "secret_detected",
        "range_invalid",
        "duplicate_verified_range",
    )

    # ---- 调用失败稳定错误码（adapter 失败只回码，绝不回 stderr 全文）----
    CALL_ERROR_CODES = (
        "auth_missing",
        "auth_permanent",
        "http_error",
        "transport_error",
        "no_run_id",
        "result_unknown",
        "binding_missing",
        "binding_offline",
        "binding_wrong_logical_session",
        "session_mismatch",
        "no_rollout",
        "command_bypass_detected",
        "cli_not_found",
        "cli_failed",
        "codex_model_unsupported",
        "codex_model_invalid",
        "provider_balance_insufficient",
        "timeout",
        "internal_error",
    )

    # ---- 外部工具路径（非敏感，带默认）----
    # Dedicated runner settings; never rewrite the desktop/global Codex config.
    CODEX_BIN = _env("TRIAD_CODEX_BIN", "")
    CODEX_MODEL = _env("TRIAD_CODEX_MODEL", "")
    CODEX_JS = _env(
        "TRIAD_CODEX_JS",
        "",
    )
    NODE = _env(
        "TRIAD_NODE",
        "",
    )
    HTTPS_PROXY = _env("TRIAD_HTTPS_PROXY", "http://127.0.0.1:7890")

    DB_PATH = _env("TRIAD_DB_PATH", str(Path(__file__).resolve().parent / "triad.db"))

    # ---- 必填项（缺失只报字段名，不报值）----
    REQUIRED_FIELDS = (
        "WB_GATEWAY_PASSWORD",
        "HUB_INTERNAL_HMAC_SECRET",
        "HUB_ADMIN_TOKEN",
        "FEISHU_CHAT_ID",
        "FEISHU_OPERATOR_UNION_ID",
    )
    # 视为敏感、任何情况下不得出现在日志/证据/报告中的字段
    SECRET_FIELDS = (
        "WB_GATEWAY_PASSWORD",
        "FEISHU_WB_APP_SECRET",
        "FEISHU_CODEX_APP_SECRET",
        "FEISHU_HERMES_APP_SECRET",
        "HUB_INTERNAL_HMAC_SECRET",
        "HUB_ADMIN_TOKEN",
    )
    # 受保护身份字段：open_id / chat_id / union_id 等飞书身份标识，快照只允许 <set>/<unset>
    IDENTITY_FIELDS = (
        "FEISHU_OPERATOR_UNION_ID",
        "FEISHU_OPERATOR_USER_ID",  # 仅 union 未配置时过渡使用
        "FEISHU_CHAT_ID",
        "FEISHU_WB_OPEN_ID",
        "FEISHU_CODEX_OPEN_ID",
        "FEISHU_HERMES_OPEN_ID",
    )
    # 启动自检：三个 Bot Open ID 是否配置（只报是否配置，禁止返回完整 Open ID）
    BOT_OPEN_ID_FIELDS = (
        "FEISHU_WB_OPEN_ID",
        "FEISHU_CODEX_OPEN_ID",
        "FEISHU_HERMES_OPEN_ID",
    )

    def bot_open_ids(self) -> dict[str, str]:
        return {
            "workbuddy": self.FEISHU_WB_OPEN_ID,
            "codex": self.FEISHU_CODEX_OPEN_ID,
            "hermes": self.FEISHU_HERMES_OPEN_ID,
        }

    def missing_required(self) -> list[str]:
        """返回缺失的必填字段名列表（只有名字，绝不含值）。"""
        fields = list(self.REQUIRED_FIELDS)
        if self.WB_TRANSPORT == 'cli_fixed_session':
            fields.remove('WB_GATEWAY_PASSWORD')
            fields.extend(('WB_CLI_ENTRY', 'WB_CLI_PROFILE', 'WB_CLI_CWD', 'WB_CLI_MODEL'))
        return [f for f in fields if not getattr(self, f, "")]

    def secret_values(self) -> list[str]:
        """当前已配置的真实敏感值（仅供 redaction 内部使用，不得外泄/打印）。"""
        vals = []
        for f in self.SECRET_FIELDS:
            v = getattr(self, f, "")
            if isinstance(v, str) and len(v) >= 6:
                vals.append(v)
        return vals

    def redacted_snapshot(self) -> dict:
        """可安全写入日志的配置快照：敏感字段与受保护身份字段只显示是否已设置。"""
        snap = {}
        for f in dir(self):
            if f.startswith("_") or callable(getattr(self, f)):
                continue
            if f in self.SECRET_FIELDS or f in self.IDENTITY_FIELDS:
                snap[f] = "<set>" if getattr(self, f) else "<unset>"
            else:
                snap[f] = getattr(self, f)
        return snap


config = Config()
