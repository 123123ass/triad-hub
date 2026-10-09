"""Triad Hub 安全门禁（Phase 1 / Step 4）。

覆盖 Codex 冻结的五条边界：
1. 内部调用 HMAC-SHA256 签名 + 恒定时间比较（hmac.compare_digest）。
2. 时间戳校验，允许偏差不超过 config.HMAC_TIMESTAMP_SKEW_SEC（默认 60s）。
3. 固定群 ID 白名单，非白名单群一律拒绝。
4. /pause、/stop、/resume 三个管理命令仅指定操作员身份可执行。
5. Hub 只允许绑定回环地址。

补充：同一合法 HMAC 请求的重放，由数据库 event_id 幂等兜底，禁止二次调用下游。
所有拒绝路径只返回错误码，不回显签名、时间戳原值、群 ID 或任何凭据。
"""
from __future__ import annotations

import hashlib
import hmac
import time
from typing import Optional, Tuple

from config import config

# ---- 错误码（对外只暴露码，不暴露细节）----
ERR_HMAC_UNCONFIGURED = "hmac_unconfigured"
ERR_SIG_MISSING = "sig_missing"
ERR_SIG_INVALID = "sig_invalid"
ERR_TS_MISSING = "ts_missing"
ERR_TS_MALFORMED = "ts_malformed"
ERR_TS_EXPIRED = "ts_expired"
ERR_TS_FUTURE = "ts_future"
ERR_CHAT_DENIED = "chat_denied"
ERR_ADMIN_DENIED = "admin_denied"
ERR_BIND_DENIED = "bind_denied"
OK = "ok"


class SecurityError(Exception):
    """只带错误码，不带敏感细节。"""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


# ---------------- 1/2. HMAC 签名与时间戳 ----------------
def _canonical(body: str | bytes, timestamp: str) -> bytes:
    if isinstance(body, str):
        body = body.encode("utf-8")
    return timestamp.encode("utf-8") + b"." + body


def build_signature(body: str | bytes, timestamp: Optional[str] = None) -> Tuple[str, str]:
    """生成 (timestamp, signature)。密钥未配置直接抛错，绝不降级为明文放行。"""
    secret = config.HUB_INTERNAL_HMAC_SECRET
    if not secret:
        raise SecurityError(ERR_HMAC_UNCONFIGURED)
    ts = timestamp or str(int(time.time()))
    sig = hmac.new(
        secret.encode("utf-8"), _canonical(body, ts), hashlib.sha256
    ).hexdigest()
    return ts, sig


def verify_signature(
    body: str | bytes,
    timestamp: Optional[str],
    signature: Optional[str],
    now: Optional[float] = None,
) -> str:
    """校验内部请求签名。返回 OK 或错误码，不抛异常、不回显原值。"""
    secret = config.HUB_INTERNAL_HMAC_SECRET
    if not secret:
        return ERR_HMAC_UNCONFIGURED
    if not signature:
        return ERR_SIG_MISSING
    if not timestamp:
        return ERR_TS_MISSING
    try:
        ts_val = float(timestamp)
    except (TypeError, ValueError):
        return ERR_TS_MALFORMED

    cur = time.time() if now is None else now
    skew = config.HMAC_TIMESTAMP_SKEW_SEC
    if ts_val < cur - skew:
        return ERR_TS_EXPIRED
    if ts_val > cur + skew:
        return ERR_TS_FUTURE

    expected = hmac.new(
        secret.encode("utf-8"), _canonical(body, str(timestamp)), hashlib.sha256
    ).hexdigest()
    # 恒定时间比较，防时序侧信道
    if not hmac.compare_digest(expected, signature):
        return ERR_SIG_INVALID
    return OK


def assert_signature(body, timestamp, signature, now: Optional[float] = None) -> None:
    code = verify_signature(body, timestamp, signature, now=now)
    if code != OK:
        raise SecurityError(code)


# ---------------- 3. 固定群白名单 ----------------
def allowed_chat_ids() -> set[str]:
    return {c for c in (config.FEISHU_CHAT_ID,) if c}


def is_allowed_chat(chat_id: Optional[str]) -> bool:
    allow = allowed_chat_ids()
    if not allow:
        return False  # 未配置白名单时默认拒绝，不默认放行
    return bool(chat_id) and chat_id in allow


def assert_allowed_chat(chat_id: Optional[str]) -> None:
    if not is_allowed_chat(chat_id):
        raise SecurityError(ERR_CHAT_DENIED)


# ---------------- 4. 管理命令仅操作员 ----------------
def parse_admin_command(text: Optional[str]) -> Optional[str]:
    """识别 /pause /stop /resume；非管理命令返回 None。"""
    if not text:
        return None
    head = text.strip().split()[0].lower() if text.strip() else ""
    return head if head in config.ADMIN_COMMANDS else None


def authorize_admin_command(
    text: Optional[str],
    actor_agent: Optional[str] = None,
    actor_user_id: Optional[str] = None,
    actor_union_id: Optional[str] = None,
) -> str:
    """返回 OK / ERR_ADMIN_DENIED。非管理命令返回 OK（不归本函数管）。

    fail-closed：FEISHU_OPERATOR_UNION_ID 配置后，操作员管理命令只认 union_id 精确匹配，
    union_id 缺失/错误/仅旧 open_id 一律拒绝；USER_ID 仅在 union 未配置时过渡使用。
    """
    cmd = parse_admin_command(text)
    if cmd is None:
        return OK
    if actor_agent != config.ADMIN_ONLY_AGENT:
        return ERR_ADMIN_DENIED
    union_id = config.FEISHU_OPERATOR_UNION_ID
    if union_id:
        if actor_union_id and actor_union_id == union_id:
            return OK
        return ERR_ADMIN_DENIED
    # 过渡兼容（union 未配置）：旧 open_id 路径
    operator_id = config.FEISHU_OPERATOR_USER_ID
    if not operator_id:
        return ERR_ADMIN_DENIED
    if actor_user_id and actor_user_id != operator_id:
        return ERR_ADMIN_DENIED
    if not actor_user_id:
        return ERR_ADMIN_DENIED
    return OK


def assert_admin_command(
    text, actor_agent=None, actor_user_id=None, actor_union_id=None
) -> None:
    code = authorize_admin_command(text, actor_agent, actor_user_id, actor_union_id)
    if code != OK:
        raise SecurityError(code)


# ---------------- 5. 只监听回环 ----------------
def is_loopback(host: Optional[str]) -> bool:
    return bool(host) and host in config.ALLOWED_BIND_HOSTS


def assert_loopback_bind(host: Optional[str] = None) -> None:
    h = host or config.HOST
    if config.LOOPBACK_ONLY and not is_loopback(h):
        raise SecurityError(ERR_BIND_DENIED)


# ---------------- 重放兜底 ----------------
def is_replayed_event(event_id: Optional[str]) -> bool:
    """合法 HMAC 也可能是重放：以库内 event_id 是否已存在为准。

    命中即 Hub 只回原结果，禁止二次调用下游 agent。
    """
    if not event_id:
        return False
    from db import connect

    conn = connect()
    try:
        row = conn.execute(
            "SELECT 1 FROM events WHERE event_id=?", (event_id,)
        ).fetchone()
        return row is not None
    finally:
        conn.close()


# ---------------- 启动自检 ----------------
def startup_check() -> dict:
    """启动前安全自检。缺失项只回字段名，绝不回值。"""
    missing = config.missing_required()
    result = {
        "missing_config_fields": missing,
        "loopback_only": config.LOOPBACK_ONLY,
        "bind_host_ok": is_loopback(config.HOST),
        "chat_whitelist_size": len(allowed_chat_ids()),
        "hmac_configured": bool(config.HUB_INTERNAL_HMAC_SECRET),
        "admin_token_configured": bool(config.HUB_ADMIN_TOKEN),
    }
    return result
