"""Triad Hub 脱敏（Phase 1 / Step 4 扩充版）。

四个出口必须全部经过本模块：
    OUTLET_DB       落库（events / messages / tasks / evidence 等所有 JSON 与文本列）
    OUTLET_LOG      结构化日志
    OUTLET_EVIDENCE 证据文件（docs/、报告、验收产物）
    OUTLET_FEISHU   飞书出站消息

覆盖：Bearer、Authorization、password、token、secret、JWT、api key，
以及 config 中当前已配置的真实敏感值（网关密码、飞书 secret、HMAC 密钥、管理端 token）。

safe_error() 不得包含请求头、完整 URL 查询参数、stderr 全文或异常对象原文。
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Iterable

REDACTED = "[REDACTED]"

# ---- 出口标识 ----
OUTLET_DB = "db"
OUTLET_LOG = "log"
OUTLET_EVIDENCE = "evidence"
OUTLET_FEISHU = "feishu"
OUTLETS = (OUTLET_DB, OUTLET_LOG, OUTLET_EVIDENCE, OUTLET_FEISHU)

# ---- 凭据特征 ----
_SECRET_PATTERNS = [
    re.compile(r"Bearer[ \t]+[A-Za-z0-9._\-]+", re.IGNORECASE),
    re.compile(r"Authorization[ \t]*[:=][ \t]*\S+", re.IGNORECASE),
    re.compile(r"Proxy-Authorization[ \t]*[:=][ \t]*\S+", re.IGNORECASE),
    re.compile(r"Cookie[ \t]*[:=][ \t]*\S+", re.IGNORECASE),
    re.compile(r"X-(?:Api|Auth|Access|Session)-?\w*[ \t]*[:=][ \t]*\S+", re.IGNORECASE),
    re.compile(r"password[ \t]*[:=][ \t]*\S+", re.IGNORECASE),
    re.compile(r"access[_-]?key[ \t]*[:=][ \t]*\S+", re.IGNORECASE),
    re.compile(r"passwd[ \t]*[:=][ \t]*\S+", re.IGNORECASE),
    re.compile(r"token[ \t]*[:=][ \t]*[\"']?[A-Za-z0-9\-_.]{16,}", re.IGNORECASE),
    re.compile(r"secret[ \t]*[:=][ \t]*\S+", re.IGNORECASE),
    re.compile(r"app_secret[ \t]*[:=][ \t]*\S+", re.IGNORECASE),
    re.compile(r"ticket[ \t]*[:=][ \t]*\S+", re.IGNORECASE),
    re.compile(r"device[_-]?id[ \t]*[:=][ \t]*\S+", re.IGNORECASE),
    re.compile(r"\b(?:sk|pk|rk)[-_][A-Za-z0-9]{16,}", re.IGNORECASE),
    re.compile(r"\bapi[_-]?key[ \t]*[:=][ \t]*\S+", re.IGNORECASE),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),  # JWT
    re.compile(r"[A-Za-z0-9]{32,}\.[A-Za-z0-9._\-]{32,}\.[A-Za-z0-9_\-]{16,}"),  # JWT 形状
]

# URL 查询串（safe_error 必须剥掉）
_URL_QUERY = re.compile(r"((?:https?|wss)://[^\s?]+)\?\S*", re.IGNORECASE)
# 形如 "Header-Name: value" 的请求头行
_HEADER_LINE = re.compile(r"^[A-Za-z][A-Za-z0-9\-]{1,40}\s*:\s*.+$")


def _config_secret_values() -> list[str]:
    """当前已配置的真实敏感值。延迟导入避免循环依赖。"""
    try:
        from config import config

        return config.secret_values()
    except Exception:
        return []


def _replace_literal_secrets(text: str, extra: Iterable[str] = ()) -> str:
    out = text
    vals = list(_config_secret_values()) + [v for v in extra if v]
    # 长的先替换，避免子串截断
    for v in sorted({v for v in vals if isinstance(v, str) and len(v) >= 6}, key=len, reverse=True):
        out = out.replace(v, REDACTED)
    return out


def redact_text(text: Any, extra_secrets: Iterable[str] = ()) -> Any:
    if not isinstance(text, str):
        return text
    out = _replace_literal_secrets(text, extra_secrets)
    for p in _SECRET_PATTERNS:
        out = p.sub(
            lambda m: (m.group(0).split(":", 1)[0] + ": " + REDACTED)
            if ":" in m.group(0)
            else REDACTED,
            out,
        )
    out = strip_url_query(out)
    return out


def _blob(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, ensure_ascii=False, default=str)
    return str(value)


def _secret_field_names() -> set[str]:
    """返回大小写无关的敏感字段名集合，不返回字段值。"""
    from config import config

    return {str(name).casefold() for name in config.SECRET_FIELDS}


def _is_secret_key(key: object) -> bool:
    """字段名是否属于 config.SECRET_FIELDS；大小写不敏感。"""
    return isinstance(key, str) and key.casefold() in _secret_field_names()


def _sanitize_recursive(
    value: Any,
    outlet: str,
    extra_secrets: Iterable[str] = (),
) -> Any:
    """递归脱敏并保持普通数据类型。"""
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            if _is_secret_key(key):
                cleaned[key] = REDACTED
            else:
                cleaned[key] = _sanitize_recursive(
                    item,
                    outlet=outlet,
                    extra_secrets=extra_secrets,
                )
        return cleaned

    if isinstance(value, list):
        return [
            _sanitize_recursive(
                item,
                outlet=outlet,
                extra_secrets=extra_secrets,
            )
            for item in value
        ]

    if isinstance(value, tuple):
        return tuple(
            _sanitize_recursive(
                item,
                outlet=outlet,
                extra_secrets=extra_secrets,
            )
            for item in value
        )

    if isinstance(value, str):
        return redact_text(value, extra_secrets)

    return value


def contains_secret(value: Any, extra_secrets: Iterable[str] = ()) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if _is_secret_key(key):
                if item not in (REDACTED, "<set>", "<unset>", None, ""):
                    return True
            if contains_secret(item, extra_secrets):
                return True
        return False

    if isinstance(value, (list, tuple)):
        return any(contains_secret(item, extra_secrets) for item in value)

    blob = _blob(value)
    if not blob:
        return False

    for secret in list(_config_secret_values()) + [
        item for item in extra_secrets if item
    ]:
        if (
            isinstance(secret, str)
            and len(secret) >= 6
            and secret in blob
        ):
            return True

    return any(pattern.search(blob) for pattern in _SECRET_PATTERNS)


def assert_no_secret(value: Any, outlet: str = OUTLET_DB, extra_secrets: Iterable[str] = ()) -> None:
    """任一出口写出前必须调用。命中凭据即抛 ValueError（只带出口名，不带内容）。"""
    if contains_secret(value, extra_secrets):
        raise ValueError(f"secret pattern detected at outlet={outlet}; write rejected")


def sanitize(value: Any, outlet: str, extra_secrets: Iterable[str] = ()) -> Any:
    """统一出口脱敏：先脱敏，再自检，确保脱敏后仍无残留。"""
    if outlet not in OUTLETS:
        raise ValueError(f"unknown outlet: {outlet}")

    cleaned = _sanitize_recursive(
        value,
        outlet=outlet,
        extra_secrets=extra_secrets,
    )

    assert_no_secret(
        cleaned,
        outlet=outlet,
        extra_secrets=extra_secrets,
    )
    return cleaned


# 四个出口的便捷入口
def for_db(value, extra_secrets: Iterable[str] = ()):
    return sanitize(value, OUTLET_DB, extra_secrets)


def for_log(value, extra_secrets: Iterable[str] = ()):
    return sanitize(value, OUTLET_LOG, extra_secrets)


def for_evidence(value, extra_secrets: Iterable[str] = ()):
    return sanitize(value, OUTLET_EVIDENCE, extra_secrets)


def for_feishu(value, extra_secrets: Iterable[str] = ()):
    return sanitize(value, OUTLET_FEISHU, extra_secrets)


# ---------------- 错误信息安全化 ----------------
def strip_url_query(text: str) -> str:
    return _URL_QUERY.sub(lambda m: m.group(1) + "?" + REDACTED, text)


def strip_header_lines(text: str) -> str:
    kept = []
    for line in text.splitlines():
        if _HEADER_LINE.match(line.strip()):
            continue
        kept.append(line)
    return " ".join(kept)


def summarize_stderr(stderr: str | None) -> str:
    """stderr 只留脱敏后的首行摘要与长度，绝不回全文。"""
    if not stderr:
        return "stderr_empty"
    first = stderr.strip().splitlines()[0] if stderr.strip() else ""
    first = redact_text(strip_url_query(strip_header_lines(first)))
    return f"stderr_first_line={first[:80]} len={len(stderr)}"


def safe_error(exc: BaseException, max_len: int = 120) -> str:
    """只返回错误类别 + 脱敏摘要 + 指纹。

    不含：请求头、完整 URL 查询参数、stderr 全文、异常对象原文。
    """
    name = type(exc).__name__
    raw = str(exc)
    fingerprint = hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest()[:12]
    summary = redact_text(strip_url_query(strip_header_lines(raw)))
    summary = re.sub(r"\s+", " ", summary).strip()[:max_len]
    return f"{name}|{summary}|fp={fingerprint}"


def error_code(exc: BaseException) -> str:
    """给日志用的稳定错误码，不含任何内容。"""
    return f"{type(exc).__name__}:{hashlib.sha256(str(exc).encode('utf-8','ignore')).hexdigest()[:8]}"


# ---------------- 进程输出流脱敏（飞书桥场景） ----------------
class _RedactStream:
    """包装任意文本流，write 前过 redact_text，杜绝 SDK 直打 stderr 的凭据落盘。"""

    def __init__(self, raw):
        object.__setattr__(self, "_raw", raw)
        object.__setattr__(self, "_redact_wrapped", True)

    def write(self, s):
        raw = object.__getattribute__(self, "_raw")
        try:
            if isinstance(s, str):
                s = redact_text(s)
        except Exception:
            pass
        return raw.write(s)

    def flush(self):
        return object.__getattribute__(self, "_raw").flush()

    def __getattr__(self, name):
        return getattr(object.__getattribute__(self, "_raw"), name)


def _wrap_logger_handlers(logger, wrapped_cache):
    """把单个 logger 的所有 StreamHandler 的 stream 包成 _RedactStream。

    wrapped_cache: dict[id(raw_stream)] -> _RedactStream，保证同一个底层流
    （哪怕被多个 logger / handler 共享）只产生一个包装对象，且全部 handler 都指向它。
    """
    for h in list(getattr(logger, "handlers", []) or []):
        stream = getattr(h, "stream", None)
        if stream is None:
            continue
        if getattr(stream, "_redact_wrapped", False):
            # 已经是包装流，无需重复处理
            continue
        wrapped = wrapped_cache.get(id(stream))
        if wrapped is None:
            wrapped = _RedactStream(stream)
            wrapped_cache[id(stream)] = wrapped
        try:
            h.stream = wrapped
        except Exception:
            pass


def install_stream_redactor() -> None:
    """桥进程入口调用：把 sys.stdout/stderr 与全部 logging StreamHandler 包装为脱敏流。

    不依赖 import 顺序：遍历 logging.root 与 logging.root.manager.loggerDict 中
    所有真实 Logger（含 SDK 的 named logger，如 "Lark"）的 handler。
    可重复调用（幂等去重）：run_bridge 在 client.start() 前再调一次，可捕获 SDK
    延迟添加的日志 handler；同一底层流只包装一次。
    """
    import logging
    import sys

    for name in ("stdout", "stderr"):
        cur = getattr(sys, name)
        if not getattr(cur, "_redact_wrapped", False):
            setattr(sys, name, _RedactStream(cur))

    wrapped_cache = {}
    _wrap_logger_handlers(logging.root, wrapped_cache)
    manager = getattr(logging.root, "manager", None)
    if manager is not None:
        for logger in manager.loggerDict.values():
            if isinstance(logger, logging.Logger):
                _wrap_logger_handlers(logger, wrapped_cache)
