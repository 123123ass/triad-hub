"""Triad Hub 结构化脱敏日志（Phase 1 / Step 4）。

硬约束（Codex 冻结）：
- 禁止直接记录请求 body、prompt 全文、环境变量、adapter 原始 stderr。
- 只保留 trace_id、event_id、call_id、状态、耗时和脱敏错误码。
- 字段采用白名单制：不在白名单内的字段一律丢弃，只记录被丢弃的字段名。
- 所有字符串值出库前统一过 redaction.for_log。
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict

from redaction import contains_secret, error_code, for_log, safe_error

LOG_DIR = Path(__file__).resolve().parent / "logs"
LOG_FILE = LOG_DIR / "hub.jsonl"

# 只允许出现在日志里的字段
ALLOWED_FIELDS = {
    "ts", "level", "logger", "event",
    "trace_id", "event_id", "call_id", "task_id",
    "source_agent", "target_agent", "agent",
    "status", "state", "reason",
    "duration_ms", "attempt", "hop_count", "event_seq",
    "error_code", "error_summary",
    "outlet", "delivery_id", "outbox_id", "lease_id",
    "count", "version", "step_id", "dropped_fields",
}

# 明确禁止的字段名（即使误传也要拦下）
BANNED_FIELDS = {
    "body", "payload", "payload_json", "prompt", "text", "content", "message",
    "env", "environ", "environment", "stderr", "stdout", "output",
    "headers", "header", "authorization", "cookie",
    "password", "passwd", "token", "secret", "app_secret", "api_key",
    "url", "full_url", "query", "args", "argv", "cmd", "command",
}

_LEVELS = {"DEBUG": 10, "INFO": 20, "WARN": 30, "ERROR": 40}
_MIN_LEVEL = _LEVELS.get(os.environ.get("TRIAD_LOG_LEVEL", "INFO").upper(), 20)


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())


def _filter_fields(fields: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    dropped = []
    for k, v in fields.items():
        lk = k.lower()
        if lk in BANNED_FIELDS or lk not in ALLOWED_FIELDS:
            dropped.append(k)
            continue
        if isinstance(v, str):
            v = for_log(v)
        elif isinstance(v, (dict, list, tuple)):
            # 复杂结构一律不进日志，只留长度
            dropped.append(k)
            continue
        out[k] = v
    if dropped:
        out["dropped_fields"] = sorted(set(dropped))
    return out


class HubLogger:
    def __init__(self, name: str):
        self.name = name

    def _emit(self, level: str, event: str, **fields: Any) -> Dict[str, Any]:
        if _LEVELS.get(level, 20) < _MIN_LEVEL:
            return {}
        rec = {"ts": _now_iso(), "level": level, "logger": self.name, "event": str(event)[:80]}
        rec.update(_filter_fields(fields))
        line = json.dumps(rec, ensure_ascii=False, default=str)
        # 兜底自检：任何残留凭据一律不写盘
        if contains_secret(line):
            rec = {
                "ts": rec["ts"], "level": "ERROR", "logger": self.name,
                "event": "log_record_rejected", "error_code": "secret_in_log_record",
            }
            line = json.dumps(rec, ensure_ascii=False)
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass
        print(line, file=sys.stderr)
        return rec

    def debug(self, event: str, **f):
        return self._emit("DEBUG", event, **f)

    def info(self, event: str, **f):
        return self._emit("INFO", event, **f)

    def warn(self, event: str, **f):
        return self._emit("WARN", event, **f)

    def error(self, event: str, **f):
        return self._emit("ERROR", event, **f)

    def exception(self, event: str, exc: BaseException, **f):
        """异常只落脱敏错误码与摘要，绝不落 traceback / 原文 / stderr。"""
        f.setdefault("error_code", error_code(exc))
        f.setdefault("error_summary", safe_error(exc))
        return self._emit("ERROR", event, **f)


def get_logger(name: str) -> HubLogger:
    return HubLogger(name)
