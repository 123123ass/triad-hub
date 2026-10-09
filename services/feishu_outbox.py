"""services/feishu_outbox.py —— 可靠飞书出站（Step 5.8）。

职责（严格按规格）：
- 原子 claim 待发送 outbox（repository.claim_outbox 用 BEGIN IMMEDIATE）。
- 调用 adapters.feishu.send_message 发送，outbox_id 固定作为飞书幂等键。
- 按 FeishuSendResult.status 落库：sent / retry（安全重试）/ delivery_unknown（不重发）/ failed（死信）。
- 重启恢复：将崩溃残留的 sending 状态恢复为 delivery_unknown。
- run_outbox_once 单次执行，不得新增 while True 循环。

所有状态以 SQLite 为准，不依赖进程内 set/字典保证幂等。
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, Optional

import repository
from adapters import feishu as feishu_adapter
from config import config
from db import connect, transaction
from redaction import OUTLET_FEISHU, assert_no_secret, for_feishu

# FeishuSendResult.status 与 outbox.state 的映射
STATE_SENT = "sent"
STATE_RETRY = "retry"
STATE_DELIVERY_UNKNOWN = "delivery_unknown"
STATE_FAILED = "failed"

RECOVERY_REASON = "worker_restarted"


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())


# ---------------- 5.8.4 claim + send ----------------
def claim_next_outbox(worker_id: str) -> Optional[Dict[str, Any]]:
    """取一条待发送 outbox；无则返回 None。"""
    rows = repository.claim_outbox(worker_id, limit=1)
    return rows[0] if rows else None


def send_claimed_outbox(record: Dict[str, Any]) -> Dict[str, Any]:
    """解析 payload、四出口脱敏检查、调飞书发送，并落库结果。"""
    outbox_id = record["outbox_id"]
    payload = json.loads(record["payload_json"])
    text = payload["text"]

    # 四出口脱敏检查（出库前最后一道闸门）
    text = for_feishu(text)
    assert_no_secret(text, outlet=OUTLET_FEISHU)

    result = feishu_adapter.send_message(
        text=text,
        bot=record["bot_identity"],
        idempotency_key=outbox_id,
    )

    if result.status == STATE_SENT:
        repository.mark_outbox_sent(outbox_id, result.message_id or "")
        return {
            "outbox_id": outbox_id,
            "state": STATE_SENT,
            "message_id": result.message_id,
            "error_code": None,
        }
    if result.status == STATE_RETRY:
        schedule_retry(record, result.error_code or "feishu_retry")
        return {
            "outbox_id": outbox_id,
            "state": STATE_RETRY,
            "message_id": None,
            "error_code": result.error_code,
        }
    if result.status == STATE_DELIVERY_UNKNOWN:
        mark_delivery_unknown(record, result.error_code or "feishu_delivery_unknown")
        return {
            "outbox_id": outbox_id,
            "state": STATE_DELIVERY_UNKNOWN,
            "message_id": None,
            "error_code": result.error_code,
        }
    # failed
    move_failed_to_dead_letter(record, result.error_code or "feishu_failed")
    return {
        "outbox_id": outbox_id,
        "state": STATE_FAILED,
        "message_id": None,
        "error_code": result.error_code,
    }


# ---------------- 5.8.6 安全重试 ----------------
def schedule_retry(record: Dict[str, Any], reason_code: str) -> None:
    """attempt_no+1，按重试表延迟，置 retry。超过上限转死信 failed。"""
    outbox_id = record["outbox_id"]
    next_attempt = int(record["attempt_no"] or 0) + 1

    if next_attempt > config.OUTBOX_MAX_ATTEMPTS:
        move_failed_to_dead_letter(record, reason_code)
        _set_outbox_state(
            outbox_id,
            state=STATE_FAILED,
            last_error_redacted=reason_code,
        )
        return

    delays = config.OUTBOX_RETRY_DELAYS
    delay = delays[next_attempt - 1] if (1 <= next_attempt <= len(delays)) else delays[-1]
    next_at = time.time() + delay

    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="schedule_retry", role="outbox"):
            conn.execute(
                "UPDATE outbox SET state='retry', attempt_no=?, next_attempt_at=?, "
                "claimed_by=NULL, claimed_at=NULL, last_error_redacted=? WHERE outbox_id=?",
                (next_attempt, str(next_at), reason_code, outbox_id),
            )
    finally:
        conn.close()


# ---------------- 5.8.7 状态未知 ----------------
def mark_delivery_unknown(record: Dict[str, Any], reason_code: str) -> None:
    """标记 delivery_unknown，不自动进入 retry，不自动再次发送。"""
    outbox_id = record["outbox_id"]
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="mark_delivery_unknown", role="outbox"):
            conn.execute(
                "UPDATE outbox SET state='delivery_unknown', delivery_unknown_at=?, "
                "last_error_redacted=?, claimed_by=NULL, claimed_at=NULL WHERE outbox_id=?",
                (_now(), reason_code, outbox_id),
            )
    finally:
        conn.close()


# ---------------- 5.8.8 确定失败与死信 ----------------
def move_failed_to_dead_letter(record: Dict[str, Any], reason_code: str) -> None:
    """写入 dead_letters（只存引用，禁止 payload 全文）。"""
    outbox_id = record["outbox_id"]
    repository.move_to_dead_letter(
        source_table="outbox",
        source_id=outbox_id,
        reason_code=reason_code,
        payload_ref="outbox:" + str(outbox_id),
    )
    _set_outbox_state(
        outbox_id,
        state=STATE_FAILED,
        last_error_redacted=reason_code,
    )


# ---------------- 5.8.10 重启恢复 ----------------
def recover_stuck_sending() -> int:
    """将崩溃残留的 sending 状态恢复为 delivery_unknown（无证据证明请求已发出的默认处理）。

    应由 worker 启动时调用一次。返回被恢复的条数。
    """
    conn = connect()
    try:
        recovered = 0
        with transaction(conn, immediate=True, operation="recover_stuck_sending", role="outbox"):
            rows = conn.execute(
                "SELECT outbox_id FROM outbox WHERE state='sending'"
            ).fetchall()
            stamp = _now()
            for r in rows:
                conn.execute(
                    "UPDATE outbox SET state='delivery_unknown', delivery_unknown_at=?, "
                    "last_error_redacted=?, claimed_by=NULL, claimed_at=NULL WHERE outbox_id=?",
                    (stamp, RECOVERY_REASON, r["outbox_id"]),
                )
                recovered += 1
        return recovered
    finally:
        conn.close()


# ---------------- 5.8.9 单次 worker ----------------
def run_outbox_once(worker_id: str) -> Dict[str, Any]:
    """处理一条 outbox；无待处理返 idle。不得新增 while True。"""
    record = claim_next_outbox(worker_id)
    if record is None:
        return {"status": "idle", "outbox_id": None}
    result = send_claimed_outbox(record)
    return {"status": result["state"], "outbox_id": result["outbox_id"]}


# ---------------- 内部工具 ----------------
def _set_outbox_state(
    outbox_id: str,
    state: str,
    last_error_redacted: Optional[str] = None,
) -> None:
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="_set_outbox_state", role="outbox"):
            conn.execute(
                "UPDATE outbox SET state=?, last_error_redacted=?, "
                "claimed_by=NULL, claimed_at=NULL WHERE outbox_id=?",
                (state, last_error_redacted, outbox_id),
            )
    finally:
        conn.close()
