"""Triad Hub 仓储层 (Phase 1)。

关键不变量（Codex 冻结）：
- "事件查重 -> 分配 event_seq -> 建投递" 必须处于同一 BEGIN IMMEDIATE 事务。
- event_dedup.signature 仅 120s 窗口去重，不永久唯一。
- JSON 写入前统一过 redaction.assert_no_secret。
- 单 Agent 调用串行：claim_next_call + agent_leases 保证单会话单 writer。
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from db import connect, transaction
from config import config
from redaction import OUTLET_DB, assert_no_secret, for_db


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())


def _uid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


# ---------------- 事件入库 ----------------
def ingest_event(
    envelope: Dict[str, Any], targets: Optional[List[str]] = None
) -> Tuple[Optional[int], bool]:
    """入站事件归一化入库。返回 (event_seq, duplicate)。"""
    assert_no_secret(envelope.get("text"))
    assert_no_secret(envelope.get("payload_json"))
    event_id = envelope.get("event_id") or _uid("evt")
    trace_id = envelope.get("trace_id") or _uid("trc")
    content_sig = envelope.get("content_signature")
    targets = targets or envelope.get("target_agents") or []

    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="ingest_event", role="hub"):
            # 1) event_id 去重（外部重复投递）—— 必须先判，才能回原 event_seq
            row = conn.execute(
                "SELECT event_seq FROM events WHERE event_id=?", (event_id,)
            ).fetchone()
            if row:
                return (row["event_seq"], True)
            # 2) 内容签名去重（120s 窗口，不同 event_id 的同文本重放）
            if content_sig:
                row = conn.execute(
                    """
                    SELECT e.event_seq
                    FROM event_dedup d
                    JOIN events e ON e.event_id=d.first_event_id
                    WHERE d.signature=?
                      AND CAST(d.expires_at AS REAL)>?
                    """,
                    (content_sig, time.time()),
                ).fetchone()
                if row:
                    return (row["event_seq"], True)
            # 3) 分配 event_seq 并落事件
            cur = conn.execute(
                """INSERT INTO events(event_id, idempotency_key, trace_id, parent_event_id, root_event_id,
                   source_agent, source_type, source_id, message_type, text, mentions_json, refs_json,
                   payload_json, task_id, hop_count, max_hops, created_at, received_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    event_id,
                    envelope.get("idempotency_key"),
                    trace_id,
                    envelope.get("parent_event_id"),
                    envelope.get("root_event_id"),
                    envelope.get("source_agent"),
                    envelope.get("source_type"),
                    envelope.get("source_id"),
                    envelope.get("message_type", "chat"),
                    envelope.get("text", ""),
                    json.dumps(envelope.get("mentions", []), ensure_ascii=False),
                    json.dumps(envelope.get("refs", {}), ensure_ascii=False),
                    envelope.get("payload_json"),
                    envelope.get("task_id"),
                    envelope.get("hop_count", 0),
                    envelope.get("max_hops", 2),
                    envelope.get("created_at"),
                    _now(),
                ),
            )
            event_seq = cur.lastrowid
            # 4) 内容签名写入（TTL）
            if content_sig:
                conn.execute(
                    "INSERT OR REPLACE INTO event_dedup(signature, first_event_id, expires_at) VALUES(?,?,?)",
                    (content_sig, event_id, str(time.time() + 120)),
                )
            # 5) 只建 Agent 投递；飞书 outbox 由 Agent 回复落事件后单独创建
            _create_deliveries(conn, event_seq, targets)
        return (event_seq, False)
    finally:
        conn.close()


def _create_deliveries(conn, event_seq: int, targets: List[str]) -> None:
    """只创建 Agent 投递，不创建飞书 outbox。"""
    for t in targets:
        bot = t  # Phase 5 细化 target->bot_identity 映射
        conn.execute(
            "INSERT OR IGNORE INTO deliveries(delivery_id, event_seq, destination, bot_identity, state, attempt_no, next_attempt_at, external_message_id, last_error_redacted) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (_uid("dlv"), event_seq, t, bot, "pending", 0, None, None, None),
        )


# ---------------- 签名保留 ----------------
def reserve_content_signature(signature: str, first_event_id: str, ttl_seconds: int = 120) -> None:
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="reserve_content_signature", role="hub"):
            conn.execute(
                "INSERT OR REPLACE INTO event_dedup(signature, first_event_id, expires_at) VALUES(?,?,?)",
                (signature, first_event_id, str(time.time() + ttl_seconds)),
            )
    finally:
        conn.close()


# ---------------- 调用租约 ----------------
def claim_next_call(agent: str, worker_id: str, limit: int = 1) -> List[Dict[str, Any]]:
    conn = connect()
    try:
        rows = conn.execute(
            "SELECT * FROM call_attempts WHERE agent=? AND state='pending' ORDER BY started_at LIMIT ?",
            (agent, limit),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def acquire_agent_lease(
    agent: str,
    call_id: str,
    worker_id: str,
    ttl: int = 300,
) -> bool:
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="acquire_agent_lease", role="agent"):
            row = conn.execute(
                "SELECT 1 FROM agent_leases WHERE agent=? AND CAST(expires_at AS REAL) > ?",
                (agent, time.time()),
            ).fetchone()
            if row:
                return False
            conn.execute(
                "INSERT OR REPLACE INTO agent_leases(agent, holder_id, call_id, acquired_at, expires_at) VALUES(?,?,?,?,?)",
                (agent, worker_id, call_id, _now(), str(time.time() + ttl)),
            )
            return True
    finally:
        conn.close()


def release_agent_lease(agent: str, call_id: str) -> None:
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="release_agent_lease", role="agent"):
            conn.execute(
                "DELETE FROM agent_leases WHERE agent=? AND call_id=?", (agent, call_id)
            )
    finally:
        conn.close()


def complete_call(call_id: str, truth_metadata: Dict[str, Any], text: str) -> None:
    assert_no_secret(text)
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="complete_call", role="agent"):
            conn.execute(
                "UPDATE call_attempts SET state='completed', completed_at=?, exit_code=?, actual_session_id=?, error_message_redacted=? WHERE call_id=?",
                (
                    _now(),
                    truth_metadata.get("exit_code"),
                    truth_metadata.get("actual_session_id"),
                    truth_metadata.get("error_message_redacted"),
                    call_id,
                ),
            )
    finally:
        conn.close()


def fail_call(call_id: str, error_message_redacted: str) -> None:
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="fail_call", role="agent"):
            conn.execute(
                "UPDATE call_attempts SET state='failed', completed_at=?, error_message_redacted=? WHERE call_id=?",
                (_now(), error_message_redacted, call_id),
            )
    finally:
        conn.close()


def advance_cursor(agent: str, event_seq: int) -> None:
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="advance_cursor", role="hub"):
            conn.execute(
                "INSERT INTO consumer_cursors(agent, last_consumed_event_seq, updated_at) VALUES(?,?,?) "
                "ON CONFLICT(agent) DO UPDATE SET last_consumed_event_seq=excluded.last_consumed_event_seq, updated_at=excluded.updated_at",
                (agent, event_seq, _now()),
            )
    finally:
        conn.close()


# ---------------- 出站 ----------------
def enqueue_outbox(
    event_seq: int,
    bot_identity: str,
    payload: Dict[str, Any],
    outbox_id: Optional[str] = None,
) -> str:
    """入队飞书出站。相同 (event_seq, bot_identity) 只允许一条，冲突返回已存在 outbox_id。

    入站用户消息不得调用；只有 Agent 回复事件或系统状态消息可以调用。
    """
    payload = for_db(payload)
    assert_no_secret(payload, outlet=OUTLET_DB)
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="enqueue_outbox", role="outbox"):
            row = conn.execute(
                "SELECT outbox_id FROM outbox WHERE event_seq=? AND bot_identity=?",
                (event_seq, bot_identity),
            ).fetchone()
            if row:
                return row["outbox_id"]
            new_id = outbox_id or _uid("obx")
            conn.execute(
                "INSERT INTO outbox(outbox_id, event_seq, bot_identity, payload_json, state, attempt_no, next_attempt_at, created_at) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (
                    new_id,
                    event_seq,
                    bot_identity,
                    json.dumps(payload, ensure_ascii=False),
                    "pending",
                    0,
                    None,
                    _now(),
                ),
            )
            return new_id
    finally:
        conn.close()


def claim_outbox(
    worker_id: str,
    limit: int = 10,
    now_ts: Optional[float] = None,
) -> List[Dict[str, Any]]:
    """原子领取待发送 outbox。同一条只能被一个 worker 取得。"""
    now = time.time() if now_ts is None else now_ts
    conn = connect()
    try:
        # 空队列不抢写锁（Gate5-B2-WB：先只读判断，无候选返回空）
        ro = connect(read_only=True)
        try:
            cand = ro.execute(
                "SELECT 1 FROM outbox "
                "WHERE state IN ('pending','retry') "
                "  AND (next_attempt_at IS NULL OR CAST(next_attempt_at AS REAL)<=?) "
                "  AND claimed_by IS NULL "
                "LIMIT 1",
                (now,),
            ).fetchone()
        finally:
            ro.close()
        if not cand:
            return []
        with transaction(conn, immediate=True, operation="claim_outbox", role="outbox"):
            rows = conn.execute(
                "SELECT * FROM outbox "
                "WHERE state IN ('pending','retry') "
                "  AND (next_attempt_at IS NULL OR CAST(next_attempt_at AS REAL)<=?) "
                "  AND claimed_by IS NULL "
                "ORDER BY created_at LIMIT ?",
                (now, limit),
            ).fetchall()
            claimed: List[Dict[str, Any]] = []
            stamp = _now()
            for r in rows:
                cur = conn.execute(
                    "UPDATE outbox SET state='sending', claimed_by=?, claimed_at=? "
                    "WHERE outbox_id=? AND claimed_by IS NULL AND state IN ('pending','retry')",
                    (worker_id, stamp, r["outbox_id"]),
                )
                if cur.rowcount != 1:
                    continue
                rec = dict(r)
                rec["state"] = "sending"
                rec["claimed_by"] = worker_id
                rec["claimed_at"] = stamp
                claimed.append(rec)
            return claimed
    finally:
        conn.close()


def count_visible_agent_replies(conn, baseline_seq: int) -> int:
    """R2-FIX.1 #2（#528.1 修正）：以 outbox 为权威统计「可见 Agent 出站回复」。

    严格对齐生产真实状态机（feishu_outbox.send_claimed_outbox →
    repository.mark_outbox_sent）：
    - event_seq > baseline_seq（仅本轮及之后）
    - outbox.state == 'sent' 且 external_message_id 非空（已真实投递到外部平台）
    - 关联 delivery.state == 'sent'（mark_outbox_sent 把 delivery 一并置 'sent'，
      生产里绝不会是 'completed'——旧查询误用 'completed' 会把真实回复算成 0）
    - 关联 call_attempts 必须存在且 state == 'completed'：call_id 非空是「真实 Agent
      调用产物」的硬凭证，无 call_id 的系统消息（如内部广播/系统提示）一律排除，
      不得冒充 Agent 回复；state=='completed' 防 Agent 回合未结束的内部残留计数
    - bot_identity ∈ {workbuddy,hermes,codex}（仅三方 Agent 出站，排除用户）
    - 按 external_message_id 去重（at-least-once 重投不重复计数）

    反例（R2 真实故障）：仅有 Agent 文本但 outbox 未 sent / 无 external_message_id /
    delivery 非 'sent' / 无 call_id（系统消息）/ call 未完成 -> 结果必须为 0。
    """
    cur = conn.execute(
        "SELECT COUNT(DISTINCT o.external_message_id) "
        "FROM outbox o "
        "JOIN deliveries d ON d.event_seq = o.event_seq AND d.bot_identity = o.bot_identity "
        "LEFT JOIN call_attempts c ON c.call_id = d.call_id "
        "WHERE o.event_seq > ? "
        "AND o.state = 'sent' "
        "AND o.external_message_id IS NOT NULL "
        "AND o.external_message_id != '' "
        "AND d.state = 'sent' "
        "AND c.call_id IS NOT NULL "
        "AND c.state = 'completed' "
        "AND o.bot_identity IN ('workbuddy','hermes','codex')",
        (baseline_seq,),
    )
    return cur.fetchone()[0]


def mark_outbox_sent(outbox_id: str, external_message_id: str) -> None:
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="mark_outbox_sent", role="outbox"):
            conn.execute(
                "UPDATE outbox SET state='sent', sent_at=?, external_message_id=?, "
                "claimed_by=NULL, claimed_at=NULL, last_error_redacted=NULL WHERE outbox_id=?",
                (_now(), external_message_id, outbox_id),
            )
            row = conn.execute(
                "SELECT event_seq, bot_identity FROM outbox WHERE outbox_id=?", (outbox_id,)
            ).fetchone()
            if row:
                # 无对应 delivery 时不强制创建；系统消息允许独立 outbox
                conn.execute(
                    "UPDATE deliveries SET state='sent', external_message_id=? "
                    "WHERE event_seq=? AND bot_identity=?",
                    (external_message_id, row["event_seq"], row["bot_identity"]),
                )
    finally:
        conn.close()


def move_to_dead_letter(source_table: str, source_id: str, reason_code: str, payload_ref: str) -> None:
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="move_to_dead_letter", role="hub"):
            conn.execute(
                "INSERT INTO dead_letters(dead_letter_id, source_table, source_id, reason_code, payload_ref, created_at) VALUES(?,?,?,?,?,?)",
                (_uid("dl"), source_table, source_id, reason_code, payload_ref, _now()),
            )
    finally:
        conn.close()


def set_trace_control(trace_id: str, state: str, changed_by: str) -> None:
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="set_trace_control", role="hub"):
            conn.execute(
                "INSERT INTO trace_controls(trace_id, state, changed_by, changed_at) VALUES(?,?,?,?) "
                "ON CONFLICT(trace_id) DO UPDATE SET state=excluded.state, changed_by=excluded.changed_by, changed_at=excluded.changed_at",
                (trace_id, state, changed_by, _now()),
            )
    finally:
        conn.close()


# ---------------- 身份绑定解析（物理会话 id 唯一来源）----------------
class BindingNotFound(Exception):
    """agent_bindings 中查不到绑定；禁止回落任何硬编码 session。"""


def get_binding(agent: str) -> Dict[str, Any]:
    """读取 agent 的绑定行。物理会话 id 只能从这里来，源码中不得出现。

    【F-3】必须带出 preverified 权威值（adapter 的 BindingVerification.preverified
    直接取该值，禁止用 dataclass 默认值或任何推断升级）；同时带出 active_binding_count
    供 adapter 判定"重复 active 绑定"这一稳定错误码。
    """
    conn = connect(read_only=True)
    try:
        row = conn.execute(
            "SELECT agent, logical_session, actual_session_id, adapter, status, binding_version, "
            "preverified FROM agent_bindings WHERE agent=?",
            (agent,),
        ).fetchone()
        if row is None:
            raise BindingNotFound(f"no binding for agent={agent}")
        data = dict(row)
        cnt = conn.execute(
            "SELECT COUNT(*) AS c FROM agent_bindings WHERE agent=?", (agent,)
        ).fetchone()
        data["active_binding_count"] = int(cnt["c"]) if cnt else 1
        return data
    finally:
        conn.close()


def get_actual_session(agent: str) -> str:
    """返回物理会话 id。缺失即抛错，绝不回落硬编码。"""
    b = get_binding(agent)
    sid = b.get("actual_session_id")
    if not sid:
        raise BindingNotFound(f"binding for agent={agent} has empty actual_session_id")
    return sid


def set_binding(agent: str, logical_session: str, actual_session_id: str,
                adapter: str, status: str = "online") -> int:
    """写入/更新绑定，binding_version 自增。用于 Step 8 切换 triad-codex-main。"""
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="set_binding", role="hub"):
            row = conn.execute(
                "SELECT binding_version FROM agent_bindings WHERE agent=?", (agent,)
            ).fetchone()
            ver = (row["binding_version"] + 1) if row else 1
            conn.execute(
                "INSERT INTO agent_bindings(agent, logical_session, actual_session_id, adapter, status, "
                "binding_version, verified_at, metadata_json) VALUES(?,?,?,?,?,?,?,'{}') "
                "ON CONFLICT(agent) DO UPDATE SET logical_session=excluded.logical_session, "
                "actual_session_id=excluded.actual_session_id, adapter=excluded.adapter, "
                "status=excluded.status, binding_version=excluded.binding_version, "
                "verified_at=excluded.verified_at",
                (agent, logical_session, actual_session_id, adapter, status, ver, _now()),
            )
        return ver
    finally:
        conn.close()


# ---------------- Step 8：绑定验真（triad-codex-main 真实性证据）----------------


def has_verified_codex_binding() -> bool:
    """是否已存在 verified 的 triad-codex-main 绑定（status='online' + preverified=1）。"""
    conn = connect(read_only=True)
    try:
        row = conn.execute(
            "SELECT 1 FROM agent_bindings "
            "WHERE agent='codex' AND logical_session='triad-codex-main' "
            "  AND status='online' AND preverified=1 LIMIT 1",
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def get_binding_row(agent: str) -> Optional[Dict[str, Any]]:
    """返回 agent 绑定全列（含 preverified / metadata_json）。"""
    conn = connect(read_only=True)
    try:
        row = conn.execute(
            "SELECT * FROM agent_bindings WHERE agent=?", (agent,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def insert_binding_verification(*, rec: Dict[str, Any]) -> None:
    """写入一条 binding_verifications。evidence_ref 只存相对路径。"""
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="insert_binding_verification", role="hub"):
            conn.execute(
                "INSERT INTO binding_verifications("
                "verification_id, agent, logical_session, requested_session_id, actual_session_id, "
                "verification_type, command_mode, nonce_hash, bootstrap_manifest_hash, "
                "exit_code, evidence_ref, status, error_code, created_at, parent_verification_id) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    rec["verification_id"], rec["agent"], rec["logical_session"],
                    rec.get("requested_session_id"), rec.get("actual_session_id"),
                    rec["verification_type"], rec["command_mode"], rec.get("nonce_hash"),
                    rec.get("bootstrap_manifest_hash"), rec.get("exit_code"),
                    rec.get("evidence_ref"), rec["status"], rec.get("error_code"),
                    rec.get("created_at", _now()), rec.get("parent_verification_id"),
                ),
            )
    finally:
        conn.close()


def get_binding_verification(verification_id: str) -> Optional[Dict[str, Any]]:
    """按 id 读取单条 binding_verifications。"""
    conn = connect(read_only=True)
    try:
        row = conn.execute(
            "SELECT * FROM binding_verifications WHERE verification_id=?",
            (verification_id,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def insert_recovery_verification(*, parent_verification_id: str, rec: Dict[str, Any]) -> Dict[str, Any]:
    """恢复协议：为一条 failed 的 fresh_create 记录派生一条 created 记录（单事务 + 幂等）。

    单 BEGIN IMMEDIATE 事务内完成：
      1) 父记录必须存在、agent=codex、logical_session=triad-codex-main、
         verification_type=fresh_create、status=failed、error_code=bootstrap_reply_mismatch；
      2) 父记录字段（actual_session_id / nonce_hash / bootstrap_manifest_hash / exit_code /
         evidence_ref）必须与恢复记录完全一致——恢复只允许"重新解析同一份证据"，
         不允许引入任何新的物理事实；
      3) 幂等：该父记录若已派生过恢复记录，直接返回既有记录，不新增第二条；
      4) 插入新记录（status=created, parent_verification_id=父 id）。
    父记录本身在任何路径下都不做 UPDATE。
    """
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="insert_recovery_verification", role="hub"):
            prow = conn.execute(
                "SELECT * FROM binding_verifications WHERE verification_id=?",
                (parent_verification_id,),
            ).fetchone()
            if not prow:
                raise ValueError(f"parent verification not found: {parent_verification_id}")
            parent = dict(prow)
            if parent["agent"] != "codex" or parent["logical_session"] != "triad-codex-main":
                raise ValueError("parent verification does not belong to triad-codex-main")
            if parent["verification_type"] != "fresh_create":
                raise ValueError(f"parent verification_type={parent['verification_type']!r}, expected 'fresh_create'")
            if parent["status"] != "failed":
                raise ValueError(f"parent status={parent['status']!r}, expected 'failed'")
            if parent.get("error_code") != "bootstrap_reply_mismatch":
                raise ValueError(f"parent error_code={parent.get('error_code')!r}, expected 'bootstrap_reply_mismatch'")

            # 恢复记录必须复用父记录的物理事实，不得篡改
            for field in ("actual_session_id", "nonce_hash", "bootstrap_manifest_hash",
                          "exit_code", "evidence_ref"):
                if rec.get(field) != parent.get(field):
                    raise ValueError(
                        f"recovery record field {field!r} differs from parent (recovery must reuse original evidence)"
                    )

            existing = conn.execute(
                "SELECT * FROM binding_verifications WHERE parent_verification_id=?",
                (parent_verification_id,),
            ).fetchone()
            if existing:
                return {"status": "already_recovered", "record": dict(existing)}

            conn.execute(
                "INSERT INTO binding_verifications("
                "verification_id, agent, logical_session, requested_session_id, actual_session_id, "
                "verification_type, command_mode, nonce_hash, bootstrap_manifest_hash, "
                "exit_code, evidence_ref, status, error_code, created_at, parent_verification_id) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    rec["verification_id"], "codex", "triad-codex-main",
                    rec.get("requested_session_id"), rec.get("actual_session_id"),
                    "fresh_create", rec["command_mode"], rec.get("nonce_hash"),
                    rec.get("bootstrap_manifest_hash"), rec.get("exit_code"),
                    rec.get("evidence_ref"), "created", rec.get("error_code"),
                    rec.get("created_at", _now()), parent_verification_id,
                ),
            )
            row = conn.execute(
                "SELECT * FROM binding_verifications WHERE verification_id=?",
                (rec["verification_id"],),
            ).fetchone()
            return {"status": "recovered", "record": dict(row)}
    finally:
        conn.close()


def get_binding_verifications(agent: str, verification_type: Optional[str] = None) -> List[Dict[str, Any]]:
    """读取 agent 的绑定验真记录（可选按类型过滤）。"""
    conn = connect(read_only=True)
    try:
        if verification_type:
            rows = conn.execute(
                "SELECT * FROM binding_verifications WHERE agent=? AND verification_type=? "
                "ORDER BY created_at",
                (agent, verification_type),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM binding_verifications WHERE agent=? ORDER BY created_at",
                (agent,),
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ---------------- Evidence 隔离（Step 8 安全收尾 / migration 007） ----------------
def insert_evidence_quarantine(*, rec: Dict[str, Any]) -> Dict[str, Any]:
    """登记一条 evidence 隔离记录（append-only 侧表，不改写既有验真记录）。

    幂等：同一 original_ref 重复写入时返回既有记录（status=exists）；
    若既有记录的 raw_evidence_sha256 与本次不同，判定为篡改，抛错。
    """
    required = (
        "artifact_kind", "original_ref", "raw_evidence_sha256",
        "private_raw_ref", "sanitized_evidence_ref", "sanitized_sha256",
    )
    for k in required:
        if not rec.get(k):
            raise ValueError(f"insert_evidence_quarantine: missing field {k}")

    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="insert_evidence_quarantine", role="hub"):
            existing = conn.execute(
                "SELECT * FROM evidence_quarantine WHERE original_ref=?",
                (rec["original_ref"],),
            ).fetchone()
            if existing is not None:
                row = dict(existing)
                if row["raw_evidence_sha256"] != rec["raw_evidence_sha256"]:
                    raise ValueError(
                        "evidence_quarantine_tampered: raw sha256 mismatch for "
                        f"{rec['original_ref']}"
                    )
                return {"status": "exists", "record": row}

            qid = rec.get("quarantine_id") or _uid("eq")
            conn.execute(
                "INSERT INTO evidence_quarantine("
                "quarantine_id, artifact_kind, original_ref, raw_evidence_sha256,"
                " private_raw_ref, sanitized_evidence_ref, sanitized_sha256,"
                " redaction_count, session_hashes_json, verification_id,"
                " quarantined_at, note) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    qid, rec["artifact_kind"], rec["original_ref"],
                    rec["raw_evidence_sha256"], rec["private_raw_ref"],
                    rec["sanitized_evidence_ref"], rec["sanitized_sha256"],
                    int(rec.get("redaction_count") or 0),
                    rec["session_hashes_json"]
                    if isinstance(rec.get("session_hashes_json"), str)
                    else json.dumps(rec.get("session_hashes") or [], ensure_ascii=False),
                    rec.get("verification_id"),
                    rec.get("quarantined_at") or _now(),
                    rec.get("note"),
                ),
            )
            row = conn.execute(
                "SELECT * FROM evidence_quarantine WHERE quarantine_id=?", (qid,)
            ).fetchone()
            return {"status": "quarantined", "record": dict(row)}
    finally:
        conn.close()


def update_evidence_quarantine_sanitized(
    *, original_ref: str, sanitized_sha256: str, redaction_count: int,
    session_hashes: Optional[List[str]] = None, note: Optional[str] = None,
) -> Dict[str, Any]:
    """脱敏层升级后重生成脱敏副本时，更新记录的副本指纹。

    raw_evidence_sha256 / private_raw_ref 是原件锚点，**永不更新**；
    只允许刷新脱敏副本侧的字段，保证"原始 → 隔离 → 脱敏"三段仍可复验。
    """
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="update_evidence_quarantine_sanitized", role="hub"):
            row = conn.execute(
                "SELECT * FROM evidence_quarantine WHERE original_ref=?", (original_ref,)
            ).fetchone()
            if row is None:
                raise ValueError(f"evidence_quarantine_not_found: {original_ref}")
            conn.execute(
                "UPDATE evidence_quarantine SET sanitized_sha256=?, redaction_count=?,"
                " session_hashes_json=COALESCE(?, session_hashes_json),"
                " note=COALESCE(?, note) WHERE original_ref=?",
                (
                    sanitized_sha256, int(redaction_count),
                    json.dumps(session_hashes, ensure_ascii=False) if session_hashes else None,
                    note, original_ref,
                ),
            )
            out = conn.execute(
                "SELECT * FROM evidence_quarantine WHERE original_ref=?", (original_ref,)
            ).fetchone()
            return {"status": "updated", "record": dict(out)}
    finally:
        conn.close()


def get_evidence_quarantine(original_ref: str) -> Optional[Dict[str, Any]]:
    """按原始 evidence 引用查隔离记录。"""
    conn = connect(read_only=True)
    try:
        row = conn.execute(
            "SELECT * FROM evidence_quarantine WHERE original_ref=?", (original_ref,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def list_evidence_quarantine(artifact_kind: Optional[str] = None) -> List[Dict[str, Any]]:
    """列出隔离记录（可按 artifact_kind 过滤）。"""
    conn = connect(read_only=True)
    try:
        if artifact_kind:
            rows = conn.execute(
                "SELECT * FROM evidence_quarantine WHERE artifact_kind=? "
                "ORDER BY quarantined_at",
                (artifact_kind,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM evidence_quarantine ORDER BY quarantined_at"
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ---------------- stdout_evidence（Gate5-B2 阶段一 v3：两阶段登记） ----------------
# 状态机：pending -> verified（原子发布+校验后）| failed / quarantined（任一步失败）。
# 幂等：UNIQUE(idempotency_hash)；同 key 同内容复用，同 key 不同内容判冲突。
STDOUT_STATUS_PENDING = "pending"
STDOUT_STATUS_VERIFIED = "verified"
STDOUT_STATUS_FAILED = "failed"
STDOUT_STATUS_QUARANTINED = "quarantined"


def insert_stdout_evidence_pending(
    *, agent: str, raw_ref: str, reviewed_ref: str, raw_sha256: str,
    reviewed_sha256: str, idempotency_hash: str, note: str = "",
) -> Dict[str, Any]:
    """登记 pending 记录（事务内）。

    返回 {"status": "created"|"exists"|"conflict", "record": {...}}。
    - exists：idempotency_hash 已存在且 raw_sha 一致（幂等复用，不重复登记）；
    - conflict：idempotency_hash 已存在但 raw_sha 不同（同 key 不同内容，禁止生成两份证据）。
    """
    now = _now()
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="insert_stdout_evidence_pending", role="hub"):
            existing = conn.execute(
                "SELECT * FROM stdout_evidence WHERE idempotency_hash=?",
                (idempotency_hash,),
            ).fetchone()
            if existing is not None:
                rec = dict(existing)
                if rec["raw_sha256"] == raw_sha256:
                    return {"status": "exists", "record": rec}
                return {"status": "conflict", "record": rec}
            evidence_id = _uid("sev")
            conn.execute(
                "INSERT INTO stdout_evidence(evidence_id, agent, raw_ref, reviewed_ref, "
                "raw_sha256, reviewed_sha256, idempotency_hash, status, acl_verified, "
                "redaction_count, created_at, updated_at, note) "
                "VALUES(?,?,?,?,?,?,?,?,0,0,?,?,?)",
                (evidence_id, agent, raw_ref, reviewed_ref, raw_sha256, reviewed_sha256,
                 idempotency_hash, STDOUT_STATUS_PENDING, now, now, note),
            )
            row = conn.execute(
                "SELECT * FROM stdout_evidence WHERE evidence_id=?", (evidence_id,)
            ).fetchone()
            return {"status": "created", "record": dict(row)}
    finally:
        conn.close()


def get_stdout_evidence_by_idem(idempotency_hash: str) -> Optional[Dict[str, Any]]:
    """按幂等哈希查记录（读）。"""
    conn = connect(read_only=True)
    try:
        row = conn.execute(
            "SELECT * FROM stdout_evidence WHERE idempotency_hash=?", (idempotency_hash,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def update_stdout_evidence_status(
    evidence_id: str, status: str, *, acl_verified: Optional[int] = None,
    redaction_count: Optional[int] = None, note: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """原子更新登记状态（verified / failed / quarantined）。"""
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="update_stdout_evidence_status", role="hub"):
            sets = ["status=?", "updated_at=?"]
            params: list = [status, _now()]
            if acl_verified is not None:
                sets.append("acl_verified=?")
                params.append(int(acl_verified))
            if redaction_count is not None:
                sets.append("redaction_count=?")
                params.append(int(redaction_count))
            if note is not None:
                sets.append("note=?")
                params.append(note)
            params.append(evidence_id)
            conn.execute(
                f"UPDATE stdout_evidence SET {', '.join(sets)} WHERE evidence_id=?",
                params,
            )
            row = conn.execute(
                "SELECT * FROM stdout_evidence WHERE evidence_id=?", (evidence_id,)
            ).fetchone()
            return dict(row) if row else None
    finally:
        conn.close()


def list_stdout_evidence(status: Optional[str] = None) -> List[Dict[str, Any]]:
    """列出 stdout 证据登记（可按状态过滤）。"""
    conn = connect(read_only=True)
    try:
        if status:
            rows = conn.execute(
                "SELECT * FROM stdout_evidence WHERE status=? ORDER BY created_at",
                (status,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM stdout_evidence ORDER BY created_at"
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def commit_verified_binding(
    *,
    agent: str,
    logical_session: str,
    actual_session_id: str,
    adapter: str,
    verification_ids: List[str],
    metadata: Dict[str, Any],
) -> int:
    """原子提交 triad-codex-main 正式绑定（Step 8.16）。

    单 BEGIN IMMEDIATE 事务内：核对 agent=codex / logical_session=triad-codex-main /
    三条 verification 存在且状态为 created/verified/verified / 三条 actual_session_id 相同且等于入参 /
    三条 bootstrap_manifest_hash 一致 / binding_version+1 / 更新 agent_bindings(preverified=1) /
    插入 binding_commit verification（脱敏 audit）/ commit。任一步失败整体回滚。
    """
    if agent != "codex":
        raise ValueError(f"commit_verified_binding requires agent='codex', got {agent!r}")
    if logical_session != "triad-codex-main":
        raise ValueError(f"commit_verified_binding requires logical_session='triad-codex-main', got {logical_session!r}")
    if not isinstance(verification_ids, list) or len(verification_ids) != 3:
        raise ValueError("verification_ids must be a list of exactly 3 ids (create, resume, continuity)")

    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="commit_verified_binding", role="hub"):
            # 1) 三条 verification 必须存在
            placeholders = ",".join("?" for _ in verification_ids)
            rows = conn.execute(
                f"SELECT * FROM binding_verifications "
                f"WHERE verification_id IN ({placeholders})",
                verification_ids,
            ).fetchall()
            by_id = {r["verification_id"]: dict(r) for r in rows}
            for vid in verification_ids:
                if vid not in by_id:
                    raise ValueError(f"missing verification_id: {vid}")

            # 2) 状态必须为 created / verified / verified（顺序：create, resume, continuity）
            expected_statuses = ["created", "verified", "verified"]
            actual_sessions = []
            manifest_hashes = []
            for vid, exp in zip(verification_ids, expected_statuses):
                rec = by_id[vid]
                if rec["status"] != exp:
                    raise ValueError(
                        f"verification {vid} status={rec['status']!r}, expected {exp!r}"
                    )
                if rec["agent"] != "codex" or rec["logical_session"] != "triad-codex-main":
                    raise ValueError(f"verification {vid} does not belong to triad-codex-main")
                actual_sessions.append(rec["actual_session_id"])
                manifest_hashes.append(rec.get("bootstrap_manifest_hash"))

            # 3) 三条 actual_session_id 必须完全相同，且等于入参
            if not all(s == actual_sessions[0] for s in actual_sessions):
                raise ValueError("three verification actual_session_id mismatch")
            if actual_sessions[0] != actual_session_id:
                raise ValueError("verification actual_session_id != requested actual_session_id")

            # 4) manifest hash 一致
            if not all(h == manifest_hashes[0] for h in manifest_hashes) or not manifest_hashes[0]:
                raise ValueError("verification bootstrap_manifest_hash mismatch or empty")

            # 4.5) 幂等：相同 (actual_session_id, manifest_hash) 的 binding_commit 已存在则直接返回当前版本
            dup = conn.execute(
                "SELECT 1 FROM binding_verifications "
                "WHERE verification_type='binding_commit' AND actual_session_id=? "
                "  AND bootstrap_manifest_hash=? LIMIT 1",
                (actual_sessions[0], manifest_hashes[0]),
            ).fetchone()
            if dup:
                cur = conn.execute(
                    "SELECT binding_version FROM agent_bindings WHERE agent='codex'"
                ).fetchone()
                return cur["binding_version"] if cur else 0

            # 5) binding_version+1（保留旧 binding 哈希引用，不复制旧物理 id）
            old = conn.execute(
                "SELECT * FROM agent_bindings WHERE agent='codex'"
            ).fetchone()
            old_ref = None
            if old:
                old_ref = {
                    "binding_version": old["binding_version"],
                    "logical_session": old["logical_session"],
                    "status": old["status"],
                }
            new_version = (old["binding_version"] + 1) if old else 1

            # 6) 更新 agent_bindings
            meta_json = json.dumps(metadata, ensure_ascii=False) if metadata else "{}"
            conn.execute(
                "INSERT INTO agent_bindings("
                "agent, logical_session, actual_session_id, adapter, status, "
                "binding_version, verified_at, preverified, metadata_json) "
                "VALUES(?,?,?,?,?,?,?,1,?) "
                "ON CONFLICT(agent) DO UPDATE SET logical_session=excluded.logical_session, "
                "actual_session_id=excluded.actual_session_id, adapter=excluded.adapter, "
                "status=excluded.status, binding_version=excluded.binding_version, "
                "verified_at=excluded.verified_at, preverified=excluded.preverified, "
                "metadata_json=excluded.metadata_json",
                (
                    "codex", "triad-codex-main", actual_session_id, adapter, "online",
                    new_version, _now(), meta_json,
                ),
            )

            # 7) 脱敏 audit：binding_commit verification
            commit_id = "bv_" + hashlib.sha256(
                f"{actual_session_id}|{new_version}|{_now()}".encode("utf-8")
            ).hexdigest()[:16]
            conn.execute(
                "INSERT INTO binding_verifications("
                "verification_id, agent, logical_session, requested_session_id, actual_session_id, "
                "verification_type, command_mode, nonce_hash, bootstrap_manifest_hash, "
                "exit_code, evidence_ref, status, error_code, created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    commit_id, "codex", "triad-codex-main", None, actual_session_id,
                    "binding_commit", "resume", None, manifest_hashes[0],
                    0, None, "verified", None, _now(),
                ),
            )
        return new_version
    finally:
        conn.close()


# ---------------- Step 6：共享上下文与摘要 ----------------
# 上下文包只保存范围/哈希/证据序号，不保存完整 prompt 或原始事件全文。
_EVENT_COLS = (
    "event_seq, event_id, trace_id, parent_event_id, root_event_id, "
    "source_agent, source_type, message_type, text, mentions_json, refs_json, created_at, received_at"
)


def get_consumer_cursor(agent: str) -> int:
    """返回 Agent 最后成功消费的 event_seq；不存在时返回 0。"""
    conn = connect(read_only=True)
    try:
        row = conn.execute(
            "SELECT last_consumed_event_seq FROM consumer_cursors WHERE agent=?", (agent,)
        ).fetchone()
        return row["last_consumed_event_seq"] if row else 0
    finally:
        conn.close()


def get_event(event_seq: int) -> Optional[Dict[str, Any]]:
    """按 event_seq 读取单条脱敏事件。"""
    conn = connect(read_only=True)
    try:
        row = conn.execute(
            f"SELECT {_EVENT_COLS} FROM events WHERE event_seq=?", (event_seq,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_events_range(from_exclusive: int, to_inclusive: int) -> List[Dict[str, Any]]:
    """按 event_seq 升序返回 (from_exclusive, to_inclusive] 范围事件。"""
    conn = connect(read_only=True)
    try:
        rows = conn.execute(
            f"SELECT {_EVENT_COLS} FROM events "
            f"WHERE event_seq > ? AND event_seq <= ? ORDER BY event_seq",
            (from_exclusive, to_inclusive),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_events_by_trace(trace_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    conn = connect(read_only=True)
    try:
        rows = conn.execute(
            f"SELECT {_EVENT_COLS} FROM events WHERE trace_id=? ORDER BY event_seq DESC LIMIT ?",
            (trace_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_events_by_task(task_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    """events.task_id 列由 003 迁移新增并由 ingest_event 写入。"""
    conn = connect(read_only=True)
    try:
        rows = conn.execute(
            f"SELECT {_EVENT_COLS} FROM events WHERE task_id=? ORDER BY event_seq DESC LIMIT ?",
            (task_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_task(task_id: str) -> Optional[Dict[str, Any]]:
    conn = connect(read_only=True)
    try:
        row = conn.execute(
            "SELECT task_id, owner, objective, acceptance_criteria, trace_id, state, "
            "result_ref, evidence_refs_json, revision FROM tasks WHERE task_id=?",
            (task_id,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_latest_verified_summary(up_to_event_seq: int) -> Optional[Dict[str, Any]]:
    """返回不晚于 up_to_event_seq 的最新 verified 摘要（仅 verified，按 to_event_seq 倒序）。"""
    conn = connect(read_only=True)
    try:
        row = conn.execute(
            "SELECT summary_id, from_event_seq, to_event_seq, summary_text, source_digest, facts_json "
            "FROM shared_summaries WHERE status='verified' AND to_event_seq <= ? "
            "ORDER BY to_event_seq DESC LIMIT 1",
            (up_to_event_seq,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def create_context_packet_record(
    *,
    packet_id: str,
    agent: str,
    trigger_event_seq: int,
    last_consumed_event_seq: int,
    through_event_seq: int,
    summary_id: Optional[str],
    summary_from_seq: Optional[int],
    summary_to_seq: Optional[int],
    delta_from_seq: Optional[int],
    delta_to_seq: Optional[int],
    required_event_seqs: List[int],
    payload_hash: str,
) -> None:
    """审计落库一条上下文包，初始状态 built。绝不前移消费游标。"""
    required_json = for_db({"seqs": list(required_event_seqs)})
    assert_no_secret(required_json, OUTLET_DB)
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="create_context_packet_record", role="agent"):
            conn.execute(
                "INSERT INTO context_packets("
                "packet_id, agent, trigger_event_seq, last_consumed_event_seq, through_event_seq, "
                "summary_id, summary_from_seq, summary_to_seq, delta_from_seq, delta_to_seq, "
                "required_event_seqs_json, payload_hash, state, created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,'built',?)",
                (
                    packet_id,
                    agent,
                    trigger_event_seq,
                    last_consumed_event_seq,
                    through_event_seq,
                    summary_id,
                    summary_from_seq,
                    summary_to_seq,
                    delta_from_seq,
                    delta_to_seq,
                    json.dumps(required_json, ensure_ascii=False),
                    payload_hash,
                    _now(),
                ),
            )
    finally:
        conn.close()


def mark_context_delivered(packet_id: str) -> None:
    """built -> delivered。游标不变。"""
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="mark_context_delivered", role="agent"):
            row = conn.execute(
                "SELECT state FROM context_packets WHERE packet_id=?", (packet_id,)
            ).fetchone()
            if not row or row["state"] != "built":
                raise ValueError(f"mark_context_delivered requires built state, got {row['state'] if row else 'missing'}")
            conn.execute(
                "UPDATE context_packets SET state='delivered', delivered_at=? WHERE packet_id=?",
                (_now(), packet_id),
            )
    finally:
        conn.close()


def mark_context_failed(packet_id: str, failure_code: str) -> None:
    """built/delivered -> failed。游标不变。"""
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="mark_context_failed", role="agent"):
            row = conn.execute(
                "SELECT state FROM context_packets WHERE packet_id=?", (packet_id,)
            ).fetchone()
            if not row or row["state"] not in ("built", "delivered"):
                raise ValueError(f"mark_context_failed requires built/delivered, got {row['state'] if row else 'missing'}")
            conn.execute(
                "UPDATE context_packets SET state='failed', failure_code=? WHERE packet_id=?",
                (failure_code, packet_id),
            )
    finally:
        conn.close()


def commit_context_consumed(
    *,
    packet_id: str,
    agent: str,
    through_event_seq: int,
    reason: str = "agent_reply_persisted",
) -> None:
    """Agent 回复及真实性元数据原子落库成功后，才允许前移游标。

    必须在 BEGIN IMMEDIATE 内：
    1) 读取 packet；2) 核对 agent；3) 核对状态 delivered；
    4) 核对 through_event_seq 等于记录值；5) 读取当前 cursor；
    6) 禁止新值 < 当前 cursor；7) 更新 consumer_cursors；
    8) 插入 consumer_cursor_history；9) packet 状态 -> consumed。
    同 packet 重复提交幂等返回，不新增历史。
    """
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="commit_context_consumed", role="agent"):
            _commit_context_consumed_conn(
                conn,
                packet_id=packet_id,
                agent=agent,
                through_event_seq=through_event_seq,
                reason=reason,
            )
    finally:
        conn.close()


def _commit_context_consumed_conn(
    conn,
    *,
    packet_id: str,
    agent: str,
    through_event_seq: int,
    reason: str = "agent_reply_persisted",
) -> None:
    """commit_context_consumed 的连接内版本，供 commit_agent_reply 同连接调用。

    不自行开关事务；调用方必须已持有 BEGIN IMMEDIATE。
    """
    pkt = conn.execute(
        "SELECT * FROM context_packets WHERE packet_id=?", (packet_id,)
    ).fetchone()
    if not pkt:
        raise ValueError("context packet not found")
    if pkt["agent"] != agent:
        raise ValueError("context packet agent mismatch")
    if pkt["state"] == "consumed":
        # 已消费：幂等放行，不重复写历史
        return
    if pkt["state"] != "delivered":
        raise ValueError(f"context packet not delivered: {pkt['state']}")
    if pkt["through_event_seq"] != through_event_seq:
        raise ValueError("through_event_seq tampered")
    cur = conn.execute(
        "SELECT last_consumed_event_seq FROM consumer_cursors WHERE agent=?", (agent,)
    ).fetchone()
    cur_seq = cur["last_consumed_event_seq"] if cur else 0
    new_seq = through_event_seq
    if new_seq < cur_seq:
        raise ValueError("consumer cursor cannot move backward")
    existing = conn.execute(
        "SELECT 1 FROM consumer_cursor_history WHERE agent=? AND packet_id=?",
        (agent, packet_id),
    ).fetchone()
    if existing:
        # 幂等：确保状态为 consumed，不重复写历史
        conn.execute(
            "UPDATE context_packets SET state='consumed', consumed_at=? WHERE packet_id=? AND state<>'consumed'",
            (_now(), packet_id),
        )
        return
    conn.execute(
        "INSERT INTO consumer_cursors(agent, last_consumed_event_seq, updated_at) VALUES(?,?,?) "
        "ON CONFLICT(agent) DO UPDATE SET last_consumed_event_seq=excluded.last_consumed_event_seq, "
        "updated_at=excluded.updated_at",
        (agent, new_seq, _now()),
    )
    conn.execute(
        "INSERT INTO consumer_cursor_history(cursor_event_id, agent, packet_id, previous_event_seq, "
        "new_event_seq, reason, created_at) VALUES(?,?,?,?,?,?,?)",
        (_uid("cur"), agent, packet_id, cur_seq, new_seq, reason, _now()),
    )
    conn.execute(
        "UPDATE context_packets SET state='consumed', consumed_at=? WHERE packet_id=?",
        (_now(), packet_id),
    )


# ---------------- Step 7：调用队列（call worker 驱动）----------------
def claim_next_delivery(
    *,
    agent: str,
    worker_id: str,
    now_ts: Optional[float] = None,
) -> Optional[Dict[str, Any]]:
    """原子领取一条待调用投递。无任务返回 None。

    筛选：destination=agent, state IN ('pending','retry'),
          next_attempt_at 为空或到期, claimed_by 为空；按 event_seq ASC。
    同事务：delivery -> claimed；写 claimed_by/claimed_at/call_id；
            INSERT OR IGNORE call_attempts（同 event_seq+agent 只一条 call）。
    稳定生成：call_id = "call_" + sha256(event_seq|agent)；
              idempotency_key = "agent-call:{event_seq}:{agent}"。
    """
    now = time.time() if now_ts is None else now_ts
    conn = connect()
    try:
        # 空队列不抢写锁（Gate5-B2-WB：先用只读查询判断是否存在候选，无候选直接 idle）
        ro = connect(read_only=True)
        try:
            cand = ro.execute(
                "SELECT 1 FROM deliveries "
                "WHERE destination=? AND state IN ('pending','retry') "
                "  AND (next_attempt_at IS NULL OR CAST(next_attempt_at AS REAL) <= ?) "
                "  AND claimed_by IS NULL "
                "LIMIT 1",
                (agent, now),
            ).fetchone()
        finally:
            ro.close()
        if not cand:
            return None
        with transaction(conn, immediate=True, operation="claim_next_delivery", role="agent"):
            row = conn.execute(
                "SELECT * FROM deliveries "
                "WHERE destination=? AND state IN ('pending','retry') "
                "  AND (next_attempt_at IS NULL OR CAST(next_attempt_at AS REAL) <= ?) "
                "  AND claimed_by IS NULL "
                "ORDER BY event_seq ASC LIMIT 1",
                (agent, now),
            ).fetchone()
            if not row:
                return None
            event_seq = row["event_seq"]
            call_id = "call_" + hashlib.sha256(
                f"{event_seq}|{agent}".encode("utf-8")
            ).hexdigest()
            idempotency_key = f"agent-call:{event_seq}:{agent}"
            conn.execute(
                "INSERT OR IGNORE INTO call_attempts("
                "call_id, event_seq, agent, idempotency_key, state, trace_id, started_at) "
                "VALUES(?,?,?,?,'pending',?,?)",
                (call_id, event_seq, agent, idempotency_key, row["trace_id"], ""),
            )
            cur = conn.execute(
                "UPDATE deliveries SET state='claimed', claimed_by=?, claimed_at=?, call_id=? "
                "WHERE delivery_id=? AND claimed_by IS NULL",
                (worker_id, _now(), call_id, row["delivery_id"]),
            )
            if cur.rowcount != 1:
                # 并发被抢：幂等返回 None
                return None
            dlv = conn.execute(
                "SELECT * FROM deliveries WHERE delivery_id=?", (row["delivery_id"],)
            ).fetchone()
            call = conn.execute(
                "SELECT * FROM call_attempts WHERE call_id=?", (call_id,)
            ).fetchone()
        return {"delivery": dict(dlv), "call": dict(call)}
    finally:
        conn.close()


def mark_call_running(
    *,
    call_id: str,
    delivery_id: str,
    worker_id: str,
    context_packet_id: str,
    requested_session_id: str,
    command_mode: str,
    lease_expires_at: str,
) -> None:
    """delivery/call -> running。绑定调用上下文字段到 call_attempts。"""
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="mark_call_running", role="agent"):
            conn.execute(
                "UPDATE call_attempts SET state='running', context_packet_id=?, "
                "requested_session_id=?, command_mode=?, lease_expires_at=?, "
                "claimed_by=?, claimed_at=?, started_at=? WHERE call_id=?",
                (
                    context_packet_id,
                    requested_session_id,
                    command_mode,
                    lease_expires_at,
                    worker_id,
                    _now(),
                    _now(),
                    call_id,
                ),
            )
            conn.execute(
                "UPDATE deliveries SET state='running', call_id=? WHERE delivery_id=? AND state='claimed'",
                (call_id, delivery_id),
            )
    finally:
        conn.close()


def mark_call_waiting_summary(
    *,
    call_id: str,
    delivery_id: str,
    reason_code: str,
) -> None:
    """call/delivery -> waiting_summary。游标不变。"""
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="mark_call_waiting_summary", role="agent"):
            conn.execute(
                "UPDATE call_attempts SET state='waiting_summary', error_code=? WHERE call_id=?",
                (reason_code, call_id),
            )
            conn.execute(
                "UPDATE deliveries SET state='waiting_summary', last_error_redacted=? WHERE delivery_id=?",
                (reason_code, delivery_id),
            )
    finally:
        conn.close()


def mark_call_blocked(
    *,
    call_id: str,
    delivery_id: str,
    reason_code: str,
) -> None:
    """call/delivery -> blocked。不创建 outbox。"""
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="mark_call_blocked", role="agent"):
            conn.execute(
                "UPDATE call_attempts SET state='blocked', error_code=? WHERE call_id=?",
                (reason_code, call_id),
            )
            conn.execute(
                "UPDATE deliveries SET state='blocked', last_error_redacted=? WHERE delivery_id=?",
                (reason_code, delivery_id),
            )
    finally:
        conn.close()


def mark_call_result_unknown(
    *,
    call_id: str,
    delivery_id: str,
    reason_code: str,
) -> None:
    """call/delivery -> result_unknown。不得进入自动 retry。"""
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="mark_call_result_unknown", role="agent"):
            conn.execute(
                "UPDATE call_attempts SET state='result_unknown', result_unknown_at=?, error_code=? WHERE call_id=?",
                (_now(), reason_code, call_id),
            )
            conn.execute(
                "UPDATE deliveries SET state='result_unknown', last_error_redacted=? WHERE delivery_id=?",
                (reason_code, delivery_id),
            )
    finally:
        conn.close()


def commit_agent_reply(
    *,
    call_id: str,
    delivery_id: str,
    packet_id: str,
    agent: str,
    trigger_event_seq: int,
    result: Any,
) -> Dict[str, Any]:
    """成功调用后原子提交：单一 BEGIN IMMEDIATE 完成全部写入，任一步失败全回滚。

    步骤：核对 call/delivery 仍 running、packet 属本 agent 且 delivered、lease 属本 call；
    写 events(agent_reply)、messages、call_attempts(completed)、deliveries(completed)、
    飞书 outbox、原子前移 cursor、cursor history、packet consumed、删除 lease。
    result 应为 AdapterResult（含 text / actual_session_id / exit_code / stdout_ref / result_ref）。
    绝不写 prompt 全文、绝不写私有记忆、绝不写敏感配置。
    """
    text = result.text if hasattr(result, "text") else str(result)
    actual_session_id = getattr(result, "actual_session_id", None)
    exit_code = getattr(result, "exit_code", None)
    stdout_ref = getattr(result, "stdout_ref", None)
    result_ref = getattr(result, "result_ref", None)
    assert_no_secret(text)
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="commit_agent_reply", role="hub"):
            call = conn.execute(
                "SELECT * FROM call_attempts WHERE call_id=?", (call_id,)
            ).fetchone()
            if call and call["state"] == "completed":
                # 幂等：已完成的 call 重复提交，返回既有回复事件，不重复写。
                return {
                    "status": "completed",
                    "reply_event_seq": call["response_event_seq"],
                    "agent": agent,
                    "idempotent": True,
                }
            if not call or call["state"] != "running":
                raise ValueError(f"call not running: {call['state'] if call else 'missing'}")
            dlv = conn.execute(
                "SELECT * FROM deliveries WHERE delivery_id=?", (delivery_id,)
            ).fetchone()
            if not dlv or dlv["state"] != "running":
                raise ValueError(f"delivery not running: {dlv['state'] if dlv else 'missing'}")
            pkt = conn.execute(
                "SELECT * FROM context_packets WHERE packet_id=?", (packet_id,)
            ).fetchone()
            if not pkt or pkt["agent"] != agent:
                raise ValueError("context packet agent mismatch")
            if pkt["state"] != "delivered":
                raise ValueError(f"context packet not delivered: {pkt['state']}")
            lease = conn.execute(
                "SELECT * FROM agent_leases WHERE agent=?", (agent,)
            ).fetchone()
            if not lease or lease["call_id"] != call_id:
                raise ValueError("agent lease not held by this call")

            trig = conn.execute(
                "SELECT * FROM events WHERE event_seq=?", (trigger_event_seq,)
            ).fetchone()
            if not trig:
                raise ValueError(f"trigger event not found: {trigger_event_seq}")

            # 稳定回复 event_id
            reply_event_id = f"agent-reply:{call_id}"
            cur = conn.execute(
                "INSERT INTO events(event_id, idempotency_key, trace_id, parent_event_id, root_event_id, "
                "source_agent, source_type, source_id, message_type, text, mentions_json, refs_json, "
                "payload_json, task_id, hop_count, max_hops, created_at, received_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    reply_event_id,
                    reply_event_id,
                    trig["trace_id"],
                    trig["event_id"],
                    trig["root_event_id"],
                    agent,
                    "agent",
                    None,
                    "agent_reply",
                    text,
                    "[]",
                    "{}",
                    None,
                    trig["task_id"],
                    trig["hop_count"],
                    trig["max_hops"],
                    _now(),
                    _now(),
                ),
            )
            reply_seq = cur.lastrowid

            conn.execute(
                "INSERT INTO messages(message_id, event_seq, speaker, text, visible_state, created_at) "
                "VALUES(?,?,?,?,'visible',?)",
                (_uid("msg"), reply_seq, agent, text, _now()),
            )

            conn.execute(
                "UPDATE call_attempts SET state='completed', actual_session_id=?, exit_code=?, "
                "stdout_ref=?, result_ref=?, response_event_seq=?, completed_at=? WHERE call_id=?",
                (actual_session_id, exit_code, stdout_ref, result_ref, reply_seq, _now(), call_id),
            )
            conn.execute(
                "UPDATE deliveries SET state='completed', completed_at=? WHERE delivery_id=?",
                (_now(), delivery_id),
            )

            outbox_payload = for_db({"text": text})
            assert_no_secret(outbox_payload, OUTLET_DB)
            conn.execute(
                "INSERT INTO outbox(outbox_id, event_seq, bot_identity, payload_json, state, attempt_no, "
                "next_attempt_at, created_at) VALUES(?,?,?,?,?,?,?,?)",
                (
                    _uid("obx"),
                    reply_seq,
                    agent,
                    json.dumps(outbox_payload, ensure_ascii=False),
                    "pending",
                    0,
                    None,
                    _now(),
                ),
            )

            # 原子前移 cursor（同连接）
            _commit_context_consumed_conn(
                conn,
                packet_id=packet_id,
                agent=agent,
                through_event_seq=trigger_event_seq,
                reason="agent_reply_persisted",
            )
            conn.execute(
                "DELETE FROM agent_leases WHERE agent=? AND call_id=?", (agent, call_id)
            )
        return {"status": "completed", "reply_event_seq": reply_seq, "agent": agent}
    finally:
        conn.close()


def get_trace_state(trace_id: Optional[str]) -> str:
    """返回 trace 控制状态：active / paused / stopped。

    无记录（未受控）一律视为 active（继续调用）。仅读 trace_controls 表。
    """
    if not trace_id:
        return "active"
    conn = connect(read_only=True)
    try:
        row = conn.execute(
            "SELECT state FROM trace_controls WHERE trace_id=?", (trace_id,)
        ).fetchone()
        return row["state"] if row else "active"
    finally:
        conn.close()


def set_delivery_state(*, delivery_id: str, state: str, reason_code: Optional[str] = None) -> None:
    """直接设置 delivery 状态（用于 trace paused/stopped 等非标状态机出口）。"""
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="set_delivery_state", role="hub"):
            conn.execute(
                "UPDATE deliveries SET state=?, last_error_redacted=? WHERE delivery_id=?",
                (state, reason_code, delivery_id),
            )
    finally:
        conn.close()


def reset_delivery_to_retry(delivery_id: str) -> None:
    """调用前临时失败 / 租约冲突：释放 claim，回到 retry，允许同 call_id 重新领取。

    同 call_id = sha256(event_seq|agent) 确定性生成，重领复用同一 call_attempts 行（幂等）。
    """
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="reset_delivery_to_retry", role="hub"):
            row = conn.execute(
                "SELECT call_id FROM deliveries WHERE delivery_id=?", (delivery_id,)
            ).fetchone()
            old_call_id = row["call_id"] if row else None
            conn.execute(
                "UPDATE deliveries SET state='retry', claimed_by=NULL, claimed_at=NULL, call_id=NULL "
                "WHERE delivery_id=?",
                (delivery_id,),
            )
            if old_call_id:
                conn.execute(
                    "UPDATE call_attempts SET state='retry' WHERE call_id=?", (old_call_id,)
                )
    finally:
        conn.close()


def recover_stuck_calls(
    *,
    now_ts: Optional[float] = None,
) -> Dict[str, int]:
    """崩溃恢复：claimed 但未 running 且 claim 过期 -> retry；running 且 lease 过期 -> result_unknown。

    只有能证明外部调用尚未开始才允许 retry；completed/result_unknown/waiting_summary/blocked 不自动处理。
    """
    now = time.time() if now_ts is None else now_ts
    counts = {"retry": 0, "result_unknown": 0, "unchanged": 0}
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="recover_stuck_calls", role="hub"):
            # claimed 但未 running：若 call_attempts 仍 pending 且 claim 过期（claimed_at 过旧）-> retry
            claimed = conn.execute(
                "SELECT d.delivery_id, d.call_id, d.claimed_at FROM deliveries d "
                "JOIN call_attempts c ON c.call_id=d.call_id "
                "WHERE d.state='claimed' AND c.state='pending'",
            ).fetchall()
            for r in claimed:
                claimed_at = r["claimed_at"]
                try:
                    ct = time.mktime(time.strptime(claimed_at, "%Y-%m-%dT%H:%M:%S")) if claimed_at else 0
                except Exception:
                    ct = 0
                if now - ct > config.CALL_CLAIM_TTL_SEC:
                    old_call_id = r["call_id"]
                    conn.execute(
                        "UPDATE deliveries SET state='retry', claimed_by=NULL, claimed_at=NULL, call_id=NULL "
                        "WHERE delivery_id=?",
                        (r["delivery_id"],),
                    )
                    if old_call_id:
                        conn.execute(
                            "UPDATE call_attempts SET state='retry' WHERE call_id=?",
                            (old_call_id,),
                        )
                    counts["retry"] += 1
                else:
                    counts["unchanged"] += 1

            # running 且 agent lease 过期 -> result_unknown
            running = conn.execute(
                "SELECT d.delivery_id, d.call_id FROM deliveries d "
                "WHERE d.state='running'",
            ).fetchall()
            for r in running:
                lease = conn.execute(
                    "SELECT expires_at FROM agent_leases WHERE call_id=?", (r["call_id"],)
                ).fetchone()
                expired = True
                if lease and lease["expires_at"]:
                    try:
                        et = float(lease["expires_at"])
                    except Exception:
                        et = 0
                    expired = et <= now
                if expired:
                    conn.execute(
                        "UPDATE call_attempts SET state='result_unknown', result_unknown_at=?, error_code='timeout' "
                        "WHERE call_id=?",
                        (_now(), r["call_id"]),
                    )
                    conn.execute(
                        "UPDATE deliveries SET state='result_unknown', last_error_redacted='timeout' "
                        "WHERE delivery_id=?",
                        (r["delivery_id"],),
                    )
                    counts["result_unknown"] += 1
                else:
                    counts["unchanged"] += 1
        return counts
    finally:
        conn.close()
