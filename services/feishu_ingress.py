"""services/feishu_ingress.py —— 飞书入站归一化与原子入库。

职责：
- 校验入站 schema、固定群、发送者身份。
- 归一化为 EnvelopeV1。
- 在同一 BEGIN IMMEDIATE 事务内完成查重 -> 分配 event_seq -> 写 events/messages/deliveries。
- 不创建飞书 outbox；不调用任何 Agent；不发送飞书消息。
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
from typing import Any, Dict, List, Optional, Set

import repository
import security
from adapters.feishu import extract_clean_text
from config import config
from db import connect, transaction
from redaction import OUTLET_DB, assert_no_secret, for_db
from schemas import EnvelopeV1, FeishuIngressV1

BOT_IDENTITIES = ("workbuddy", "codex", "hermes")
TARGET_ORDER = ("workbuddy", "codex", "hermes")
EVENT_TYPE_MESSAGE_RECEIVED = "im.message.message_received_v1"
DEDUP_TTL_SEC = 120
TASK_PREFIXES = ("协同：", "协同:")

ERR_SCHEMA_INVALID = "schema_invalid"
ERR_CHAT_DENIED = "chat_denied"
ERR_SENDER_DENIED = "sender_denied"
ERR_ADMIN_DENIED = "admin_denied"
ERR_TRACE_ID_REQUIRED = "trace_id_required"
ERR_DB_BUSY = "db_busy"


class IngressRejected(Exception):
    """只带稳定错误码，不带任何原始内容。"""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


# ---------------- 5.6.1 标准化入站 ----------------
def normalize_ingress(
    payload: Dict[str, Any],
) -> FeishuIngressV1:
    try:
        ingress = FeishuIngressV1(**payload)
    except Exception as exc:  # noqa: BLE001 —— 不回显 pydantic 原文
        raise IngressRejected(ERR_SCHEMA_INVALID) from exc

    if ingress.bot_identity not in BOT_IDENTITIES:
        raise IngressRejected(ERR_SCHEMA_INVALID)

    raw = ingress.raw_event or {}
    if raw.get("event_type") != EVENT_TYPE_MESSAGE_RECEIVED:
        raise IngressRejected(ERR_SCHEMA_INVALID)
    if not raw.get("event_id"):
        raise IngressRejected(ERR_SCHEMA_INVALID)
    if not raw.get("chat_id"):
        raise IngressRejected(ERR_SCHEMA_INVALID)
    if not raw.get("sender_open_id"):
        raise IngressRejected(ERR_SCHEMA_INVALID)
    if raw.get("receiving_bot") != ingress.bot_identity:
        raise IngressRejected(ERR_SCHEMA_INVALID)
    if not security.is_allowed_chat(raw.get("chat_id")):
        raise IngressRejected(ERR_CHAT_DENIED)
    return ingress


# ---------------- 5.6.2 识别发送者 ----------------
def identify_sender(
    sender_open_id: str,
    sender_union_id: str = "",
) -> str:
    """识别发送者身份。fail-closed：FEISHU_OPERATOR_UNION_ID 配置后只认 union_id 精确匹配，
    union 缺失/错误一律 sender_denied（禁止降级旧 open_id）；USER_ID 仅在
    union 未配置时过渡使用。Bot 身份始终按 open_id 白名单匹配。
    """
    union_id = config.FEISHU_OPERATOR_UNION_ID
    if union_id:
        if sender_union_id and sender_union_id == union_id:
            return "operator"
        for agent, open_id in config.bot_open_ids().items():
            if open_id and sender_open_id == open_id:
                return agent
        raise IngressRejected(ERR_SENDER_DENIED)
    # 过渡兼容（union 未配置）：旧 open_id 路径
    if config.FEISHU_OPERATOR_USER_ID and sender_open_id == config.FEISHU_OPERATOR_USER_ID:
        return "operator"
    for agent, open_id in config.bot_open_ids().items():
        if open_id and sender_open_id == open_id:
            return agent
    raise IngressRejected(ERR_SENDER_DENIED)


# ---------------- 5.6.3 识别 mentions ----------------
def mention_open_ids(
    mentions: List[Dict[str, Any]],
) -> Set[str]:
    out: Set[str] = set()
    for m in mentions or []:
        if not isinstance(m, dict):
            continue
        open_id = m.get("open_id")
        if open_id:
            out.add(str(open_id))
    return out


def is_at_all(
    clean_text_source: str,
    mentions: List[Dict[str, Any]],
) -> bool:
    if "@_all" in (clean_text_source or ""):
        return True
    for m in mentions or []:
        if not isinstance(m, dict):
            continue
        if str(m.get("key") or "") == "@_all":
            return True
        if str(m.get("open_id") or "") == "all":
            return True
    return False


# ---------------- 5.6.4 解析目标 ----------------
def resolve_targets(
    sender_agent: str,
    mentions: List[Dict[str, Any]],
    at_all: bool,
) -> List[str]:
    if sender_agent != "operator":
        # Agent 发言只进共同事实源并广播，不自动调用其他 Agent
        return []
    if at_all:
        return ["workbuddy", "codex", "hermes"]
    mentioned = mention_open_ids(mentions)
    open_ids = config.bot_open_ids()
    return [a for a in TARGET_ORDER if open_ids.get(a) and open_ids[a] in mentioned]


# ---------------- 5.6.5 内容签名 ----------------
def build_content_signature(
    chat_id: str,
    sender_agent: str,
    message_id: Optional[str],
    clean_text: str,
) -> str:
    """内容签名。发送者维度使用规范 sender_agent（如 'operator'），
    不用应用隔离的 sender_open_id，保证三桥同消息签名一致。
    """
    canonical = "|".join([
        chat_id,
        sender_agent,
        message_id or "",
        clean_text,
    ])
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _chat_id_ref(chat_id: str) -> str:
    return "sha256:" + hashlib.sha256(chat_id.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())


def _collaboration_objective(envelope: EnvelopeV1) -> Optional[str]:
    """Only an authenticated human's explicit single-agent request starts a chain."""
    if not config.FEISHU_TASKS_ENABLED or envelope.source_agent != "operator":
        return None
    # Visible text is never sufficient: the exact Feishu mention metadata must agree.
    labels = {'codex': 'Codex', 'hermes': 'Hermes', 'workbuddy': 'WB'}
    text = envelope.text
    visible = re.match(r'^@(Codex|Hermes|WB|WorkBuddy)\s+', text, re.IGNORECASE)
    if visible:
        visible_target = visible.group(1).lower()
        visible_target = 'workbuddy' if visible_target in ('wb', 'workbuddy') else visible_target
        if envelope.target_agents != [visible_target]:
            raise IngressRejected('task_target_invalid')
        text = text[visible.end():]
    for prefix in TASK_PREFIXES:
        if text.startswith(prefix):
            if len(envelope.target_agents) != 1 or envelope.target_agents[0] not in labels:
                raise IngressRejected("task_target_invalid")
            objective = text[len(prefix):].strip()
            if not 1 <= len(objective) <= 4000:
                raise IngressRejected("task_contract_invalid")
            return objective
    return None


# ---------------- 5.6.6 构建 Envelope ----------------
def build_envelope(
    ingress: FeishuIngressV1,
) -> EnvelopeV1:
    raw = ingress.raw_event
    event_id = str(raw["event_id"])
    chat_id = str(raw["chat_id"])
    sender_open_id = str(raw["sender_open_id"])
    sender_union_id = str(raw.get("sender_union_id") or "")
    message_id = raw.get("message_id")
    mentions = raw.get("mentions") or []
    content = str(raw.get("content") or "")

    sender_agent = identify_sender(sender_open_id, sender_union_id)
    clean_text = extract_clean_text(content)
    at_all = is_at_all(content, mentions)
    targets = resolve_targets(sender_agent, mentions, at_all)

    # 操作员规范身份：union_id（全局唯一、跨应用稳定）；仅 union 未配置时过渡用 open_id
    canonical_sender_id = (
        sender_union_id
        if (sender_agent == "operator" and sender_union_id)
        else sender_open_id
    )

    if sender_agent == "operator":
        message_type = (
            "management" if security.parse_admin_command(clean_text) else "chat"
        )
    else:
        message_type = "agent_reply"

    return EnvelopeV1(
        schema_version="1.0",
        event_id=event_id,
        event_seq=None,
        idempotency_key="feishu:" + event_id,
        content_signature=build_content_signature(
            chat_id, sender_agent, message_id, clean_text
        ),
        trace_id="feishu:" + str(message_id or event_id),
        parent_event_id=None,
        root_event_id=event_id,
        task_id=None,
        source_type="human" if sender_agent == "operator" else "agent",
        source_id=canonical_sender_id,
        source_agent=sender_agent,
        target_agents=targets,
        message_type=message_type,
        text=clean_text,
        mentions=sorted(mention_open_ids(mentions)),
        refs={
            "provider": "feishu",
            "chat_id_ref": _chat_id_ref(chat_id),
            "message_id": message_id,
            "event_id_source": raw.get("event_id_source"),
            "receiving_bot": raw.get("receiving_bot"),
        },
        hop_count=0,
        max_hops=2,
        auto_reply_count=0,
        created_at=str(raw.get("message_create_time") or raw.get("event_create_time") or ""),
        received_at=ingress.received_at or _now(),
    )


# ---------------- 5.6.7 管理命令 ----------------
def process_admin_command(
    envelope: EnvelopeV1,
) -> Optional[Dict[str, Any]]:
    cmd = security.parse_admin_command(envelope.text)
    if cmd is None:
        return None
    if envelope.source_agent != "operator":
        # Agent 消息中的管理命令仍作为普通 agent_reply 落库，不调 set_trace_control
        return None
    if security.authorize_admin_command(
        envelope.text, envelope.source_agent, envelope.source_id, envelope.source_id
    ) != security.OK:
        return {"status": "rejected", "error_code": ERR_ADMIN_DENIED}

    parts = (envelope.text or "").strip().split()
    trace_id = parts[1] if len(parts) > 1 else ""
    if not trace_id:
        return {
            "status": "rejected",
            "error_code": ERR_TRACE_ID_REQUIRED,
        }
    state = {"/pause": "paused", "/stop": "stopped", "/resume": "active"}[cmd]
    repository.set_trace_control(
        trace_id=trace_id,
        state=state,
        changed_by="operator",
    )
    return {
        "status": "accepted",
        "trace_id": trace_id,
        "control_state": state,
    }


def _trace_paused(conn, trace_id: str) -> bool:
    row = conn.execute(
        "SELECT state FROM trace_controls WHERE trace_id=?", (trace_id,)
    ).fetchone()
    return bool(row) and row["state"] in ("paused", "stopped")


# ---------------- 5.6.8 原子入站 ----------------
def ingest_feishu_event(
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    try:
        ingress = normalize_ingress(payload)
        envelope = build_envelope(ingress)
        objective = _collaboration_objective(envelope)
    except IngressRejected as e:
        return {
            "status": "rejected",
            "event_seq": None,
            "duplicate": False,
            "targets": [],
            "error_code": e.code,
        }

    admin = process_admin_command(envelope)
    if admin is not None and admin.get("status") == "rejected":
        return {
            "status": "rejected",
            "event_seq": None,
            "duplicate": False,
            "targets": [],
            "error_code": admin.get("error_code"),
        }

    text = for_db(envelope.text)
    assert_no_secret(text, outlet=OUTLET_DB)
    task_objective = for_db(objective) if objective is not None else None
    if task_objective is not None:
        assert_no_secret(task_objective, outlet=OUTLET_DB)
    first_agent = envelope.target_agents[0] if task_objective is not None else None
    task_id = (("feishu-task:" if first_agent == 'codex' else f"feishu-task:{first_agent}:") +
               hashlib.sha256(envelope.event_id.encode()).hexdigest()
               if task_objective is not None else None)
    mentions_json = json.dumps(envelope.mentions, ensure_ascii=False)
    refs_json = json.dumps(for_db(envelope.refs), ensure_ascii=False)
    assert_no_secret(refs_json, outlet=OUTLET_DB)

    try:
        # 入站写事务短超时（Gate5-B2-WB：≤2000ms，锁存在时快速失败，不拖死 Hub）
        conn = connect(busy_timeout_ms=2000)
        try:
            with transaction(conn, immediate=True, operation="ingest_feishu_event", role="hub"):
                row = conn.execute(
                    "SELECT event_seq FROM events WHERE event_id=?", (envelope.event_id,)
                ).fetchone()
                if row:
                    return {
                        "status": "duplicate",
                        "event_seq": row["event_seq"],
                        "duplicate": True,
                        "targets": [],
                    }
                row = conn.execute(
                    """
                    SELECT e.event_seq
                    FROM event_dedup d
                    JOIN events e ON e.event_id=d.first_event_id
                    WHERE d.signature=?
                      AND CAST(d.expires_at AS REAL)>?
                    """,
                    (envelope.content_signature, time.time()),
                ).fetchone()
                if row:
                    return {
                        "status": "duplicate",
                        "event_seq": row["event_seq"],
                        "duplicate": True,
                        "targets": [],
                    }
                if _trace_paused(conn, envelope.trace_id):
                    return {
                        "status": "paused",
                        "event_seq": None,
                        "duplicate": False,
                        "targets": [],
                        "error_code": "paused",
                    }

                cur = conn.execute(
                    """INSERT INTO events(event_id, idempotency_key, trace_id, parent_event_id, root_event_id,
                       source_agent, source_type, source_id, message_type, text, mentions_json, refs_json,
                       payload_json, hop_count, max_hops, created_at, received_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        envelope.event_id,
                        envelope.idempotency_key,
                        envelope.trace_id,
                        envelope.parent_event_id,
                        envelope.root_event_id,
                        envelope.source_agent,
                        envelope.source_type,
                        envelope.source_id,
                        envelope.message_type,
                        text,
                        mentions_json,
                        refs_json,
                        None,
                        envelope.hop_count,
                        envelope.max_hops,
                        envelope.created_at,
                        envelope.received_at,
                    ),
                )
                event_seq = cur.lastrowid
                conn.execute(
                    "INSERT OR REPLACE INTO event_dedup(signature, first_event_id, expires_at) VALUES(?,?,?)",
                    (
                        envelope.content_signature,
                        envelope.event_id,
                        str(time.time() + DEDUP_TTL_SEC),
                    ),
                )
                feishu_message_id = (envelope.refs or {}).get("message_id")
                if task_id is not None:
                    conn.execute(
                        "INSERT INTO tasks(task_id,owner,objective,acceptance_criteria,trace_id,state,"
                        "evidence_refs_json,revision,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (task_id, first_agent, task_objective,
                         "The mentioned agent performs the requested task; the other two agents review verified results; "
                         "Codex gives the final evidence-bounded verdict.",
                         envelope.trace_id, "active", "[]", 0, _now(), _now()),
                    )
                    conn.execute("UPDATE events SET task_id=? WHERE event_seq=?", (task_id, event_seq))
                conn.execute(
                    "INSERT INTO messages(message_id, event_seq, speaker, text, feishu_message_id, visible_state, created_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (
                        str(feishu_message_id) if feishu_message_id else "msg_" + envelope.event_id,
                        event_seq,
                        envelope.source_agent,
                        text,
                        str(feishu_message_id) if feishu_message_id else None,
                        "visible",
                        envelope.created_at,
                    ),
                )
                # 只建 Agent 投递，绝不在入站创建飞书 outbox
                repository._create_deliveries(conn, event_seq, envelope.target_agents)
                if task_id is not None:
                    conn.execute("UPDATE deliveries SET task_id=?,trace_id=? WHERE event_seq=?",
                                 (task_id, envelope.trace_id, event_seq))
            return {
                "status": "accepted",
                "event_seq": event_seq,
                "duplicate": False,
                "targets": list(envelope.target_agents),
                "task_id": task_id,
            }
        finally:
            conn.close()
    except sqlite3.OperationalError:
        return {
            "status": "rejected",
            "event_seq": None,
            "duplicate": False,
            "targets": [],
            "error_code": ERR_DB_BUSY,
        }
