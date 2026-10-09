"""Opt-in, bounded controller progression for explicit Feishu collaboration tasks.

Agent prose never selects the next recipient. Only verified completed calls and
sent Feishu outbox receipts permit one deterministic transition per poll.
"""
from __future__ import annotations

import sqlite3
import hashlib
import json

import repository as repo
from config import config
from db import connect, transaction
from logging_config import get_logger
from services import task_handoff, task_review

log = get_logger("auto_handoff")

_INSTRUCTIONS = (
    "Review the original task and the first agent's verified result in required source events. "
    "Independently identify mistakes or missing evidence. Do not repeat side effects, "
    "modify files, contact external services, or delegate. Reply with a concise review.",
    "Review the original task plus the first two agents' verified results in required source "
    "events. Identify unresolved issues and give a concise independent verdict. "
    "Do not repeat side effects, modify files, contact external services, or delegate. "
    "Return only two plain-language sentences for the human. Do not quote or mention "
    "internal context headings, bracketed TRIAD labels, session metadata, or provenance tags.",
)


def _attention(task_id: str, revision: int, code: str) -> None:
    # The task remains visible, but no call or transition is retried automatically.
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="auto_handoff_attention", role="hub"):
            task = conn.execute(
                "SELECT trace_id FROM tasks WHERE task_id=? AND revision=? "
                "AND state IN ('active','completed','reviewing')", (task_id, revision),
            ).fetchone()
            if task is None:
                return
            changed = conn.execute(
                "UPDATE tasks SET state='needs_attention',updated_at=? "
                "WHERE task_id=? AND revision=? AND state IN ('active','completed','reviewing')",
                (repo._now(), task_id, revision),
            )
            if changed.rowcount != 1:
                return
            # A single static, redacted status message is visible to the human.
            # It is not a delivery to an agent and cannot trigger another model call.
            event_id = "task-attention:" + hashlib.sha256(task_id.encode()).hexdigest()
            message = "协同任务已暂停，未自动重试。请在看板查看状态。任务编号：" + task_id[-8:]
            event = conn.execute(
                "INSERT INTO events(event_id,idempotency_key,trace_id,root_event_id,"
                "source_agent,source_type,message_type,text,mentions_json,refs_json,task_id,"
                "hop_count,max_hops,created_at,received_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (event_id, event_id, task["trace_id"], event_id, "codex", "controller",
                 "system", message, "[]", "{}", task_id, revision, 4, repo._now(), repo._now()),
            )
            conn.execute(
                "INSERT INTO outbox(outbox_id,event_seq,bot_identity,payload_json,state,"
                "attempt_no,next_attempt_at,created_at) VALUES(?,?,?,?,?,?,?,?)",
                ("obx:" + hashlib.sha256(event_id.encode()).hexdigest(), event.lastrowid,
                 "codex", json.dumps({"text": message}, ensure_ascii=False), "pending", 0,
                 None, repo._now()),
            )
    finally:
        conn.close()
    log.warn("task_needs_attention", status="needs_attention", error_code=code)


def _source_call(conn: sqlite3.Connection, task_id: str, hop: int, agent: str):
    rows = conn.execute(
        "SELECT c.call_id,c.state,c.response_event_seq,c.attempt_no FROM call_attempts c "
        "JOIN events e ON CAST(c.event_seq AS INTEGER)=e.event_seq "
        "WHERE e.task_id=? AND e.hop_count=? AND c.agent=? ORDER BY c.started_at",
        (task_id, hop, agent),
    ).fetchall()
    if len(rows) > 1:
        raise task_handoff.HandoffError("handoff_extra_call_detected")
    return rows[0] if rows else None


def advance_for_agent(agent: str) -> dict:
    """Advance at most one verified stage, or return idle; never invoke a model."""
    if not config.FEISHU_TASKS_ENABLED or agent not in task_handoff.CHAIN:
        return {"status": "disabled"}
    conn = connect(read_only=True)
    try:
        tasks = conn.execute(
            "SELECT task_id,state,revision FROM tasks WHERE owner=? "
            "AND task_id LIKE 'feishu-task:%' AND state IN ('active','completed','reviewing') "
            "ORDER BY updated_at LIMIT 30", (agent,),
        ).fetchall()
        for task in tasks:
            revision = task["revision"]
            state = task["state"]
            chain = task_handoff.chain_for(task["task_id"])
            if revision in (0, 1, 2) and state == "active":
                source_agent, hop = chain[revision], revision
            elif revision == 3 and state == "completed" and agent == chain[2]:
                source_agent, hop = chain[2], 2
            elif revision == 4 and state == "reviewing" and agent == "codex":
                source_agent, hop = "codex", 3
            else:
                continue
            try:
                call = _source_call(conn, task["task_id"], hop, source_agent)
            except task_handoff.HandoffError as exc:
                _attention(task["task_id"], revision, str(exc))
                return {"status": "needs_attention"}
            if call is None:
                continue
            if call["state"] != "completed" or call["attempt_no"] not in (None, 0):
                if call["state"] in ("result_unknown", "blocked", "failed"):
                    _attention(task["task_id"], revision, "handoff_source_unverified")
                    return {"status": "needs_attention"}
                continue
            outbox = conn.execute(
                "SELECT state,attempt_no,external_message_id FROM outbox WHERE event_seq=?",
                (call["response_event_seq"],),
            ).fetchall()
            if len(outbox) != 1 or outbox[0]["attempt_no"] != 0:
                _attention(task["task_id"], revision, "handoff_outbox_conflict")
                return {"status": "needs_attention"}
            if outbox[0]["state"] != "sent" or not outbox[0]["external_message_id"]:
                if outbox[0]["state"] in ("failed", "dead"):
                    _attention(task["task_id"], revision, "handoff_outbox_failed")
                    return {"status": "needs_attention"}
                continue
            task_id, call_id = task["task_id"], call["call_id"]
            break
        else:
            return {"status": "idle"}
    finally:
        conn.close()

    try:
        if revision in (0, 1):
            task_handoff.handoff(
                task_id=task_id, completed_call_id=call_id, expected_revision=revision,
                target=task_handoff.chain_for(task_id)[revision + 1], instruction=_INSTRUCTIONS[revision],
            )
        elif revision == 2:
            task_handoff.finish_task(task_id=task_id, completed_call_id=call_id)
        elif revision == 3:
            task_review.request_review(task_id=task_id, completed_call_id=call_id)
        else:
            task_review.finish_review(task_id=task_id, completed_call_id=call_id)
    except task_handoff.HandoffError as exc:
        _attention(task_id, revision, str(exc))
        return {"status": "needs_attention"}
    return {"status": "advanced", "revision": revision}
