"""Triad Hub 共享摘要服务（Step 6）。

本模块只实现候选接收、结构验证、证据校验、状态流转。
本步骤不实际调用 Hermes：Hermes 未来通过 adapter 提交 candidate，Hub 在此验证后转 verified。

铁律：
- proposed_by 必须为 hermes；candidate 不能自封 verified。
- source_digest 由 Hub 根据输入事件计算，Hermes 必须原样返回；不一致即拒。
- 每条事实至少一个证据，且证据必须存在并位于摘要范围内。
- reject 只写稳定错误码，绝不写 Hermes 原始错误全文。
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, List, Optional

from db import connect, transaction
from redaction import OUTLET_DB, assert_no_secret, contains_secret, for_db
from repository import _now, _uid
from schemas import SharedSummaryCandidateV1

# 稳定错误码（与 config.SUMMARY_REJECTION_CODES 对齐；此处用于校验入参）
STABLE_ERROR_CODES = {
    "digest_mismatch",
    "evidence_missing",
    "evidence_out_of_range",
    "secret_detected",
    "range_invalid",
    "duplicate_verified_range",
}


def compute_source_digest(events: List[Dict[str, Any]]) -> str:
    """按规范化字段计算原始事件摘要。用于核对 Hermes 返回的 source_digest。"""
    normalized = []
    for e in events:
        normalized.append(
            {
                "event_seq": e.get("event_seq"),
                "event_id": e.get("event_id"),
                "source_agent": e.get("source_agent"),
                "message_type": e.get("message_type"),
                "text": e.get("text"),
            }
        )
    blob = json.dumps(
        normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _fetch_range_events(conn, from_seq: int, to_seq: int) -> List[Dict[str, Any]]:
    rows = conn.execute(
        "SELECT event_seq, event_id, source_agent, message_type, text "
        "FROM events WHERE event_seq >= ? AND event_seq <= ? ORDER BY event_seq",
        (from_seq, to_seq),
    ).fetchall()
    return [dict(r) for r in rows]


def propose_summary(candidate: Any) -> str:
    """接收 Hermes 提交的候选摘要。返回 summary_id；失败抛 ValueError（稳定原因）。

    candidate: SharedSummaryCandidateV1 或可被其解析的 dict。
    """
    if isinstance(candidate, dict):
        candidate = SharedSummaryCandidateV1(**candidate)
    if candidate.proposed_by != "hermes":
        raise ValueError("proposed_by must be hermes")

    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="propose_summary", role="summary"):
            frm, to = candidate.from_event_seq, candidate.to_event_seq
            if to < frm:
                raise ValueError("range_invalid")

            evs = _fetch_range_events(conn, frm, to)
            if not evs:
                raise ValueError("evidence_missing")
            ev_seqs = {r["event_seq"] for r in evs}

            # 事实与证据校验
            for f in candidate.facts:
                if not f.evidence_event_seqs:
                    raise ValueError("evidence_missing")
                for e in f.evidence_event_seqs:
                    if e < frm or e > to:
                        raise ValueError("evidence_out_of_range")
                    if e not in ev_seqs:
                        raise ValueError("evidence_missing")

            # digest 一致性
            computed = compute_source_digest(evs)
            if computed != candidate.source_digest:
                raise ValueError("digest_mismatch")

            # 秘密扫描
            text_blob = candidate.summary_text + " " + " ".join(
                f.text for f in candidate.facts
            )
            if contains_secret(text_blob):
                raise ValueError("secret_detected")

            # 不允许相同区间已存在 verified
            dup = conn.execute(
                "SELECT 1 FROM shared_summaries WHERE from_event_seq=? AND to_event_seq=? AND status='verified'",
                (frm, to),
            ).fetchone()
            if dup:
                raise ValueError("duplicate_verified_range")

            summary_id = candidate.summary_id
            facts_json = for_db([f.model_dump() for f in candidate.facts])
            assert_no_secret(facts_json, OUTLET_DB)
            conn.execute(
                "INSERT INTO shared_summaries("
                "summary_id, from_event_seq, to_event_seq, summary_text, status, proposed_by, "
                "created_at, facts_json, source_digest) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    summary_id,
                    frm,
                    to,
                    candidate.summary_text,
                    "candidate",
                    candidate.proposed_by,
                    _now(),
                    json.dumps(facts_json, ensure_ascii=False),
                    candidate.source_digest,
                ),
            )
            for f in candidate.facts:
                for e in f.evidence_event_seqs:
                    conn.execute(
                        "INSERT OR IGNORE INTO summary_evidence(summary_id, event_seq) VALUES(?,?)",
                        (summary_id, e),
                    )
            return summary_id
    except Exception as exc:  # 含 UNIQUE(from,to) 冲突
        if "UNIQUE" in str(exc):
            raise ValueError("duplicate_verified_range") from exc
        raise
    finally:
        conn.close()


def verify_summary_candidate(summary_id: str, verified_by: str = "hub") -> Dict[str, Any]:
    """结构验收通过后转 verified。返回脱敏摘要元数据（不含完整原始事件）。"""
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="verify_summary_candidate", role="summary"):
            row = conn.execute(
                "SELECT * FROM shared_summaries WHERE summary_id=?", (summary_id,)
            ).fetchone()
            if not row:
                raise ValueError("candidate not found")
            if row["status"] != "candidate":
                raise ValueError(f"not a candidate: {row['status']}")

            frm, to = row["from_event_seq"], row["to_event_seq"]
            evs = _fetch_range_events(conn, frm, to)
            if not evs:
                raise ValueError("evidence_missing")
            computed = compute_source_digest(evs)
            if computed != row["source_digest"]:
                raise ValueError("digest_mismatch")

            facts = json.loads(row["facts_json"]) if row["facts_json"] else []
            ev_seqs = {r["event_seq"] for r in evs}
            for f in facts:
                for e in f.get("evidence_event_seqs", []):
                    if e < frm or e > to:
                        raise ValueError("evidence_out_of_range")
                    if e not in ev_seqs:
                        raise ValueError("evidence_missing")

            text_blob = (row["summary_text"] or "") + " " + " ".join(
                f.get("text", "") for f in facts
            )
            if contains_secret(text_blob):
                raise ValueError("secret_detected")

            dup = conn.execute(
                "SELECT 1 FROM shared_summaries WHERE from_event_seq=? AND to_event_seq=? "
                "AND status='verified' AND summary_id<>?",
                (frm, to, summary_id),
            ).fetchone()
            if dup:
                raise ValueError("duplicate_verified_range")

            conn.execute(
                "UPDATE shared_summaries SET status='verified', verified_by=?, verified_at=? WHERE summary_id=?",
                (verified_by, _now(), summary_id),
            )
            return {
                "summary_id": summary_id,
                "from_event_seq": frm,
                "to_event_seq": to,
                "status": "verified",
                "verified_by": verified_by,
                "evidence_event_seqs": sorted(ev_seqs),
            }
    finally:
        conn.close()


def reject_summary_candidate(
    summary_id: str, reason_code: str, verified_by: str = "hub"
) -> None:
    """candidate -> rejected。rejection_reason_redacted 只写稳定错误码。"""
    if reason_code not in STABLE_ERROR_CODES:
        raise ValueError(f"invalid reason_code: {reason_code}")
    conn = connect()
    try:
        with transaction(conn, immediate=True, operation="reject_summary_candidate", role="summary"):
            row = conn.execute(
                "SELECT status FROM shared_summaries WHERE summary_id=?", (summary_id,)
            ).fetchone()
            if not row or row["status"] != "candidate":
                raise ValueError("not a candidate")
            conn.execute(
                "UPDATE shared_summaries SET status='rejected', rejection_reason_redacted=?, verified_by=? "
                "WHERE summary_id=?",
                (reason_code, verified_by, summary_id),
            )
    finally:
        conn.close()


def get_verified_summary_for_context(up_to_event_seq: int) -> Optional[Dict[str, Any]]:
    """仅供上下文注入使用：只返回 verified 摘要（按 to_event_seq 倒序第一条）。"""
    conn = connect(read_only=True)
    try:
        row = conn.execute(
            "SELECT summary_id, from_event_seq, to_event_seq, summary_text, source_digest "
            "FROM shared_summaries WHERE status='verified' AND to_event_seq <= ? "
            "ORDER BY to_event_seq DESC LIMIT 1",
            (up_to_event_seq,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()
