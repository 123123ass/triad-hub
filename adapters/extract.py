"""Gate5-B2 阶段一：统一 Agent 输出提取器 + stdout 证据安全存储（Codex 2026-08-12 裁决 v4）。

核心契约：
- 四出口（result / 数据库 / evidence / 飞书 outbox）只接受"明确的最终回答"；
- **禁止把整段 stdout 直接作为回复**；原始 stdout 只能进受限 evidence 区（owner-only）；
- 移除 ANSI 及不可见控制字符；去除 prompt 回显 / CLI 前缀 / 调试日志 / 工具过程；
- 无法唯一提取 -> agent_result_ambiguous（禁发群）；空正文 -> agent_result_empty；
  包含敏感字段或内部上下文 -> agent_result_secret_detected。

形态分支：
- hermes：CLI 交互输出 -> 回复框内正文；生产模式仅唯一完整回复框成功，
  无框/多框/半截一律 ambiguous（禁黑名单降级）。
- codex / wb：结构化流（JSONL / SSE）已由 adapter 解出 markdown，仅做统一收口。

证据存储（v4，Codex v3 状态机修复）：
- stdout_evidence 表登记：pending -> verified（raw+reviewed 双文件全部发布校验后）
  -> failed / quarantined；
- 幂等状态机：仅 verified + 双文件完整复验（存在/SHA/ACL/reviewed 输出安全）才复用；
  pending 先有界恢复；failed/quarantined 一律失败；同 key 不同内容 idempotency_conflict；
- final 文件名含 idempotency hash（agent_idem8_digest12）——不同 key 同 raw 不路径碰撞；
- raw 原件（evidence/private/raw/stdout/）与 reviewed 脱敏副本（evidence/reviewed/stdout/）
  分离，均走 tmp+ACL+os.link 不可覆盖两阶段发布，双文件完成后才 verified；
- ref 一律规范化为相对 evidence/private/raw 的 POSIX 精确路径（禁子串/basename 匹配）；
- ACL 验证枚举 ACE：只允许 当前用户 / SYSTEM / Administrators / OWNER RIGHTS / CREATOR OWNER；
- stdout_evidence_audit() 纯只读（preflight 调用，发现 pending/不一致阻止启动）；
  recover_stdout_evidence() 显式恢复（改 DB/文件，报告记录修改）。
"""
from __future__ import annotations

import hashlib
import os
import re
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from redaction import contains_secret, redact_text

# ---------------- 稳定错误码（Codex 枚举，固定） ----------------
RESULT_AMBIGUOUS = "agent_result_ambiguous"
RESULT_EMPTY = "agent_result_empty"
RESULT_SECRET = "agent_result_secret_detected"
RESULT_EVIDENCE_FAILED = "agent_result_evidence_failed"
RESULT_IDEMPOTENCY_CONFLICT = "idempotency_conflict"
RESULT_PENDING = "agent_result_evidence_pending"   # v5：普通调用遇 pending 等待超时（不得自动恢复）

# ---------------- ANSI / 控制字符 ----------------
_ANSI_OSC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")   # OSC 序列
_ANSI_CSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")           # CSI 序列
_ANSI_OTHER = re.compile(r"\x1b[()][0-9A-Z]")                   # 字符集选择
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")         # 其余不可见控制符

# ---------------- Hermes CLI 内部上下文标记（prompt 回显特征） ----------------
_TRIAD_TEMPLATE_MARKERS = (
    "Triad Hub 共享上下文模板",
    "[TRIAD_IDENTITY]",
    "[TRIAD_SHARED_SUMMARY]",
    "[TRIAD_DELTA]",
    "[TRIAD_REQUIRED_SOURCES]",
    "[TRIAD_CURRENT_TASK]",
    "[TRIAD_USER_MESSAGE]",
    "[TRIAD_REPLY_CONTRACT]",
    "[TRIAD_",
)
_INTERNAL_CONTEXT_RE = re.compile(
    r"(Triad Hub 共享上下文模板|\[TRIAD_[A-Z_]+\]|event_seq=\d+|logical_session=)", re.IGNORECASE
)

# 回复框边界（hermes chat 输出的最终回答框）
_BOX_TOP_RE = re.compile(r"^\s*╭")
_BOX_BOTTOM_RE = re.compile(r"^\s*╰")


def _public_output_has_secret(text: str) -> bool:
    """Physical bindings are private even when the model volunteers them."""
    import sqlite3
    from config import config
    try:
        with sqlite3.connect(Path(config.DB_PATH).resolve().as_uri() + '?mode=ro', uri=True,
                             timeout=2) as conn:
            values = [sid for agent, sid in conn.execute(
                'SELECT agent,actual_session_id FROM agent_bindings')
                if sid and sid != config.LOGICAL_SESSIONS.get(agent)]
    except sqlite3.Error:
        # Cannot verify the identity boundary: never publish an unchecked answer.
        return True
    return contains_secret(text, extra_secrets=values)


@dataclass
class ExtractResult:
    """统一提取结果。ok=False 时 error_code 为稳定枚举，绝不含原文。"""

    ok: bool
    text: str = ""
    error_code: Optional[str] = None


def strip_ansi(text: str) -> str:
    """移除 ANSI 转义与不可见控制字符，保留正文。"""
    if not text:
        return text
    t = _ANSI_OSC.sub("", text)
    t = _ANSI_CSI.sub("", t)
    t = _ANSI_OTHER.sub("", t)
    return _CTRL.sub("", t)


def _hermes_extract_reply(raw: str) -> ExtractResult:
    """Hermes CLI 输出 -> 回复框内正文（多框/半截/无框 -> ambiguous）。"""
    t = strip_ansi(raw)
    lines = t.splitlines()

    boxes = []
    cur_box: Optional[list] = None
    for ln in lines:
        s = ln.strip()
        if _BOX_TOP_RE.match(ln):
            if cur_box is not None:
                return ExtractResult(ok=False, error_code=RESULT_AMBIGUOUS)
            cur_box = []
            continue
        if _BOX_BOTTOM_RE.match(ln):
            if cur_box is None:
                return ExtractResult(ok=False, error_code=RESULT_AMBIGUOUS)
            boxes.append(cur_box)
            cur_box = None
            continue
        if cur_box is not None:
            cur_box.append(ln)

    if cur_box is not None:
        return ExtractResult(ok=False, error_code=RESULT_AMBIGUOUS)
    if len(boxes) > 1:
        return ExtractResult(ok=False, error_code=RESULT_AMBIGUOUS)
    if not boxes:
        return ExtractResult(ok=False, error_code=RESULT_AMBIGUOUS)
    body = "\n".join(boxes[0]).strip("\n")
    if not body.strip():
        return ExtractResult(ok=False, error_code=RESULT_EMPTY)
    return ExtractResult(ok=True, text=body.strip("\n"))


class AgentResultExtractor:
    """统一提取器：结构化解包 -> 收口（ANSI / secret / 空 / 唯一性）。"""

    def extract(self, agent: str, raw: str) -> ExtractResult:
        """agent: hermes | codex | workbuddy。raw: 原始 stdout 或已解出的候选文本。"""
        if agent == "hermes":
            res = _hermes_extract_reply(raw)
        else:
            res = ExtractResult(ok=True, text=strip_ansi(raw))

        if not res.ok:
            return res

        text = res.text.strip()
        if not text:
            return ExtractResult(ok=False, error_code=RESULT_EMPTY)
        if _INTERNAL_CONTEXT_RE.search(text) or any(m in text for m in _TRIAD_TEMPLATE_MARKERS):
            return ExtractResult(ok=False, error_code=RESULT_SECRET)
        if _public_output_has_secret(text):
            return ExtractResult(ok=False, error_code=RESULT_SECRET)
        return ExtractResult(ok=True, text=text)


# ================= stdout 证据安全存储（v4） =================
def _evidence_root() -> Path:
    """默认部署根固定；仅受控测试轮允许显式隔离，路径非法直接拒绝。"""
    hub = Path(__file__).resolve().parents[1]
    raw = os.environ.get("TRIAD_EVIDENCE_ROOT")
    if not raw:
        return hub / "evidence"
    path = Path(raw)
    if os.environ.get("TRIAD_TEST_MODE") != "true" or not path.is_absolute():
        raise ValueError("stdout_evidence_isolation_invalid")
    if ".." in path.parts or str(path).startswith("\\\\"):
        raise ValueError("stdout_evidence_isolation_invalid")
    for part in (path, *path.parents):
        if part.is_symlink() or (hasattr(part, "is_junction") and part.is_junction()):
            raise ValueError("stdout_evidence_isolation_reparse")
    resolved = path.resolve()
    allowed = (hub / ".gate4_iso", hub / "_sr2_qualify")
    if not any(resolved.is_relative_to(root.resolve()) and resolved != root.resolve()
               for root in allowed):
        raise ValueError("stdout_evidence_isolation_outside_run_roots")
    return resolved


EVIDENCE_ROOT = _evidence_root()
EVIDENCE_STDOUT_DIR = EVIDENCE_ROOT / "private" / "raw" / "stdout"
EVIDENCE_REVIEWED_DIR = EVIDENCE_ROOT / "reviewed" / "stdout"
EVIDENCE_FAILED_DIR = EVIDENCE_ROOT / "private" / "stdout_failed"
_RAW_STDOUT_PREFIX = "stdout/"


def _idempotency_hash(agent: str, idempotency_key: str) -> str:
    """不可逆幂等键：sha256(agent \0 idempotency_key) 前 32 位。"""
    return hashlib.sha256(
        f"{agent}\x00{idempotency_key or ''}".encode("utf-8", errors="replace")
    ).hexdigest()[:32]


def _normalize_raw_ref(raw_ref: str) -> Optional[str]:
    """规范化相对 evidence/private/raw 的 POSIX 精确路径；非法返回 None。

    拒绝：绝对路径、..、重复分隔符、尾斜杠、大小写歧义、越界路径。
    """
    if not raw_ref or not isinstance(raw_ref, str):
        return None
    p = raw_ref.replace("\\", "/")
    if p.startswith("/") or re.match(r"^[A-Za-z]:", p):
        return None
    parts = [part for part in p.split("/") if part]
    if ".." in parts or "." in parts:
        return None
    norm = "/".join(parts)
    if norm != p or not norm:
        return None
    if not norm.startswith(_RAW_STDOUT_PREFIX):
        return None
    return norm


def _raw_ref_abs(norm_ref: str) -> Path:
    """规范化 raw 相对路径 -> 仓库绝对路径（基于 EVIDENCE_STDOUT_DIR，测试可隔离）。"""
    return EVIDENCE_STDOUT_DIR / Path(*norm_ref.split("/")[1:])


def _build_reviewed(agent: str, raw: str, reviewed_text: str = "") -> tuple[str, int]:
    """生成 reviewed 脱敏副本正文 + 脱敏计数。"""
    if reviewed_text:
        body = reviewed_text
    else:
        body = redact_text(strip_ansi(raw))
    body = _INTERNAL_CONTEXT_RE.sub("[REDACTED]", body)
    count = body.count("[REDACTED]")
    return body, count


def _record_paths(rec: dict) -> tuple[Optional[Path], Optional[Path], Optional[str], Optional[str]]:
    """解析记录为 (raw_path, reviewed_path, norm_raw_ref, norm_reviewed_ref)。

    reviewed_ref 语义：相对 EVIDENCE_REVIEWED_DIR（evidence/reviewed/stdout）的 POSIX 路径。
    """
    norm_raw = _normalize_raw_ref(rec.get("raw_ref") or "")
    if norm_raw is None:
        return None, None, None, None
    rref = (rec.get("reviewed_ref") or "").replace("\\", "/")
    if rref.startswith("/") or re.match(r"^[A-Za-z]:", rref):
        return None, None, None, None
    parts = [p for p in rref.split("/") if p]
    if not parts or ".." in parts or "." in parts or rref != "/".join(parts):
        return None, None, None, None
    norm_reviewed = "/".join(parts)
    return (_raw_ref_abs(norm_raw), EVIDENCE_REVIEWED_DIR / Path(*norm_reviewed.split("/")),
            norm_raw, norm_reviewed)


def _record_fully_verified(rec: dict) -> bool:
    """完整复验：raw+reviewed 均存在、SHA 匹配、ACL 均合格、reviewed 输出安全。"""
    raw_p, rev_p, _, _ = _record_paths(rec)
    if raw_p is None or rev_p is None:
        return False
    try:
        if not raw_p.exists() or not rev_p.exists():
            return False
        if hashlib.sha256(raw_p.read_bytes()).hexdigest() != rec.get("raw_sha256"):
            return False
        if hashlib.sha256(rev_p.read_bytes()).hexdigest() != rec.get("reviewed_sha256"):
            return False
        if not _acl_owner_only_verified(raw_p) or not _acl_owner_only_verified(rev_p):
            return False
        rev_txt = rev_p.read_text(encoding="utf-8", errors="replace")
        if "\x1b" in rev_txt:
            return False
        if _INTERNAL_CONTEXT_RE.search(rev_txt) or any(m in rev_txt for m in _TRIAD_TEMPLATE_MARKERS):
            return False
        if _public_output_has_secret(rev_txt):
            return False
        return True
    except Exception:  # noqa: BLE001
        return False


_IDEM_PENDING_WAIT_TRIES = 50   # pending 有界等待（并发同 key 时首个线程发布中）
_IDEM_PENDING_WAIT_SEC = 0.1

# 进程内 idempotency 协调锁（v5，Codex 裁决）：同 key 同 raw 并发调用串行化，
# 全部成功并返回同一 raw_ref；锁用 with 自动释放，异常时绝不泄漏。
_IDEM_LOCKS: dict = {}
_IDEM_LOCKS_GUARD = None  # 惰性初始化（threading）


def _idem_lock(idem: str):
    global _IDEM_LOCKS_GUARD
    import threading
    if _IDEM_LOCKS_GUARD is None:
        _IDEM_LOCKS_GUARD = threading.Lock()
    with _IDEM_LOCKS_GUARD:
        lk = _IDEM_LOCKS.setdefault(idem, threading.Lock())
    return lk


def _idem_reuse(rec: dict, raw_sha: str):
    """幂等命中状态机（Codex v3 P0-1 + v5）：
    - verified + 完整复验 -> 复用；
    - pending -> 有界等待另一个写入者完成；等待后仍 pending -> agent_result_evidence_pending
      （普通调用绝不得自动执行恢复/移动文件/改库）；
    - failed/quarantined -> agent_result_evidence_failed。
    返回 (ref, error_code)。
    """
    from repository import get_stdout_evidence_by_idem
    if rec.get("raw_sha256") != raw_sha:
        return None, RESULT_IDEMPOTENCY_CONFLICT
    if rec.get("status") == "verified":
        if _record_fully_verified(rec):
            return rec["raw_ref"], None
        return None, RESULT_EVIDENCE_FAILED
    if rec.get("status") == "pending":
        # 只等待，不恢复：另一个写入者（同进程持 idem 锁 / 跨进程 os.link 冲突）会
        # 把状态推进到 verified/failed/quarantined；等待超时返回 pending 错误码。
        for _ in range(_IDEM_PENDING_WAIT_TRIES):
            cur = get_stdout_evidence_by_idem(rec["idempotency_hash"])
            if cur is None:
                break
            if cur["status"] == "verified":
                if _record_fully_verified(cur):
                    return cur["raw_ref"], None
                return None, RESULT_EVIDENCE_FAILED
            if cur["status"] in ("failed", "quarantined"):
                return None, RESULT_EVIDENCE_FAILED
            time.sleep(_IDEM_PENDING_WAIT_SEC)
        return None, RESULT_PENDING
    return None, RESULT_EVIDENCE_FAILED  # failed / quarantined


def _recover_single_pending(rec: dict) -> Optional[dict]:
    """单条 pending 有界恢复：raw+reviewed 双文件完整复验通过 -> verified；否则 failed+收容。"""
    from repository import update_stdout_evidence_status
    raw_p, rev_p, _, _ = _record_paths(rec)
    try:
        if _record_fully_verified(rec):
            return update_stdout_evidence_status(rec["evidence_id"], "verified",
                                                 acl_verified=1, note="recovery: verified")
        update_stdout_evidence_status(rec["evidence_id"], "failed", note="recovery: incomplete")
        for p in (raw_p, rev_p):
            if p is not None and p.exists():
                _move_to_failed_area(p)
        return None
    except Exception:  # noqa: BLE001
        return None


def store_raw_stdout(
    agent: str, raw: str, idempotency_key: str = "", reviewed_text: str = "",
) -> tuple[Optional[str], Optional[str]]:
    """两阶段可恢复写入原始 stdout 证据。返回 (raw_ref, error_code)。

    流程：idem 进程锁内（幂等状态机 -> pending 登记 -> raw tmp+ACL -> os.link 不可
    覆盖发布 -> 复验 -> reviewed 两阶段发布 -> 双文件完成才 verified）。任一步失败：
    登记 quarantined + 文件受控迁入失败区，禁止留下无登记文件。
    v5（Codex 裁决）：reviewed_text 必填（不得从 raw 自动推导）；reviewed 进 pending
    前过 ANSI / 内部 prompt / secret 检查；普通调用遇 pending 只等待不恢复。
    """
    if not raw or not reviewed_text:
        return None, RESULT_EVIDENCE_FAILED
    idem = _idempotency_hash(agent, idempotency_key)
    day = time.strftime("%Y%m%d", time.localtime())
    digest = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()[:12]
    raw_sha = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()
    # reviewed 安全检查（进 pending 前）：不得含 ANSI / 内部上下文 / secret
    if "\x1b" in reviewed_text or _INTERNAL_CONTEXT_RE.search(reviewed_text) \
            or any(m in reviewed_text for m in _TRIAD_TEMPLATE_MARKERS) \
            or _public_output_has_secret(reviewed_text):
        return None, RESULT_SECRET
    redaction_count = reviewed_text.count("[REDACTED]")
    reviewed = reviewed_text
    reviewed_sha = hashlib.sha256(reviewed.encode("utf-8", errors="replace")).hexdigest()

    sub = EVIDENCE_STDOUT_DIR / day
    rsub = EVIDENCE_REVIEWED_DIR / day
    try:
        sub.mkdir(parents=True, exist_ok=True)
        rsub.mkdir(parents=True, exist_ok=True)
    except Exception:  # noqa: BLE001
        return None, RESULT_EVIDENCE_FAILED

    # final 文件名含 idempotency hash（agent_idem8_digest12）：同 raw 不同 key 不路径碰撞
    final = sub / f"{agent}_{idem[:8]}_{digest}.stdout.txt"
    rfinal = rsub / f"{agent}_{idem[:8]}_{digest}.reviewed.txt"
    norm_ref = _normalize_raw_ref(f"{_RAW_STDOUT_PREFIX}{day}/{final.name}")
    if norm_ref is None:
        return None, RESULT_EVIDENCE_FAILED

    # 同 key 并发串行化（进程内 idem 锁，with 自动释放，异常不泄漏）
    with _idem_lock(idem):
        return _store_raw_stdout_locked(
            agent=agent, raw=raw, idem=idem, day=day, digest=digest, raw_sha=raw_sha,
            reviewed=reviewed, reviewed_sha=reviewed_sha, redaction_count=redaction_count,
            sub=sub, rsub=rsub, final=final, rfinal=rfinal, norm_ref=norm_ref,
        )


def _store_raw_stdout_locked(
    *, agent: str, raw: str, idem: str, day: str, digest: str, raw_sha: str,
    reviewed: str, reviewed_sha: str, redaction_count: int,
    sub: Path, rsub: Path, final: Path, rfinal: Path, norm_ref: str,
) -> tuple[Optional[str], Optional[str]]:
    """idem 锁内执行：幂等状态机 + 两阶段发布。返回 (raw_ref, error_code)。"""
    try:
        from repository import (get_stdout_evidence_by_idem,
                                insert_stdout_evidence_pending,
                                update_stdout_evidence_status)
        # 0) 幂等状态机（锁内复查：并发第二线程此时看到 verified）
        existing = get_stdout_evidence_by_idem(idem)
        if existing is not None:
            return _idem_reuse(existing, raw_sha)

        # 1) pending 登记（事务内唯一约束兜底跨进程并发）
        pend = insert_stdout_evidence_pending(
            agent=agent, raw_ref=norm_ref,
            reviewed_ref=f"{day}/{rfinal.name}",
            raw_sha256=raw_sha, reviewed_sha256=reviewed_sha,
            idempotency_hash=idem, note="pending: two-phase evidence",
        )
        if pend["status"] == "exists":
            return _idem_reuse(pend["record"], raw_sha)
        if pend["status"] == "conflict":
            return None, RESULT_IDEMPOTENCY_CONFLICT
        evidence_id = pend["record"]["evidence_id"]

        # 2) raw tmp 写入（随机 nonce）+ ACL
        tmp = sub / f".{agent}_{idem[:8]}_{digest}.{uuid.uuid4().hex[:8]}.tmp"
        with open(tmp, "w", encoding="utf-8", newline="", errors="replace") as fh:
            fh.write(raw)
        if not _set_owner_only_checked(tmp) or not _acl_owner_only_verified(tmp):
            _quarantine_failure(evidence_id, tmp, "acl_failed")
            return None, RESULT_EVIDENCE_FAILED

        # 3) raw 不可覆盖发布 + 复验
        try:
            os.link(str(tmp), str(final))
            tmp.unlink(missing_ok=True)
        except FileExistsError:
            tmp.unlink(missing_ok=True)
            again = get_stdout_evidence_by_idem(idem)
            if again is not None:
                return _idem_reuse(again, raw_sha)
            _quarantine_failure(evidence_id, None, "final_exists_no_record")
            return None, RESULT_EVIDENCE_FAILED
        except Exception:  # noqa: BLE001
            _quarantine_failure(evidence_id, tmp, "link_failed")
            return None, RESULT_EVIDENCE_FAILED
        if hashlib.sha256(final.read_bytes()).hexdigest() != raw_sha \
                or not _acl_owner_only_verified(final):
            _quarantine_failure(evidence_id, final, "final_verify_failed")
            return None, RESULT_EVIDENCE_FAILED

        # 4) reviewed 两阶段发布
        rtmp = rsub / f".{agent}_{idem[:8]}_{digest}.{uuid.uuid4().hex[:8]}.tmp"
        with open(rtmp, "w", encoding="utf-8", newline="", errors="replace") as fh:
            fh.write(reviewed)
        if not _set_owner_only_checked(rtmp) or not _acl_owner_only_verified(rtmp):
            _quarantine_failure(evidence_id, rtmp, "reviewed_acl_failed")
            return None, RESULT_EVIDENCE_FAILED
        try:
            os.link(str(rtmp), str(rfinal))
            rtmp.unlink(missing_ok=True)
        except FileExistsError:
            rtmp.unlink(missing_ok=True)
            try:
                if hashlib.sha256(rfinal.read_bytes()).hexdigest() != reviewed_sha:
                    _quarantine_failure(evidence_id, rfinal, "reviewed_verify_failed")
                    return None, RESULT_EVIDENCE_FAILED
            except Exception:  # noqa: BLE001
                _quarantine_failure(evidence_id, rfinal, "reviewed_verify_failed")
                return None, RESULT_EVIDENCE_FAILED
        except Exception:  # noqa: BLE001
            _quarantine_failure(evidence_id, rtmp, "reviewed_link_failed")
            return None, RESULT_EVIDENCE_FAILED
        if not _acl_owner_only_verified(rfinal):
            _quarantine_failure(evidence_id, rfinal, "reviewed_acl_failed")
            return None, RESULT_EVIDENCE_FAILED

        # 5) raw+reviewed 双文件完成 -> 原子更新 verified
        update_stdout_evidence_status(
            evidence_id, "verified", acl_verified=1,
            redaction_count=redaction_count,
            note=f"agent={agent} two_phase_verified",
        )
        return norm_ref, None
    except Exception:  # noqa: BLE001
        return None, RESULT_EVIDENCE_FAILED


def _quarantine_failure(evidence_id: str, path: Optional[Path], reason: str) -> None:
    """失败收容：登记 quarantined + 文件受控迁入 owner-only 失败区（删除失败兜底）。"""
    try:
        from repository import update_stdout_evidence_status
        update_stdout_evidence_status(evidence_id, "quarantined", note=f"reason={reason}")
    except Exception:  # noqa: BLE001
        pass
    if path is not None:
        try:
            path.unlink(missing_ok=True)
        except Exception:  # noqa: BLE001 safe-delete 等可能 fail-closed
            try:
                EVIDENCE_FAILED_DIR.mkdir(parents=True, exist_ok=True)
                os.replace(str(path), str(EVIDENCE_FAILED_DIR / path.name))
            except Exception:  # noqa: BLE001
                pass  # 彻底失败留给显式 recovery 收容


def stdout_evidence_audit() -> dict:
    """纯只读审计（preflight 调用）：发现 pending / verified 不一致即阻止启动。零写入。"""
    issues = []
    try:
        from repository import list_stdout_evidence
        rows = list_stdout_evidence()
    except Exception:  # noqa: BLE001
        return {"ok": False, "issues": ["audit_unavailable"], "counts": {}}
    counts = {"pending": 0, "verified": 0, "failed": 0, "quarantined": 0}
    for rec in rows:
        st = rec.get("status")
        counts[st] = counts.get(st, 0) + 1
        if st == "pending":
            issues.append(f"pending:{rec.get('evidence_id', '?')[:12]}")
        elif st == "verified" and not _record_fully_verified(rec):
            issues.append(f"inconsistent:{rec.get('evidence_id', '?')[:12]}")
    return {"ok": not issues, "issues": issues, "counts": counts}


def recover_stdout_evidence() -> dict:
    """显式恢复（改 DB/文件）：处理 pending 记录与孤立 tmp；报告记录修改。"""
    stats = {"pending_recovered": 0, "pending_failed": 0,
             "orphan_tmp_moved": 0, "failed_area_moved": 0}
    try:
        from repository import list_stdout_evidence
        for rec in list_stdout_evidence(status="pending"):
            if _recover_single_pending(rec) is not None:
                stats["pending_recovered"] += 1
            else:
                stats["pending_failed"] += 1

        for day_dir in EVIDENCE_STDOUT_DIR.glob("*"):
            if day_dir.is_dir():
                for tmp in day_dir.glob("*.tmp"):
                    if _move_to_failed_area(tmp):
                        stats["orphan_tmp_moved"] += 1
        for day_dir in EVIDENCE_REVIEWED_DIR.glob("*"):
            if day_dir.is_dir():
                for tmp in day_dir.glob("*.tmp"):
                    if _move_to_failed_area(tmp):
                        stats["orphan_tmp_moved"] += 1
    except Exception:  # noqa: BLE001
        pass
    return stats


def _move_to_failed_area(path: Path) -> bool:
    """受控迁入失败区（owner-only）；失败返回 False。"""
    try:
        EVIDENCE_FAILED_DIR.mkdir(parents=True, exist_ok=True)
        dst = EVIDENCE_FAILED_DIR / f"{time.strftime('%Y%m%d%H%M%S')}_{path.name}"
        os.replace(str(path), str(dst))
        _set_owner_only_checked(dst)
        return True
    except Exception:  # noqa: BLE001
        return False


def _set_owner_only_checked(path: Path) -> bool:
    """owner-only 设置并检查命令返回码；失败返回 False。"""
    try:
        if os.name == "nt":
            import subprocess as _sp

            r = _sp.run(
                ["icacls", str(path), "/inheritance:r", "/grant:r",
                 f"{os.environ.get('USERNAME', '')}:F"],
                capture_output=True, timeout=60, shell=False,
            )
            return r.returncode == 0
        os.chmod(path, 0o600)
        return True
    except Exception:  # noqa: BLE001
        return False


_ACE_ALLOWED_STATIC = ("nt authority\\system", "builtin\\administrators",
                       "owner rights", "creator owner")
_ACE_BANNED = ("everyone", "\\users", "authenticated users")


def _acl_owner_only_verified(path: Path) -> bool:
    """ACL 读回验证：枚举全部 ACE 主体，只允许 当前用户/SYSTEM/Administrators/
    OWNER RIGHTS/CREATOR OWNER；未知主体或普通用户组即拒绝。"""
    try:
        if os.name == "nt":
            import subprocess as _sp

            r = _sp.run(["icacls", str(path)], capture_output=True, timeout=60, shell=False)
            if r.returncode != 0:
                return False
            raw = r.stdout
            try:
                out = raw.decode("utf-8")
            except UnicodeDecodeError:
                out = raw.decode("gbk", errors="replace")
            user = (os.environ.get("USERNAME") or "").lower()
            if not user:
                return False
            low = out.lower()
            if "(i)" in low or "inherited" in low:
                return False
            # 枚举 ACE 主体。icacls 的首行格式为
            # ``D:\path\file OWNER:(F)``；不能用 split(":", 1)，否则会把盘符
            # ``D:`` 误识别为主体并令所有 Windows 绝对路径复验失败。
            # 先精确剥离本次查询路径，再从最后一个 ``:`` 拆出 ACE。
            subjects = set()
            for ln in out.splitlines():
                s = ln.strip()
                if not s or ":" not in s:
                    continue
                path_text = str(path)
                if s.lower().startswith(path_text.lower()):
                    s = s[len(path_text):].strip()
                if ":" not in s:
                    continue
                subject, rights = s.rsplit(":", 1)
                subject = subject.strip().lower()
                if not subject or not rights.lstrip().startswith("("):
                    continue
                subjects.add(subject)
            if not subjects:
                return False
            for subj in subjects:
                if subj in _ACE_ALLOWED_STATIC:
                    continue
                if subj == user or subj.split("\\")[-1] == user:
                    continue
                return False
            for banned in _ACE_BANNED:
                if banned + ":" in low:
                    return False
            return True
        import stat as _stat
        return (_stat.S_IMODE(path.stat().st_mode) & 0o077) == 0
    except Exception:  # noqa: BLE001
        return False


def _set_owner_only(path: Path) -> None:
    """兼容旧接口（owner-only 尽力而为）；新代码应使用 _set_owner_only_checked。"""
    _set_owner_only_checked(path)
