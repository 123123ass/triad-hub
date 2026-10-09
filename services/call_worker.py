"""Call Worker（Step 7）。

run_call_once 固定 10 阶段编排，单一 worker 领取一条 delivery 并原子完成一次 Agent 调用：
 阶段1 Claim        -> repository.claim_next_delivery
 阶段2 Trace 控制    -> repository.get_trace_state（paused/stopped 不调用）
 阶段3 Binding       -> adapter.verify_binding（失败 blocked，禁止 fresh 回落）
 阶段4 Agent Lease   -> repository.acquire_agent_lease（拿不到不调用，退回 retry）
 阶段5 构建上下文     -> context_builder.build_context_packet
                        ContextCompactionRequired -> waiting_summary，释放 lease
 阶段6 渲染 Prompt    -> context_builder.render_agent_prompt（不写库/日志）
 阶段7 标记 Delivered -> mark_context_delivered + mark_call_running（实际调用前）
 阶段8 调用 Adapter   -> adapter.call(...)
 阶段9 成功原子提交    -> repository.commit_agent_reply（单事务 14 步）
 阶段10 失败处理      -> blocked / waiting_summary / retry / result_unknown 分类

安全红线：
- 绝不真实执行三 Agent、绝不新建 Codex 会话、绝不启真实飞书桥（测试中 monkeypatch transport）。
- 游标只在 commit_agent_reply 内（回复+元数据落库后）前移；任何失败分支游标不变。
- prompt 全文 / 私有记忆 / 敏感配置绝不入库。
"""
from __future__ import annotations

import subprocess
import time
from typing import Any, Dict, Optional

import repository as repo
from config import config as cfg
from adapters.base import AdapterResult
from logging_config import get_logger
from context_builder import (
    ContextBuildError,
    ContextCompactionRequired,
    ContextRangeInvalid,
    ProjectMemoryUnavailable,
)


# 明确永久失败：blocked，不 retry、不 result_unknown
_PERMANENT_CODES = (
    "auth_permanent",
    "auth_missing",
    "binding_wrong_logical_session",
    "session_mismatch",
    "no_rollout",
    "command_bypass_detected",
)
# 结果未知：不得自动 retry
_RESULT_UNKNOWN_CODES = ("timeout", "result_unknown", "no_run_id")


def _command_mode_for(agent: str) -> str:
    if agent == 'workbuddy' and cfg.WB_TRANSPORT == 'cli_fixed_session':
        return 'cli_fixed_session'
    return {
        "workbuddy": "gateway_http",
        "hermes": "cli_fixed_session",
        "codex": "cli_exec",
    }.get(agent, "unknown")


def _get_adapter(agent: str, adapter: Optional[Any] = None) -> Any:
    if adapter is not None:
        return adapter
    if agent == "workbuddy":
        if cfg.WB_TRANSPORT == 'cli_fixed_session':
            from adapters.wb_cli import WBCLIAdapter
            return WBCLIAdapter()
        if cfg.WB_TRANSPORT != 'gateway_http':
            raise ValueError('invalid_wb_transport')
        from adapters.wb import WBAdapter

        return WBAdapter()
    if agent == "hermes":
        from adapters.hermes import HermesAdapter

        return HermesAdapter()
    if agent == "codex":
        from adapters.codex import CodexAdapter

        return CodexAdapter()
    raise ValueError(f"unknown agent: {agent}")


def run_call_once(*, agent: str, worker_id: str, adapter: Optional[Any] = None) -> Dict[str, Any]:
    """执行一次调用流程。无任务返回 {"status":"idle"}。"""
    adp = _get_adapter(agent, adapter)

    # 阶段1 Claim
    claimed = repo.claim_next_delivery(agent=agent, worker_id=worker_id)
    if claimed is None:
        return {"status": "idle", "agent": agent}
    delivery = claimed["delivery"]
    call = claimed["call"]
    delivery_id = delivery["delivery_id"]
    call_id = call["call_id"]
    event_seq = delivery["event_seq"]
    trace_id = delivery.get("trace_id")
    task_id = delivery.get("task_id")

    # 阶段2 Trace 控制
    trace_state = repo.get_trace_state(trace_id)
    if trace_state == "stopped":
        repo.mark_call_blocked(
            call_id=call_id, delivery_id=delivery_id, reason_code="trace_stopped"
        )
        return {"status": "blocked", "agent": agent, "call_id": call_id, "reason": "trace_stopped"}
    if trace_state == "paused":
        repo.set_delivery_state(delivery_id=delivery_id, state="paused", reason_code="trace_paused")
        return {"status": "paused", "agent": agent, "call_id": call_id, "reason": "trace_paused"}

    # 阶段3 Binding
    try:
        binding = repo.get_binding(agent)
    except repo.BindingNotFound:
        repo.mark_call_blocked(
            call_id=call_id, delivery_id=delivery_id, reason_code="binding_missing"
        )
        return {"status": "blocked", "agent": agent, "call_id": call_id, "reason": "binding_missing"}
    verification = adp.verify_binding(binding)
    if not verification.ok:
        code = verification.error_code or "binding_offline"
        repo.mark_call_blocked(call_id=call_id, delivery_id=delivery_id, reason_code=code)
        return {"status": "blocked", "agent": agent, "call_id": call_id, "reason": code}

    # 阶段4 Agent Lease
    lease_ok = repo.acquire_agent_lease(
        agent, call_id, worker_id, ttl=cfg.AGENT_LEASE_TTL_SEC
    )
    if not lease_ok:
        # 同 Agent 已有活跃 lease（并发写同一物理会话被阻止）：退回 retry
        repo.reset_delivery_to_retry(delivery_id)
        return {"status": "lease_conflict", "agent": agent, "call_id": call_id}

    # 阶段5 构建上下文
    try:
        packet = repo_build_context(agent, event_seq, task_id)
    except ContextCompactionRequired:
        repo.mark_call_waiting_summary(
            call_id=call_id, delivery_id=delivery_id, reason_code="verified_summary_required"
        )
        repo.release_agent_lease(agent, call_id)
        return {"status": "waiting_summary", "agent": agent, "call_id": call_id}
    except ContextRangeInvalid:
        repo.mark_call_blocked(
            call_id=call_id, delivery_id=delivery_id, reason_code="context_range_invalid"
        )
        repo.release_agent_lease(agent, call_id)
        return {"status": "blocked", "agent": agent, "call_id": call_id, "reason": "context_range_invalid"}
    except ProjectMemoryUnavailable:
        repo.mark_call_blocked(call_id=call_id, delivery_id=delivery_id,
                               reason_code="project_memory_unavailable")
        repo.release_agent_lease(agent, call_id)
        return {"status": "blocked", "agent": agent, "call_id": call_id,
                "reason": "project_memory_unavailable"}

    # 阶段6 渲染 Prompt（不写库/日志）
    trigger_event = repo.get_event(event_seq)
    user_text = trigger_event["text"] if trigger_event else ""
    rendered_prompt = render_prompt(packet, user_text)

    # 阶段7 标记 Delivered（实际外部调用前）
    repo.mark_context_delivered(packet.packet_id)
    lease_expires_at = str(time.time() + cfg.AGENT_LEASE_TTL_SEC)
    repo.mark_call_running(
        call_id=call_id,
        delivery_id=delivery_id,
        worker_id=worker_id,
        context_packet_id=packet.packet_id,
        requested_session_id=binding.get("actual_session_id") or "",
        command_mode=_command_mode_for(agent),
        lease_expires_at=lease_expires_at,
    )

    # 阶段8 调用 Adapter
    timeout = cfg.CALL_TIMEOUT_BY_AGENT.get(agent, cfg.CALL_TIMEOUT_SEC)
    try:
        result = adp.call(
            binding=binding,
            context_packet=packet,
            rendered_prompt=rendered_prompt,
            idempotency_key=call["idempotency_key"],
            timeout=timeout,
        )
    except Exception as exc:  # adapter 内部未捕获异常 -> 结果未知，禁止自动 retry
        # Only a fixed category: no exception message, prompt, output or traceback.
        category = ('unicode_decode_error' if isinstance(exc, UnicodeDecodeError) else
                    'subprocess_timeout' if isinstance(exc, subprocess.TimeoutExpired) else
                    'os_error' if isinstance(exc, OSError) else 'other_exception')
        get_logger('call_worker').error('adapter_exception', agent=agent,
                                      call_id=call_id, error_code=category)
        repo.mark_call_result_unknown(
            call_id=call_id, delivery_id=delivery_id, reason_code="internal_error"
        )
        repo.mark_context_failed(packet.packet_id, failure_code="adapter_exception")
        repo.release_agent_lease(agent, call_id)
        return {"status": "result_unknown", "agent": agent, "call_id": call_id, "reason": "internal_error"}

    # 阶段9 成功原子提交
    if result.success:
        try:
            commit = repo.commit_agent_reply(
                call_id=call_id,
                delivery_id=delivery_id,
                packet_id=packet.packet_id,
                agent=agent,
                trigger_event_seq=event_seq,
                result=result,
            )
            return {
                "status": "completed",
                "agent": agent,
                "call_id": call_id,
                "reply_event_seq": commit.get("reply_event_seq"),
            }
        except Exception:
            # 提交失败：事务内已全回滚，标记结果未知，释放 lease
            repo.mark_call_result_unknown(
                call_id=call_id, delivery_id=delivery_id, reason_code="commit_failed"
            )
            repo.mark_context_failed(packet.packet_id, failure_code="commit_failed")
            repo.release_agent_lease(agent, call_id)
            return {"status": "result_unknown", "agent": agent, "call_id": call_id, "reason": "commit_failed"}

    # 阶段10 失败处理
    code = result.error_code or "internal_error"
    if code in _RESULT_UNKNOWN_CODES:
        repo.mark_call_result_unknown(call_id=call_id, delivery_id=delivery_id, reason_code=code)
        repo.mark_context_failed(packet.packet_id, failure_code=code)
        repo.release_agent_lease(agent, call_id)
        return {"status": "result_unknown", "agent": agent, "call_id": call_id, "reason": code}
    if code in _PERMANENT_CODES:
        repo.mark_call_blocked(call_id=call_id, delivery_id=delivery_id, reason_code=code)
        repo.mark_context_failed(packet.packet_id, failure_code=code)
        repo.release_agent_lease(agent, call_id)
        return {"status": "blocked", "agent": agent, "call_id": call_id, "reason": code}
    # Stage 8 has already entered the adapter. A transport/CLI/quota failure is
    # NOT proof that invocation never happened. This rule applies equally to
    # human mentions and controller tasks; otherwise a resident worker can loop
    # on the same delivery indefinitely. Pre-adapter lease/claim retry stays intact.
    repo.mark_call_result_unknown(call_id=call_id, delivery_id=delivery_id, reason_code=code)
    repo.mark_context_failed(packet.packet_id, failure_code=code)
    repo.release_agent_lease(agent, call_id)
    return {"status": "result_unknown", "agent": agent, "call_id": call_id, "reason": code}


# ---- 延迟导入，避免 services 包循环依赖 ----
def repo_build_context(agent: str, event_seq: int, task_id: Optional[str]):
    import context_builder as cb

    return cb.build_context_packet(agent=agent, trigger_event_seq=event_seq, task_id=task_id)


def render_prompt(packet, user_text: str) -> str:
    import context_builder as cb

    return cb.render_agent_prompt(packet, user_text)


# 崩溃恢复：直接复用 repository 实现
def recover_stuck_calls(*, now_ts: Optional[float] = None) -> Dict[str, int]:
    return repo.recover_stuck_calls(now_ts=now_ts)
