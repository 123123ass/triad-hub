"""Hermes adapter（Step 7：继承 AgentAdapter）。

安全红线：
- 使用固定 binding session（binding.actual_session_id）；绝不创建 fresh session。
- argv 独立传递，shell=False。
- 失败只回稳定错误码 + stderr 脱敏摘要。
- preverified 一律取 agent_bindings 权威值，禁止由"未回显 session"推断升级。
- 测试通过 monkeypatch HermesAdapter._run 避免真实执行。
"""
from __future__ import annotations

import json
import os
import subprocess
from typing import Any, Dict

from config import config
from redaction import safe_error, summarize_stderr

from .base import (AdapterResult, AgentAdapter, BindingVerification,
                   parse_preverified, precheck_binding, resolve_binding_preverified)
from .extract import AgentResultExtractor, ExtractResult, store_raw_stdout


def extract_stream_result(raw: str, expected_session: str) -> ExtractResult:
    """Only the unique terminal result is an answer; never text/tool deltas."""
    fail = ExtractResult(ok=False, error_code='agent_result_ambiguous')
    try:
        records = [json.loads(line) for line in raw.splitlines() if line.strip()]
    except (ValueError, TypeError):
        return fail
    if (len(records) < 2 or not all(isinstance(r, dict) for r in records) or
            not expected_session or records[0].get('type') != 'system' or
            records[0].get('subtype') != 'init' or records[-1].get('type') != 'result'):
        return fail
    if (sum(r.get('type') == 'result' for r in records) != 1 or
            sum(r.get('type') == 'system' for r in records) != 1 or
            any(r.get('type') not in ('text', 'tool_use', 'tool_result') for r in records[1:-1])):
        return fail
    final = records[-1]
    if records[0].get('session_id') != expected_session or final.get('session_id') != expected_session:
        return ExtractResult(ok=False, error_code='agent_session_mismatch')
    if (type(final.get('exit_code')) is not int or final['exit_code'] != 0 or
            final.get('error') or not isinstance(final.get('text'), str)):
        return fail
    # Shared final-text safety checks. This is a protocol field, not stdout fallback.
    return AgentResultExtractor().extract('workbuddy', final['text'])


def stream_shape(raw: str, expected_session: str) -> str:
    """Fixed, payload-free protocol shape for a failed extraction."""
    types = []
    sessions_match = True
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except (ValueError, TypeError):
            types.append('invalid')
            continue
        if not isinstance(item, dict):
            types.append('invalid')
            continue
        kind = item.get('type')
        types.append(kind if kind in ('system', 'text', 'tool_use', 'tool_result', 'result') else 'other')
        if kind in ('system', 'result') and item.get('session_id') != expected_session:
            sessions_match = False
    return f"rows={len(types)};types={','.join(types[:20])};session_match={int(sessions_match)}"


class HermesAdapter(AgentAdapter):
    agent = "hermes"

    @staticmethod
    def failure_category(stdout: str, stderr: str) -> str:
        errors = [stderr or '']
        for line in (stdout or '').splitlines():
            try:
                event = json.loads(line)
            except (ValueError, TypeError):
                continue
            if isinstance(event, dict) and event.get('type') in ('error', 'result'):
                errors.append(str(event.get('error') or ''))
        blob = '\n'.join(errors).lower()
        if 'insufficient balance' in blob or ('402' in blob and 'payment required' in blob):
            return 'provider_balance_insufficient'
        return 'cli_failed'

    def verify_binding(self, binding: Dict[str, Any]) -> BindingVerification:
        """【F-3】preverified 取 agent_bindings 权威值。

        原实现 `bool(preverified) or not actual_session_id` 会在未回显 session 时把
        false 自动升级成 true，属 Codex 明令禁止的"自动升级"，已删除。
        """
        row, failure = precheck_binding(self.agent, binding)
        if failure is not None:
            return failure
        return resolve_binding_preverified(self.agent, row)

    def _build_argv(self, binding: Dict[str, Any], prompt: str) -> list:
        """固定 session：物理会话只来自 binding.actual_session_id，缺失即拒绝（绝不新建）。

        安全收尾后 config.HERMES_LOGICAL_SESSION 只是逻辑名（triad-hermes-main），
        不再等于物理会话，因此不能作为回落值——缺失时必须显式失败。
        """
        session = binding.get("actual_session_id")
        if not session:
            raise ValueError("hermes_actual_session_missing")
        return ["hermes", "chat", "-q", prompt, "-r", session,
                "--no-restore-cwd", "--format", "stream-json",
                "--provider", "deepseek", "--model", "deepseek-flash"]

    def _run(self, argv: list, timeout: int) -> subprocess.CompletedProcess:
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'
        return subprocess.run(argv, capture_output=True, text=True, encoding='utf-8',
                              errors='strict', env=env, timeout=timeout, shell=False)

    def call(
        self,
        *,
        binding: Dict[str, Any],
        context_packet: Any,
        rendered_prompt: str,
        idempotency_key: str,
        timeout: int,
    ) -> AdapterResult:
        argv = self._build_argv(binding, rendered_prompt)
        if any("bypass" in a for a in argv):
            return AdapterResult(success=False, error_code="command_bypass_detected",
                                 error_message_redacted="hermes 命令含 bypass")
        try:
            res = self._run(argv, timeout)
        except FileNotFoundError as e:
            return AdapterResult(success=False, error_code="cli_not_found",
                                 error_message_redacted=safe_error(e))
        if res.returncode != 0:
            code = self.failure_category(res.stdout, res.stderr)
            return AdapterResult(success=False, error_code=code,
                                 error_message_redacted=("Provider balance is insufficient; no automatic retry"
                                     if code == 'provider_balance_insufficient' else summarize_stderr(res.stderr)))
        # Gate5-B2（Codex 2026-08-12）：输出安全收口。
        # 禁止整段 stdout 直接作为回复；原始 stdout 只落受限 evidence 区（owner-only）。
        ex = extract_stream_result(res.stdout, binding['actual_session_id'])
        if not ex.ok:
            return AdapterResult(success=False, error_code=ex.error_code,
                                 error_message_redacted=(f"hermes 输出收口失败: {ex.error_code};"
                                                         f"{stream_shape(res.stdout, binding['actual_session_id'])}"))
        # Gate5-B2 v3（Codex 裁决）：证据安全在宣告成功前完成；失败必须使调用失败（禁发群）。
        stdout_ref, ev_err = store_raw_stdout(
            self.agent, res.stdout, idempotency_key, reviewed_text=ex.text,
        )
        if ev_err is not None or not stdout_ref:
            return AdapterResult(
                success=False,
                error_code=ev_err or "agent_result_evidence_failed",
                error_message_redacted="hermes 原始 stdout 证据落盘/登记失败",
            )
        # 【F-3】同样取权威值；无法解析时按 False 标注（调用已成功，不能反过来判失败），
        # 但绝不由"未回显 session"升级成 True。
        preverified = parse_preverified(binding.get("preverified"))
        return AdapterResult(
            success=True,
            text=ex.text,
            actual_session_id=binding.get("actual_session_id"),
            exit_code=0,
            preverified=bool(preverified),
            stdout_ref=stdout_ref,
        )
