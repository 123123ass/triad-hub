"""Codex adapter（Step 7：继承 AgentAdapter，安全化）。

安全红线：
- 物理 session 只从 binding（agent_bindings.actual_session_id）读取，绝不硬编码。
- binding 的 logical_session 必须为 triad-codex-main。
- 只 resume 绑定 task；禁止 'new' / fresh fallback；禁止 --dangerously-bypass-approvals-and-sandbox。
- 多行 prompt 作为单独 argv 传入（list 形式天然保留，不拆分、不 shell）。
- 失败只回稳定错误码 + stderr 脱敏摘要。
- 测试通过 monkeypatch CodexAdapter._run 避免真实执行。
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from typing import Any, Dict, Optional, Tuple

from config import config
from redaction import safe_error, summarize_stderr

from .base import (AdapterResult, AgentAdapter, BindingVerification,
                   precheck_binding, resolve_binding_preverified)
from .extract import AgentResultExtractor, store_raw_stdout


class CodexAdapter(AgentAdapter):
    agent = "codex"

    def verify_binding(self, binding: Dict[str, Any]) -> BindingVerification:
        """【F-3】通用前置校验 -> codex 专属 logical_session 校验 -> 回填权威 preverified。"""
        row, failure = precheck_binding(self.agent, binding)
        if failure is not None:
            return failure
        if row.get("logical_session") != config.CODEX_LOGICAL_SESSION:
            return BindingVerification(ok=False, error_code="binding_wrong_logical_session",
                                       error_message_redacted="codex logical_session 必须为 triad-codex-main")
        return resolve_binding_preverified(self.agent, row)

    def _build_cmd(self, binding: Dict[str, Any], prompt: str) -> list:
        """只 resume 绑定 session；prompt 作为单独 argv（可含换行）。"""
        session = binding.get("actual_session_id")
        cmd = ([config.CODEX_BIN] if config.CODEX_BIN else [config.NODE, config.CODEX_JS])
        if config.CODEX_MODEL:
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,99}', config.CODEX_MODEL):
                raise ValueError("invalid_codex_model")
            cmd += ['-c', 'model=' + json.dumps(config.CODEX_MODEL)]
        cmd += [
            "exec",
            "--skip-git-repo-check",
            "resume",
            "--json",
            session,
            prompt,
        ]
        if any("bypass" in a for a in cmd):
            raise ValueError("command_bypass_detected")
        return cmd

    @staticmethod
    def failure_category(stdout: str, stderr: str) -> str:
        """Read errors only, emit a stable code, never provider text or identifiers."""
        errors = [stderr or '']
        for line in (stdout or '').splitlines():
            try:
                event = json.loads(line)
            except (ValueError, TypeError):
                continue
            if isinstance(event, dict) and event.get('type') in ('error', 'turn.failed'):
                errors.append(json.dumps(event, ensure_ascii=False))
        blob = '\n'.join(errors).lower()
        if 'not supported when using codex' in blob or 'model_not_found' in blob:
            return 'codex_model_unsupported'
        return 'cli_failed'

    @staticmethod
    def parse_jsonl(stdout: str) -> Tuple[str, Optional[str], Optional[str]]:
        """解析 codex.js exec 的 JSONL 输出。

        返回 (text, actual_session_id, error_code)。
        error_code 为 None 表示成功可继续；'no_rollout' 表示无 rollout 阻塞。
        """
        text = ""
        actual: Optional[str] = None
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if not isinstance(obj, dict):
                continue
            if obj.get('type') == 'thread.started' and obj.get('thread_id'):
                actual = obj['thread_id']
            if obj.get('type') == 'item.completed':
                item = obj.get('item') or {}
                if isinstance(item, dict) and item.get('type') == 'agent_message':
                    text = item.get('text') or ''
            if obj.get("status") == "completed":
                text = (obj.get("content") or {}).get("markdown", "") or obj.get("text", "")
            if obj.get("session_id"):
                actual = obj.get("session_id")
            if obj.get("error") == "no_rollout_found" or "no rollout" in str(obj).lower():
                return "", None, "no_rollout"
        return text, actual, None

    def _run(self, cmd: list, env: dict, timeout: int) -> subprocess.CompletedProcess:
        return subprocess.run(cmd, env=env, capture_output=True, text=True,
                              encoding='utf-8', errors='strict', timeout=timeout, shell=False)

    def call(
        self,
        *,
        binding: Dict[str, Any],
        context_packet: Any,
        rendered_prompt: str,
        idempotency_key: str,
        timeout: int,
    ) -> AdapterResult:
        try:
            cmd = self._build_cmd(binding, rendered_prompt)
        except ValueError as exc:
            code = 'codex_model_invalid' if str(exc) == 'invalid_codex_model' else 'command_bypass_detected'
            return AdapterResult(success=False, error_code=code,
                                 error_message_redacted="Codex runner configuration rejected")
        requested = binding.get("actual_session_id")
        env = dict(os.environ)
        env["NODE_OPTIONS"] = ""
        env["HTTPS_PROXY"] = config.HTTPS_PROXY
        try:
            res = self._run(cmd, env, timeout)
        except FileNotFoundError as e:
            return AdapterResult(success=False, error_code="cli_not_found",
                                 error_message_redacted=safe_error(e))
        if res.returncode != 0:
            code = self.failure_category(res.stdout, res.stderr)
            return AdapterResult(success=False, error_code=code,
                                 error_message_redacted=("Codex model is unsupported for this login method"
                                     if code == 'codex_model_unsupported' else summarize_stderr(res.stderr)))
        text, actual, err = self.parse_jsonl(res.stdout)
        if err == "no_rollout":
            return AdapterResult(success=False, error_code="no_rollout",
                                 error_message_redacted="codex 无 rollout")
        if actual is not None and requested is not None and actual != requested:
            return AdapterResult(success=False, error_code="session_mismatch",
                                 error_message_redacted="codex 实际 session 与请求不一致")
        # Gate5-B2 v2（Codex 裁决）：证据安全在宣告成功前完成；失败必须使调用失败（禁发群）。
        extractor = AgentResultExtractor()
        ex = extractor.extract(self.agent, text)
        if not ex.ok:
            return AdapterResult(success=False, error_code=ex.error_code,
                                 error_message_redacted=f"codex 输出收口失败: {ex.error_code}")
        stdout_ref, ev_err = store_raw_stdout(
            self.agent, res.stdout, idempotency_key, reviewed_text=ex.text,
        )
        if ev_err is not None or not stdout_ref:
            return AdapterResult(
                success=False,
                error_code=ev_err or "agent_result_evidence_failed",
                error_message_redacted="codex 原始 stdout 证据落盘/登记失败",
            )
        return AdapterResult(success=True, text=ex.text,
                             actual_session_id=actual or requested, exit_code=0,
                             stdout_ref=stdout_ref)
