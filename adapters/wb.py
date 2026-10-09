"""WB adapter（Step 7：继承 AgentAdapter，网关 route B）。

安全红线：
- conversation.id 来自绑定（agent_bindings.actual_session_id）；id 来自 idempotency_key。
- 请求/日志/证据不得含 Bearer（Authorization 头仅本机网关，不落库、不打印）。
- 失败只回稳定错误码 + 脱敏摘要。
- 测试通过 monkeypatch _http_post / _http_get_lines 避免真实联网。
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Dict, Iterable, Tuple

from config import config
from redaction import safe_error

from .base import (AdapterResult, AgentAdapter, BindingVerification,
                   precheck_binding, resolve_binding_preverified)
from .extract import AgentResultExtractor, store_raw_stdout


def _http_post(url: str, body: bytes, headers: Dict[str, str], timeout: int) -> Tuple[int, str]:
    req = urllib.request.Request(url, data=body, method="POST", headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read().decode("utf-8")


def _http_get_lines(url: str, headers: Dict[str, str], timeout: int) -> Iterable[str]:
    req = urllib.request.Request(url, method="GET", headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        for raw in r:
            yield raw.decode("utf-8").rstrip("\n")


class WBAdapter(AgentAdapter):
    agent = "workbuddy"
    MAX_SSE_RETRIES = 3

    # ---------------- 绑定核验 ----------------
    def verify_binding(self, binding: Dict[str, Any]) -> BindingVerification:
        """【F-3】preverified 取 agent_bindings 权威值，不用 dataclass 默认值。"""
        row, failure = precheck_binding(self.agent, binding)
        if failure is not None:
            return failure
        return resolve_binding_preverified(self.agent, row)

    # ---------------- SSE 解析（纯函数，易测）----------------
    @staticmethod
    def parse_sse(lines: Iterable[str]) -> Tuple[str, str]:
        """解析一段 SSE 流。返回 (status, text)。

        status:
          - 'completed'：收到 status=completed，text 为完整 markdown。
          - 'active'  ：收到 running/active 但流结束（调用方应断流恢复同一 run，不重新 POST）。
          - 'unknown' ：无任何 completed/active（active=false 无结果）-> 调用方标 unknown。
        """
        status = "unknown"
        text = ""
        for raw in lines:
            line = raw.rstrip("\n") if isinstance(raw, str) else raw.decode("utf-8").rstrip("\n")
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            try:
                obj = json.loads(data)
            except Exception:
                continue
            if not isinstance(obj, dict):
                continue
            st = obj.get("status")
            if st == "completed":
                return ("completed", (obj.get("content") or {}).get("markdown", ""))
            elif st in ("running", "accepted", "streaming"):
                status = "active"
                md = (obj.get("content") or {}).get("markdown")
                if md:
                    text = md
            elif st in ("failed", "error"):
                return ("unknown", "")
        if status == "active":
            return ("active", text)
        return ("unknown", text)

    # ---------------- 调用 ----------------
    def _read_sse(self, run_id: str, timeout: int) -> Tuple[str, str]:
        headers = {
            "Authorization": f"Bearer {config.WB_GATEWAY_PASSWORD}",
            "x-codebuddy-request": "1",
        }
        url = f"{config.WB_GATEWAY_URL}/api/v1/runs/{run_id}/stream"
        last_status, last_text = "unknown", ""
        self._observed_session_id = None
        def observed(lines):
            for line in lines:
                if line.startswith("data:"):
                    try:
                        event = json.loads(line[5:])
                        if isinstance(event, dict) and event.get('status') == 'completed':
                            self._observed_session_id = (event.get('agent') or {}).get('sessionId')
                    except (ValueError, TypeError, AttributeError):
                        pass
                yield line
        for _ in range(self.MAX_SSE_RETRIES):
            st, tx = self.parse_sse(observed(_http_get_lines(url, headers, timeout)))
            last_status, last_text = st, tx
            if st == "completed":
                return st, tx
            if st != "active":
                break
        # 断流且仍 active：不重新 POST，交由调用方标 unknown
        return last_status, last_text

    def call(
        self,
        *,
        binding: Dict[str, Any],
        context_packet: Any,
        rendered_prompt: str,
        idempotency_key: str,
        timeout: int,
    ) -> AdapterResult:
        if not config.WB_GATEWAY_PASSWORD:
            return AdapterResult(success=False, error_code="auth_missing",
                                 error_message_redacted="WB_GATEWAY_PASSWORD 未设置")
        conversation_id = binding.get("actual_session_id") or binding.get("logical_session")
        self._observed_session_id = None
        try:
            status, body = _http_post(
                f"{config.WB_GATEWAY_URL}/api/v1/runs",
                json.dumps({
                    "id": idempotency_key,
                    "type": "message",
                    "source": {"platform": "generic", "sender": {"id": "triad-controller"},
                               "conversation": {"id": conversation_id, "type": "direct"}},
                    "timeoutMs": max(1, timeout - 5) * 1000,
                    "payload": {"text": rendered_prompt},
                }).encode("utf-8"),
                {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {config.WB_GATEWAY_PASSWORD}",
                    "x-codebuddy-request": "1",
                },
                timeout,
            )
        except urllib.error.HTTPError as e:
            if e.code == 401:
                return AdapterResult(success=False, error_code="auth_permanent",
                                     error_message_redacted="WB gateway 401")
            return AdapterResult(success=False, error_code="http_error",
                                 error_message_redacted=safe_error(e))
        except Exception as e:
            return AdapterResult(success=False, error_code="transport_error",
                                 error_message_redacted=safe_error(e))

        try:
            resp_obj = json.loads(body)
        except Exception as e:
            return AdapterResult(success=False, error_code="http_error",
                                 error_message_redacted=safe_error(e))
        run_id = (resp_obj.get("data") or {}).get("runId")
        if not run_id:
            return AdapterResult(success=False, error_code="no_run_id",
                                 error_message_redacted="gateway 未返回 runId")

        # SSE 读取：401 必须落 auth_permanent；其他异常归 transport_error。
        # 关键修复：原实现把 _read_sse 放在 try 之外，SSE 阶段 401 会逃逸成
        # call_worker 的 internal_error（R2 真实故障，违反 R2-FIX #518）。
        try:
            st, text = self._read_sse(run_id, timeout)
        except urllib.error.HTTPError as e:
            if e.code == 401:
                return AdapterResult(success=False, error_code="auth_permanent",
                                     error_message_redacted="WB gateway 401 (stream)")
            return AdapterResult(success=False, error_code="http_error",
                                 error_message_redacted=safe_error(e))
        except Exception as e:
            return AdapterResult(success=False, error_code="transport_error",
                                 error_message_redacted=safe_error(e))
        if st == "completed":
            if self._observed_session_id != conversation_id:
                return AdapterResult(success=False, error_code="session_mismatch",
                                     error_message_redacted="WB returned session identity does not match binding")
            # Gate5-B2 v2（Codex 裁决）：证据安全在宣告成功前完成；失败必须使调用失败（禁发群）。
            extractor = AgentResultExtractor()
            ex = extractor.extract(self.agent, text)
            if not ex.ok:
                return AdapterResult(success=False, error_code=ex.error_code,
                                     error_message_redacted=f"wb 输出收口失败: {ex.error_code}")
            stdout_ref, ev_err = store_raw_stdout(
                self.agent, text, idempotency_key, reviewed_text=ex.text,
            )
            if ev_err is not None or not stdout_ref:
                return AdapterResult(
                    success=False,
                    error_code=ev_err or "agent_result_evidence_failed",
                    error_message_redacted="wb 原始输出证据落盘/登记失败",
                )
            return AdapterResult(success=True, text=ex.text,
                                 actual_session_id=self._observed_session_id, exit_code=0,
                                 stdout_ref=stdout_ref)
        # unknown / active 断流：不重新 POST
        return AdapterResult(success=False, error_code="result_unknown",
                             error_message_redacted="SSE 未收到 completed", text=text)
