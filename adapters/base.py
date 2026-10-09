"""Adapter 基类（Step 7）。

统一契约：
- verify_binding(binding) -> BindingVerification：核验绑定可用性；失败只能回稳定错误码，不回 stderr 全文。
- call(...) -> AdapterResult：实际发起外部调用（本步骤测试中不真实执行 Agent）。

安全红线：
- 物理会话 id 只能来自 binding（agent_bindings），源码不得硬编码。
- 命令不得含 --dangerously-bypass-approvals-and-sandbox 等提权参数。
- 失败只回稳定错误码 + 脱敏摘要；绝不回原始 stderr / stdout。
- 【F-3】BindingVerification.preverified 必须直接取 agent_bindings.preverified 权威值，
  禁止依赖 dataclass 默认值，禁止把 false 自动升级成 true（例如"未回显 session 即视为
  preverified"这类推断一律删除）；绑定缺失 / 重复 active / 字段无法解析时必须回稳定
  错误码，禁止"默认 false 后仍报 ok=true"。
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Optional, Sequence, Union


@dataclass
class AdapterResult:
    """一次 Agent 调用的结果。字段完整、错误码稳定且脱敏。"""

    success: bool
    text: str = ""
    actual_session_id: Optional[str] = None
    exit_code: Optional[int] = None
    error_code: Optional[str] = None
    error_message_redacted: Optional[str] = None
    preverified: bool = False
    stdout_ref: Optional[str] = None
    result_ref: Optional[str] = None


@dataclass
class BindingVerification:
    """绑定核验结果。"""

    ok: bool
    error_code: Optional[str] = None
    error_message_redacted: Optional[str] = None
    preverified: bool = False


# ---------------- F-3：绑定核验公共实现（三 adapter 唯一入口）----------------
# 稳定错误码（枚举固定，不得回原始异常文本）
BINDING_MISSING = "binding_missing"
BINDING_DUPLICATE_ACTIVE = "binding_duplicate_active"
BINDING_OFFLINE = "binding_offline"
BINDING_PREVERIFIED_UNPARSABLE = "binding_preverified_unparsable"

_PREVERIFIED_TRUE = {"1", "true", "yes", "y", "t"}
_PREVERIFIED_FALSE = {"0", "false", "no", "n", "f"}

BindingInput = Union[Dict[str, Any], Sequence[Dict[str, Any]], None]


def parse_preverified(raw: Any) -> Optional[bool]:
    """把 agent_bindings.preverified 原始值解析为布尔。

    只接受明确的 0/1 语义；任何歧义值（None、2、'maybe'、空串、对象…）一律返回 None
    表示"无法解析"，由调用方回稳定错误码——绝不静默降级成 False。
    """
    if raw is None:
        return None
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, int) and not isinstance(raw, bool):
        return bool(raw) if raw in (0, 1) else None
    if isinstance(raw, float):
        return bool(raw) if raw in (0.0, 1.0) else None
    if isinstance(raw, str):
        s = raw.strip().lower()
        if s in _PREVERIFIED_TRUE:
            return True
        if s in _PREVERIFIED_FALSE:
            return False
        return None
    return None


def normalize_binding(binding: BindingInput) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
    """把绑定入参归一为单条 dict。

    返回 (binding_dict, error_code)：
    - None / 空 dict / 空序列          -> (None, binding_missing)
    - 多条 active 记录（序列 len>1，或 dict 携带 active_binding_count>1）
                                        -> (None, binding_duplicate_active)
    - 单条                              -> (dict, None)
    """
    if binding is None:
        return None, BINDING_MISSING
    if isinstance(binding, dict):
        if not binding:
            return None, BINDING_MISSING
        count = binding.get("active_binding_count")
        if isinstance(count, int) and count > 1:
            return None, BINDING_DUPLICATE_ACTIVE
        return binding, None
    if isinstance(binding, (list, tuple)):
        rows = [r for r in binding if r]
        if not rows:
            return None, BINDING_MISSING
        if len(rows) > 1:
            return None, BINDING_DUPLICATE_ACTIVE
        return dict(rows[0]), None
    return None, BINDING_MISSING


def precheck_binding(agent: str, binding: BindingInput) -> tuple[Optional[Dict[str, Any]],
                                                                 Optional[BindingVerification]]:
    """绑定通用前置校验（缺失 / 重复 active / offline）。

    返回 (binding_dict, failure)。failure 非 None 时调用方必须直接返回它。
    先于各 adapter 的专属校验（如 codex 的 logical_session）之外的通用项执行。
    """
    row, err = normalize_binding(binding)
    if err == BINDING_MISSING:
        return None, BindingVerification(ok=False, error_code=BINDING_MISSING,
                                         error_message_redacted=f"{agent} 绑定缺失")
    if err == BINDING_DUPLICATE_ACTIVE:
        return None, BindingVerification(ok=False, error_code=BINDING_DUPLICATE_ACTIVE,
                                         error_message_redacted=f"{agent} 存在多条 active 绑定")
    assert row is not None
    if row.get("status") == "offline":
        return row, BindingVerification(ok=False, error_code=BINDING_OFFLINE,
                                        error_message_redacted=f"{agent} binding offline")
    return row, None


def resolve_binding_preverified(agent: str, binding: Dict[str, Any]) -> BindingVerification:
    """通过全部校验后，回填数据库权威 preverified。

    preverified 字段缺失或无法解析 -> ok=False + binding_preverified_unparsable，
    绝不"默认 false 后仍报 ok=true"。
    """
    value = parse_preverified(binding.get("preverified"))
    if value is None:
        return BindingVerification(
            ok=False,
            error_code=BINDING_PREVERIFIED_UNPARSABLE,
            error_message_redacted=f"{agent} agent_bindings.preverified 缺失或无法解析",
        )
    return BindingVerification(ok=True, preverified=value)


class AgentAdapter(ABC):
    agent: str = ""

    @abstractmethod
    def verify_binding(self, binding: Dict[str, Any]) -> BindingVerification:
        """核验绑定是否可用。返回 ok / 稳定错误码。"""

    @abstractmethod
    def call(
        self,
        *,
        binding: Dict[str, Any],
        context_packet: Any,
        rendered_prompt: str,
        idempotency_key: str,
        timeout: int,
    ) -> AdapterResult:
        """实际发起外部调用。本步骤测试中通过 monkeypatch transport 避免真实执行。"""
