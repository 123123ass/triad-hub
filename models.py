"""Triad Hub 领域枚举与任务状态机 (Codex 冻结, 不得随意改迁移表).

协议细节见 docs/protocol_v1.md。旧的 make_envelope() 已删除，统一 envelope 由
schemas.EnvelopeV1 校验生成。
"""
from enum import Enum
from typing import Dict, FrozenSet

# ---- 任务状态 ----
class TaskState(str, Enum):
    PROPOSED = "proposed"
    ASSIGNED = "assigned"
    ACCEPTED = "accepted"
    IN_PROGRESS = "in_progress"
    WAITING = "waiting"
    BLOCKED = "blocked"
    REVIEW = "review"
    DONE = "done"
    FAILED = "failed"


# ---- 消息类型 ----
class MessageType(str, Enum):
    CHAT = "chat"
    MANAGEMENT = "management"
    AGENT_REPLY = "agent_reply"
    SYSTEM = "system"


# ---- 投递状态 ----
class DeliveryState(str, Enum):
    PENDING = "pending"
    RETRY = "retry"
    SENT = "sent"
    FAILED = "failed"
    DEAD = "dead"


# ---- Agent 在线状态 ----
class AgentStatus(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    BLOCKED = "blocked"
    PAUSED = "paused"


# ---- 调用状态 ----
class CallState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


# ---- trace 控制状态 ----
class TraceControlState(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    STOPPED = "stopped"


# 任务状态机（Codex 决断冻结）：proposed→assigned→accepted→in_progress→{waiting|blocked}→review→{done|failed}
ALLOWED_TASK_TRANSITIONS: Dict[TaskState, FrozenSet[TaskState]] = {
    TaskState.PROPOSED: frozenset({TaskState.ASSIGNED}),
    TaskState.ASSIGNED: frozenset({TaskState.ACCEPTED, TaskState.BLOCKED}),
    TaskState.ACCEPTED: frozenset({TaskState.IN_PROGRESS, TaskState.BLOCKED}),
    TaskState.IN_PROGRESS: frozenset({TaskState.WAITING, TaskState.BLOCKED, TaskState.REVIEW, TaskState.FAILED}),
    TaskState.WAITING: frozenset({TaskState.IN_PROGRESS, TaskState.BLOCKED, TaskState.REVIEW}),
    TaskState.BLOCKED: frozenset({TaskState.IN_PROGRESS, TaskState.REVIEW, TaskState.FAILED}),
    TaskState.REVIEW: frozenset({TaskState.DONE, TaskState.FAILED, TaskState.IN_PROGRESS}),
    TaskState.DONE: frozenset(),
    TaskState.FAILED: frozenset(),
}


def validate_transition(old: TaskState, new: TaskState) -> bool:
    """合法迁移返回 True；非法返回 False（调用方应返回 409 并记 audit_events）。"""
    allowed = ALLOWED_TASK_TRANSITIONS.get(old)
    if allowed is None:
        return False
    return new in allowed


# 防循环（Codex 决断冻结）
MAX_HOPS = 2
MAX_AUTO_REPLIES = 1
