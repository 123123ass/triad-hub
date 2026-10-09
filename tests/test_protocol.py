import pytest
from pydantic import ValidationError

from models import (
    TaskState,
    MessageType,
    DeliveryState,
    AgentStatus,
    CallState,
    TraceControlState,
    ALLOWED_TASK_TRANSITIONS,
    validate_transition,
)
from schemas import EnvelopeV1


# ---- 任务状态机 ----
def test_validate_transition_legal():
    assert validate_transition(TaskState.PROPOSED, TaskState.ASSIGNED) is True
    assert validate_transition(TaskState.ASSIGNED, TaskState.ACCEPTED) is True
    assert validate_transition(TaskState.ACCEPTED, TaskState.IN_PROGRESS) is True
    assert validate_transition(TaskState.IN_PROGRESS, TaskState.REVIEW) is True
    assert validate_transition(TaskState.IN_PROGRESS, TaskState.BLOCKED) is True
    assert validate_transition(TaskState.BLOCKED, TaskState.IN_PROGRESS) is True
    assert validate_transition(TaskState.REVIEW, TaskState.DONE) is True


def test_validate_transition_illegal():
    assert validate_transition(TaskState.DONE, TaskState.IN_PROGRESS) is False
    assert validate_transition(TaskState.FAILED, TaskState.IN_PROGRESS) is False
    assert validate_transition(TaskState.PROPOSED, TaskState.DONE) is False
    assert validate_transition(TaskState.IN_PROGRESS, TaskState.PROPOSED) is False
    # 终态不能再迁移
    assert validate_transition(TaskState.DONE, TaskState.REVIEW) is False


# ---- envelope 校验 ----
def test_envelope_missing_required_fields():
    # 缺 source_agent
    with pytest.raises(ValidationError):
        EnvelopeV1(event_id="e1", trace_id="t1")
    # 缺 event_id
    with pytest.raises(ValidationError):
        EnvelopeV1(trace_id="t1", source_agent="workbuddy")
    # 缺 trace_id
    with pytest.raises(ValidationError):
        EnvelopeV1(event_id="e1", source_agent="workbuddy")


def test_envelope_bad_source_agent():
    with pytest.raises(ValidationError):
        EnvelopeV1(event_id="e1", trace_id="t1", source_agent="evil")


def test_envelope_bad_target_agent():
    with pytest.raises(ValidationError):
        EnvelopeV1(
            event_id="e1",
            trace_id="t1",
            source_agent="workbuddy",
            target_agents=["evil"],
        )


def test_envelope_negative_hop_rejected():
    with pytest.raises(ValidationError):
        EnvelopeV1(
            event_id="e1", trace_id="t1", source_agent="workbuddy", hop_count=-1
        )


def test_envelope_hop_limit_check():
    # hop_count == max_hops 允许
    env_ok = EnvelopeV1(
        event_id="e1", trace_id="t1", source_agent="workbuddy",
        hop_count=2, max_hops=2,
    )
    env_ok.check_hop_limit()  # 不应抛
    # hop_count > max_hops 拒绝
    env_bad = EnvelopeV1(
        event_id="e2", trace_id="t1", source_agent="workbuddy",
        hop_count=3, max_hops=2,
    )
    with pytest.raises(ValueError):
        env_bad.check_hop_limit()


def test_envelope_extra_field_forbidden():
    with pytest.raises(ValidationError):
        EnvelopeV1(
            event_id="e1", trace_id="t1", source_agent="workbuddy",
            unknown_field="x",
        )


def test_enums_present():
    assert MessageType.CHAT.value == "chat"
    assert DeliveryState.DEAD.value == "dead"
    assert AgentStatus.OFFLINE.value == "offline"
    assert CallState.TIMEOUT.value == "timeout"
    assert TraceControlState.STOPPED.value == "stopped"
    # 状态机覆盖全部 9 个任务状态
    assert set(ALLOWED_TASK_TRANSITIONS.keys()) == {s for s in TaskState}
