"""Triad Hub 协议 v1 Pydantic schemas (Codex 冻结, 不得随意改字段).

对应 docs/protocol_v1.md。EnvelopeV1 的字段集合是 events 表的入站契约来源。
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ALLOWED_AGENTS = {"workbuddy", "codex", "hermes"}
ALLOWED_TARGET_AGENTS = {"workbuddy", "codex", "hermes"}
ALLOWED_SOURCE_AGENTS = {"workbuddy", "codex", "hermes", "operator"}
DEFAULT_MAX_HOPS = 2
CONTENT_SIG_TTL_SECONDS = 120


class SourceAgent(str, Enum):
    WORKBUDDY = "workbuddy"
    CODEX = "codex"
    HERMES = "hermes"
    OPERATOR = "operator"


class MessageType(str, Enum):
    CHAT = "chat"
    MANAGEMENT = "management"
    AGENT_REPLY = "agent_reply"
    SYSTEM = "system"


class EnvelopeV1(BaseModel):
    """统一事件 envelope。缺 event_id/trace_id/source_agent 时 pydantic 拒绝。"""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    event_id: str
    event_seq: Optional[int] = None
    idempotency_key: Optional[str] = None
    content_signature: Optional[str] = None
    trace_id: str
    parent_event_id: Optional[str] = None
    root_event_id: Optional[str] = None
    task_id: Optional[str] = None
    source_type: Optional[str] = None
    source_id: Optional[str] = None
    source_agent: str
    target_agents: List[str] = Field(default_factory=list)
    message_type: str = "chat"
    text: str = ""
    mentions: List[str] = Field(default_factory=list)
    refs: Dict[str, Any] = Field(default_factory=dict)
    hop_count: int = 0
    max_hops: int = DEFAULT_MAX_HOPS
    auto_reply_count: int = 0
    created_at: Optional[str] = None
    received_at: Optional[str] = None

    @field_validator("source_agent")
    @classmethod
    def _check_source_agent(cls, v: str) -> str:
        if v == "yangge":  # deprecated wire value from older local deployments
            return "operator"
        if v not in ALLOWED_SOURCE_AGENTS:
            raise ValueError(f"illegal source_agent: {v}")
        return v

    @field_validator("target_agents")
    @classmethod
    def _check_target_agents(cls, v: List[str]) -> List[str]:
        bad = [a for a in v if a not in ALLOWED_TARGET_AGENTS]
        if bad:
            raise ValueError(f"illegal target_agents: {bad}")
        return v

    @field_validator("hop_count")
    @classmethod
    def _check_hop_count(cls, v: int) -> int:
        if v < 0:
            raise ValueError("hop_count must be >= 0")
        return v

    @field_validator("max_hops")
    @classmethod
    def _check_max_hops(cls, v: int) -> int:
        if v < 0:
            raise ValueError("max_hops must be >= 0")
        return v

    def check_hop_limit(self) -> None:
        """hop_count > max_hops 时抛 ValueError（调用方拒绝）。"""
        if self.hop_count > self.max_hops:
            raise ValueError(f"hop_count {self.hop_count} > max_hops {self.max_hops}")


class FeishuIngressV1(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bot_identity: str
    raw_event: Dict[str, Any]
    received_at: Optional[str] = None


class TruthMetadataV1(BaseModel):
    call_type: Optional[str] = None
    requested_session_id: Optional[str] = None
    actual_session_id: Optional[str] = None
    command_mode: Optional[str] = None
    trace_id: Optional[str] = None
    exit_code: Optional[int] = None
    stdout_ref: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


class SummaryFactV1(BaseModel):
    """共享摘要中的单条事实（Codex 冻结强约束）。"""

    model_config = ConfigDict(extra="forbid")

    fact_id: str
    text: str
    evidence_event_seqs: List[int]

    @field_validator("fact_id")
    @classmethod
    def _check_fact_id(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("fact_id must not be empty")
        return v

    @field_validator("text")
    @classmethod
    def _check_text(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("fact text must not be empty")
        return v

    @field_validator("evidence_event_seqs")
    @classmethod
    def _check_evidence(cls, v: List[int]) -> List[int]:
        if not v:
            raise ValueError("at least one evidence event_seq required")
        for e in v:
            if not isinstance(e, int) or e <= 0:
                raise ValueError("evidence event_seq must be positive int")
        seen = set()
        out = []
        for e in v:
            if e not in seen:
                seen.add(e)
                out.append(e)
        return out


class SharedSummaryCandidateV1(BaseModel):
    """Hermes 提交的候选摘要（Hub 验证后转 verified）。"""

    model_config = ConfigDict(extra="forbid")

    summary_id: str
    from_event_seq: int
    to_event_seq: int
    summary_text: str
    facts: List[SummaryFactV1]
    proposed_by: str = "hermes"
    source_digest: str

    @field_validator("from_event_seq")
    @classmethod
    def _check_from(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("from_event_seq must be > 0")
        return v

    @field_validator("to_event_seq")
    @classmethod
    def _check_to(cls, v: int) -> int:
        if v < 1:
            raise ValueError("to_event_seq must be >= 1")
        return v

    @field_validator("proposed_by")
    @classmethod
    def _check_proposed(cls, v: str) -> str:
        if v != "hermes":
            raise ValueError("proposed_by must be hermes")
        return v

    @field_validator("summary_text")
    @classmethod
    def _check_summary_text(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("summary_text must not be empty")
        return v

    @field_validator("facts")
    @classmethod
    def _check_facts(cls, v: List[SummaryFactV1]) -> List[SummaryFactV1]:
        if not v:
            raise ValueError("at least one fact required")
        return v

    @model_validator(mode="after")
    def _check_range_and_evidence(self) -> "SharedSummaryCandidateV1":
        if self.to_event_seq < self.from_event_seq:
            raise ValueError("to_event_seq must be >= from_event_seq")
        lo, hi = self.from_event_seq, self.to_event_seq
        for f in self.facts:
            for e in f.evidence_event_seqs:
                if e < lo or e > hi:
                    raise ValueError(
                        f"fact {f.fact_id} evidence {e} out of range [{lo},{hi}]"
                    )
        return self


class ContextPacketV1(BaseModel):
    """注入某 Agent 的共享上下文包（Codex 冻结强约束）。"""

    model_config = ConfigDict(extra="forbid")

    packet_id: str
    agent_identity: str
    logical_session: str

    trigger_event_seq: int
    last_consumed_event_seq: int
    through_event_seq: int

    shared_summary_id: Optional[str] = None
    shared_summary: Optional[str] = None
    project_checkpoint: Optional[Dict[str, Any]] = None
    summary_from_seq: Optional[int] = None
    summary_to_seq: Optional[int] = None

    delta_from_seq: Optional[int] = None
    delta_to_seq: Optional[int] = None
    delta_events: List[Dict[str, Any]] = Field(default_factory=list)

    required_event_seqs: List[int] = Field(default_factory=list)
    required_source_events: List[Dict[str, Any]] = Field(default_factory=list)

    current_task_id: Optional[str] = None
    current_task_objective: Optional[str] = None
    current_task_owner: Optional[str] = None
    current_task_state: Optional[str] = None
    current_task_acceptance: Optional[str] = None

    trace_id: str
    evidence_refs: List[str] = Field(default_factory=list)
    reply_contract: str
    payload_hash: str


class AgentCallRequestV1(BaseModel):
    context_packet: ContextPacketV1
    message: str
    idempotency_key: str
    timeout: int = 300


class AgentCallResultV1(BaseModel):
    text: str
    truth_metadata: TruthMetadataV1
    raw_output_ref: Optional[str] = None
    session_id: Optional[str] = None
    status: str = "completed"


class TaskCreateV1(BaseModel):
    owner: str
    objective: str
    acceptance_criteria: Optional[str] = None
    trace_id: Optional[str] = None


class TaskTransitionV1(BaseModel):
    task_id: str
    from_state: str
    to_state: str
    actor: str
    evidence_refs: List[str] = Field(default_factory=list)


# ---------------- Step 8: 绑定验真与启动清单（Codex 冻结强约束）----------------


class BindingVerificationRecord(BaseModel):
    """一次绑定验真的事实记录（落 binding_verifications 表）。"""

    model_config = ConfigDict(extra="forbid")

    verification_id: str
    agent: str
    logical_session: str
    requested_session_id: Optional[str] = None
    actual_session_id: Optional[str] = None
    verification_type: str  # fresh_create | resume_nonce | continuity_check | binding_commit
    command_mode: str  # fresh | resume
    nonce_hash: Optional[str] = None
    bootstrap_manifest_hash: Optional[str] = None
    exit_code: Optional[int] = None
    evidence_ref: Optional[str] = None  # 仅相对路径
    status: str  # created | verified | failed | orphaned_unbound | superseded
    error_code: Optional[str] = None
    created_at: str

    @field_validator("verification_type")
    @classmethod
    def _check_type(cls, v: str) -> str:
        allowed = {"fresh_create", "resume_nonce", "continuity_check", "binding_commit"}
        if v not in allowed:
            raise ValueError(f"illegal verification_type: {v}")
        return v

    @field_validator("status")
    @classmethod
    def _check_status(cls, v: str) -> str:
        allowed = {"created", "verified", "failed", "orphaned_unbound", "superseded"}
        if v not in allowed:
            raise ValueError(f"illegal status: {v}")
        return v

    @field_validator("command_mode")
    @classmethod
    def _check_mode(cls, v: str) -> str:
        if v not in {"fresh", "resume"}:
            raise ValueError(f"illegal command_mode: {v}")
        return v


class ManifestFileV1(BaseModel):
    """启动清单中的一个源文件条目（只记录哈希与大小，不含内容）。"""

    model_config = ConfigDict(extra="forbid")

    path: str
    sha256: str
    bytes: int
    required: bool = True


class BootstrapManifestV1(BaseModel):
    """Triad 启动资料清单（构成专属 Codex 任务的共享项目历史）。"""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0"
    logical_session: str
    created_at: str
    files: List[ManifestFileV1] = Field(default_factory=list)
    manifest_hash: Optional[str] = None
