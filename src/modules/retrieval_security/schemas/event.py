"""统一安全事件 SecurityEvent 数据模型。"""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

# 统一 risk_type 命名（system_prompt.md 第 2.3 节）
RISK_TYPES = frozenset(
    {
        "prompt_injection",
        "poisoned_document",
        "suspicious_document",
        "malicious_context",
        "none",
    }
)

# stage 固定为 retrieval
STAGE_RETRIEVAL = "retrieval"


class SecurityEvent(BaseModel):
    """统一安全事件，交付给 RAG-FlowShield 的 Policy Engine。

    字段定义严格遵循 system_prompt.md 第 2.2 节。
    字段名与类型必须与小e规范一致。
    """

    event_id: str = Field(default="", description="安全事件唯一标识，uuid4 hex")
    chunk_id: str = Field(default="", description="关联的 Chunk ID")
    stage: str = Field(default=STAGE_RETRIEVAL, description="风险发生的阶段，固定为 retrieval")
    risk_score: float = Field(..., ge=0.0, le=1.0, description="风险有多高，范围 0~1")
    risk_type: str = Field(..., description="风险类型，统一命名")
    confidence: float = Field(..., ge=0.0, le=1.0, description="检测器有多确定，范围 0~1")

    @field_validator("stage")
    @classmethod
    def _validate_stage(cls, v: str) -> str:
        if v != STAGE_RETRIEVAL:
            # stage 必须固定为 retrieval；若调用方传入其他值则纠正为 retrieval。
            return STAGE_RETRIEVAL
        return v

    @field_validator("risk_type")
    @classmethod
    def _validate_risk_type(cls, v: str) -> str:
        if v not in RISK_TYPES:
            raise ValueError(
                f"risk_type '{v}' 不在统一命名集合 {sorted(RISK_TYPES)} 中"
            )
        return v
