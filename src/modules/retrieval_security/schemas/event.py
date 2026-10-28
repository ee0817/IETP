"""统一安全事件 SecurityEvent 数据模型。"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

# 统一 risk_type 命名（system_prompt.md 第 2.3 节）
# detection_error：检测器故障/不可用状态，由编排层决定复核、重试或限制，
# 检测器不得把故障转换为"无风险"安全结论。
RISK_TYPES = frozenset(
    {
        "prompt_injection",
        "poisoned_document",
        "suspicious_document",
        "malicious_context",
        "detection_error",
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

    # PR4 P2-8：开启赋值校验，防止聚合后回填字段时写入非法值绕过验证
    model_config = ConfigDict(validate_assignment=True)

    event_id: str = Field(default="", description="安全事件唯一标识，uuid4 hex")
    chunk_id: str = Field(default="", description="关联的 Chunk ID")
    stage: str = Field(default=STAGE_RETRIEVAL, description="风险发生的阶段，固定为 retrieval")
    risk_score: float = Field(..., ge=0.0, le=1.0, description="风险有多高，范围 0~1")
    risk_type: str = Field(..., description="风险类型，统一命名")
    confidence: float = Field(..., ge=0.0, le=1.0, description="检测器有多确定，范围 0~1")
    error: str | None = Field(
        default=None,
        description="检测失败信息（检测器名 + 原因）。仅 risk_type=detection_error 时使用",
    )

    @field_validator("stage")
    @classmethod
    def _validate_stage(cls, v: str) -> str:
        # PR4 P2-9：stage 必须固定为 retrieval；传入其他值直接报错，
        # 不再静默纠正，避免掩盖上游 bug。
        if v != STAGE_RETRIEVAL:
            raise ValueError(
                f"stage 必须为 '{STAGE_RETRIEVAL}'，实际传入 '{v}'"
            )
        return v

    @field_validator("risk_type")
    @classmethod
    def _validate_risk_type(cls, v: str) -> str:
        if v not in RISK_TYPES:
            raise ValueError(
                f"risk_type '{v}' 不在统一命名集合 {sorted(RISK_TYPES)} 中"
            )
        return v
