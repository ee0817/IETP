# -*- coding: utf-8 -*-
"""统一数据模型：SecurityStage / RiskType / SecurityEvent / RetrievedChunk / UserContext。

所有检测器对外只输出 SecurityEvent（stage + risk_score + risk_type + confidence）。
优先使用 pydantic 做字段校验；环境中没有 pydantic 时自动回退到等价的轻量实现，
保证模块零第三方依赖也可独立运行，两种实现对外行为一致：

- risk_score / confidence 必须落在 [0, 1]；
- to_dict() 输出可直接 JSON 序列化的字典。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class SecurityStage(str, Enum):
    """统一阶段枚举，对齐《代码规范.md》。"""

    INPUT = "input"
    RETRIEVAL = "retrieval"
    CONTEXT = "context"
    GENERATION = "generation"
    OUTPUT = "output"


class RiskType:
    """risk_type 集中管理，检测逻辑中禁止散落硬编码字符串。"""

    # ---- PPT / 接入规范已定义，直接使用 ----
    PROMPT_INJECTION = "prompt_injection"
    SUSPICIOUS_INPUT = "suspicious_input"
    POISONED_DOCUMENT = "poisoned_document"
    MALICIOUS_CONTEXT = "malicious_context"
    SUSPICIOUS_DOCUMENT = "suspicious_document"

    # ---- TODO(v1.1)：以下新增命名接入前需先与团队统一 ----
    MALICIOUS_INTENT = "malicious_intent"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    UNAUTHORIZED_RETRIEVAL = "unauthorized_retrieval"
    LOW_TRUST_SOURCE = "low_trust_source"

    # ---- TODO：检测器无命中时的占位事件类型，接入前需与团队确认 ----
    NO_RISK = "no_risk"


def _check_bounds(field_name: str, value: Any) -> float:
    value = float(value)
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{field_name} 必须在 [0, 1] 区间内，实际值: {value}")
    return value


try:  # 优先使用 pydantic（规范参考实现）
    from pydantic import BaseModel as _PydanticModel, Field, field_validator

    class SecurityEvent(_PydanticModel):  # type: ignore[misc]
        """统一风险事件四元组（可选 evidence 等解释字段，不破坏规范）。"""

        stage: SecurityStage
        risk_score: float
        risk_type: str
        confidence: float
        detector_name: Optional[str] = None
        evidence: List[str] = Field(default_factory=list)
        chunk_id: Optional[str] = None
        timestamp: Optional[str] = None

        @field_validator("risk_score", "confidence")
        @classmethod
        def _validate_bounds(cls, v: Any) -> float:
            return _check_bounds("risk_score/confidence", v)

        def to_dict(self) -> Dict[str, Any]:
            data = self.model_dump()
            data["stage"] = (
                self.stage.value
                if isinstance(self.stage, SecurityStage)
                else str(self.stage)
            )
            return data

except Exception:  # 无 pydantic 环境：轻量等价实现，行为与上方保持一致

    class SecurityEvent:  # type: ignore[no-redef]
        """统一风险事件四元组（轻量实现，无第三方依赖）。"""

        def __init__(
            self,
            *,
            stage: Any,
            risk_score: Any,
            risk_type: str,
            confidence: Any,
            detector_name: Optional[str] = None,
            evidence: Optional[List[str]] = None,
            chunk_id: Optional[str] = None,
            timestamp: Optional[str] = None,
        ) -> None:
            if isinstance(stage, str) and not isinstance(stage, SecurityStage):
                stage = SecurityStage(stage)
            self.stage = stage
            self.risk_score = _check_bounds("risk_score", risk_score)
            self.risk_type = str(risk_type)
            self.confidence = _check_bounds("confidence", confidence)
            self.detector_name = detector_name
            self.evidence = list(evidence or [])
            self.chunk_id = chunk_id
            self.timestamp = timestamp

        def to_dict(self) -> Dict[str, Any]:
            return {
                "stage": self.stage.value,
                "risk_score": self.risk_score,
                "risk_type": self.risk_type,
                "confidence": self.confidence,
                "detector_name": self.detector_name,
                "evidence": list(self.evidence),
                "chunk_id": self.chunk_id,
                "timestamp": self.timestamp,
            }

        def __repr__(self) -> str:
            return (
                f"SecurityEvent(stage={self.stage.value!r}, "
                f"risk_score={self.risk_score:.2f}, risk_type={self.risk_type!r}, "
                f"confidence={self.confidence:.2f}, chunk_id={self.chunk_id!r})"
            )


@dataclass
class RetrievedChunk:
    """检索结果块（对齐团队接口规范）。

    metadata 中可携带 acl_roles / classification 等权限标签；
    source 缺失时统一用 "unknown"，不使用空字符串；
    score 是 retriever 的相关度评分，非安全风险分。
    """

    chunk_id: str
    content: str
    source: str = "unknown"
    score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    trust_score: Optional[float] = None


@dataclass
class UserContext:
    """请求用户上下文：user_id 与角色列表（用于越权判定）。"""

    user_id: str = ""
    roles: List[str] = field(default_factory=list)
