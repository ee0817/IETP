# -*- coding: utf-8 -*-
"""统一数据模型：SecurityStage / RiskType / SecurityEvent / RetrievedChunk / UserContext / UserContextAdapter。

所有检测器对外只输出 SecurityEvent（stage + risk_score + risk_type + confidence）。
优先使用 pydantic 做字段校验；环境中没有 pydantic 时自动回退到等价的轻量实现，
保证模块零第三方依赖也可独立运行，两种实现对外行为一致：

- risk_score / confidence 必须落在 [0, 1]；
- to_dict() / to_json() 输出可直接 JSON 序列化的字典/字符串；
- from_dict() / from_json() 支持从外部字典重建实例。

UserContextAdapter：统一 context 参数校验。禁止静默匿名（不再 isinstance else None），
非 None 且非 UserContext 时：在调用方显式 raise TypeError 或产出
SecurityEvent（由调用方选择，默认产事件）。
"""
from __future__ import annotations

import json as _json
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

    # ---- 检测器无命中时的占位事件类型（按 INTERFACES.md 约定为 "no_risk"） ----
    NO_RISK = "no_risk"


def _check_bounds(field_name: str, value: Any) -> float:
    value = float(value)
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{field_name} 必须在 [0, 1] 区间内，实际值: {value}")
    return value


# ------------------------------------------------------------ SecurityEvent


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
        # 结构化扩展字段：如下游需机器可读的状态（如 trust_status），
        # 放 details，禁止要求下游解析 evidence 自由文本
        details: Dict[str, Any] = Field(default_factory=dict)

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

        def to_json(self, *, indent: Optional[int] = None) -> str:
            """序列化为 JSON 字符串。"""
            return _json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

        @classmethod
        def from_dict(cls, data: Dict[str, Any]) -> "SecurityEvent":
            """从字典重建 SecurityEvent；stage 字符串自动转为枚举。"""
            kwargs = dict(data)
            stage_val = kwargs.get("stage")
            if isinstance(stage_val, str) and not isinstance(stage_val, SecurityStage):
                kwargs["stage"] = SecurityStage(stage_val)
            return cls(**kwargs)

        @classmethod
        def from_json(cls, text: str) -> "SecurityEvent":
            """从 JSON 字符串重建 SecurityEvent。"""
            return cls.from_dict(_json.loads(text))

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
            details: Optional[Dict[str, Any]] = None,
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
            self.details = dict(details or {})

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
                "details": dict(self.details),
            }

        def to_json(self, *, indent: Optional[int] = None) -> str:
            """序列化为 JSON 字符串。"""
            return _json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

        @classmethod
        def from_dict(cls, data: Dict[str, Any]) -> "SecurityEvent":
            """从字典重建 SecurityEvent。"""
            kwargs = dict(data)
            stage_val = kwargs.get("stage")
            if isinstance(stage_val, str) and not isinstance(stage_val, SecurityStage):
                kwargs["stage"] = SecurityStage(stage_val)
            return cls(**kwargs)

        @classmethod
        def from_json(cls, text: str) -> "SecurityEvent":
            """从 JSON 字符串重建 SecurityEvent。"""
            return cls.from_dict(_json.loads(text))

        def __repr__(self) -> str:
            return (
                f"SecurityEvent(stage={self.stage.value!r}, "
                f"risk_score={self.risk_score:.2f}, risk_type={self.risk_type!r}, "
                f"confidence={self.confidence:.2f}, chunk_id={self.chunk_id!r})"
            )


# ------------------------------------------------------------ RetrievedChunk


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


# ------------------------------------------------------------ UserContext + Adapter


@dataclass
class UserContext:
    """请求用户上下文：user_id 与角色列表（用于越权判定）。"""

    user_id: str = ""
    roles: List[str] = field(default_factory=list)


# ------------------------------------------------------------ TrustResult（结构化信任交付）


class TrustStatus(str, Enum):
    """来源信任三态，对齐 INTERFACES.md Trust/Whitelist V1。

    命中白名单返回 TRUSTED，未命中返回 UNKNOWN；未命中不等于恶意。
    黑名单命中返回 BLOCKED。
    """

    TRUSTED = "TRUSTED"
    UNKNOWN = "UNKNOWN"
    BLOCKED = "BLOCKED"


@dataclass
class TrustResult:
    """来源信任检测结果的结构化交付物（对齐 INTERFACES.md 推荐字段）。

    编排层可直接消费本结构，无需解析 evidence 自由文本：
    - source_id：被检来源标识；
    - trust_status：TRUSTED / UNKNOWN / BLOCKED；
    - trust_score：信任分 [0,1]；
    - reason：判定依据（白/黑名单命中条目或未命中说明）。

    交付约定：
    - 三态均通过 SourceTrustDetector.check_trust(doc) -> TrustResult 结构化返回；
    - UNKNOWN / BLOCKED 同时产出 SecurityEvent，details 中携带同名结构化字段；
    - TRUSTED 不是风险，detect_one 不产出风险事件（合规：检测器只报告风险），
      编排层如需正向确认请调用 check_trust()。
    """

    source_id: str
    trust_status: TrustStatus
    trust_score: float
    reason: str = ""


class UserContextAdapter:
    """context 参数统一校验：禁止静默匿名（isinstance else None）。

    调用方式：
        user = UserContextAdapter.validate(context, raise_on_invalid=True/False)

    规则：
    - None -> 返回 None（无用户上下文是合法的，代表"未携带"，不等同于静默匿名）；
    - UserContext 实例 -> 原样返回；
    - 非 None 且非 UserContext：
        raise_on_invalid=True  -> raise TypeError；
        raise_on_invalid=False -> 返回 None 并产出一条 INVALID_USER_CONTEXT 事件
          供调用方 append（调用方自行决定是否上报）。
    """

    # 非法 context 参数的 risk_type（调用方需确保 RiskType 常量可访问）
    # 这里只定义字符串，避免循环导入；调用方用 RiskType 常量替换
    INVALID_CONTEXT_RISK_TYPE = "invalid_user_context"

    @staticmethod
    def validate(
        context: Any,
        *,
        raise_on_invalid: bool = False,
    ) -> Any:
        """校验 context 输入，返回 UserContext 或 None。

        - None 或 UserContext -> 直接返回；
        - 非 None 且非 UserContext：
            raise_on_invalid=True  -> raise TypeError("context 必须是 UserContext 或 None");
            raise_on_invalid=False -> 返回 None（调用方需自行 append INVALID_CONTEXT 事件）。
        """
        if context is None or isinstance(context, UserContext):
            return context
        if raise_on_invalid:
            raise TypeError(
                f"context 必须是 UserContext 或 None，实际收到 {type(context).__name__}: {context!r}"
            )
        return None

    @staticmethod
    def make_invalid_context_event(
        detector_name: str,
        context_value: Any,
        *,
        stage: Optional[SecurityStage] = None,
    ) -> SecurityEvent:
        """构造一条 INVALID_USER_CONTEXT 事件，供调用方在 context 非法时 append。

        risk_score=0.35（轻度——调用方未按规范传参，但不直接代表攻击）；
        真实恶意传参（如伪造 UserContext）应由单独检测器捕获。
        """
        from .scoring import make_event  # 延迟导入避免循环依赖

        _stage = stage if stage is not None else SecurityStage.INPUT
        actual_type = type(context_value).__name__
        return make_event(
            stage=_stage,
            risk_type=UserContextAdapter.INVALID_CONTEXT_RISK_TYPE,
            risk_score=0.35,
            confidence=0.90,
            detector_name=detector_name,
            evidence=[
                f"context 参数类型异常：期望 UserContext 或 None，"
                f"实际 {actual_type}={context_value!r}"
            ],
        )
