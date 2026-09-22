# -*- coding: utf-8 -*-
"""SourceGuardPipeline：串联输入检测与检索检测，输出 SecurityEvent 列表。

本 Pipeline 只做检测串联与风险事实汇总：
- 不决定 CONTINUE / VERIFY / RESTRICT / ROLLBACK / BLOCK；
- 不丢弃、不阻断检索文档；
- 汇总后的事件列表交给 RAG-FlowShield 的 Policy Engine 统一决策。

接入方式：
    events = pipeline.run(user_input=text, documents=docs, user_context=user)
    result = shield.process(events)   # 由对端全流程架构完成决策
"""
from __future__ import annotations

from typing import List, Optional, Sequence

from .config import GuardConfig
from .input_guard import (
    AccessControlDetector,
    MaliciousIntentDetector,
    PromptInjectionDetector,
)
from .retrieval_guard import (
    PoisonedDocumentDetector,
    RetrievalAuthzDetector,
    SourceTrustDetector,
)
from .schemas import RetrievedChunk, RiskType, SecurityEvent, SecurityStage, UserContext
from .scoring import make_event


class SourceGuardPipeline:
    def __init__(self, config: Optional[GuardConfig] = None) -> None:
        # 输入阶段（规则版）
        self.prompt_injection_detector = PromptInjectionDetector(config)
        self.malicious_intent_detector = MaliciousIntentDetector(config)
        self.access_control_detector = AccessControlDetector(config)
        # 检索阶段（v1.0 重点）
        self.source_trust_detector = SourceTrustDetector(config)
        self.poisoned_document_detector = PoisonedDocumentDetector(config)
        self.retrieval_authz_detector = RetrievalAuthzDetector(config)

    def _low_risk_event(self, detector) -> SecurityEvent:
        """检测器无命中时产出的占位事件：risk_type=no_risk，risk_score≈0。"""
        return make_event(
            stage=detector.stage,
            risk_type=RiskType.NO_RISK,
            risk_score=0.0,
            confidence=0.9,
            detector_name=detector.name,
            evidence=["未发现风险信号"],
        )

    def check_input(
        self, user_input: str, user_context: Optional[UserContext] = None
    ) -> List[SecurityEvent]:
        events: List[SecurityEvent] = []
        for detector in (
            self.prompt_injection_detector,
            self.malicious_intent_detector,
            self.access_control_detector,
        ):
            event = detector.detect(user_input, user_context)
            if event is None:
                event = self._low_risk_event(detector)
            events.append(event)
        return events

    def check_retrieval(
        self,
        documents: Sequence[RetrievedChunk],
        user_context: Optional[UserContext] = None,
        *,
        query: Optional[str] = None,
        baseline_documents: Optional[Sequence[RetrievedChunk]] = None,
    ) -> List[SecurityEvent]:
        events: List[SecurityEvent] = []
        for detector in (
            self.source_trust_detector,
            self.poisoned_document_detector,
            self.retrieval_authz_detector,
        ):
            # PoisonedDocumentDetector 扩展了 v1.2 语义离群路径，
            # 需要额外传 query / baseline；其它检测器维持两参数签名。
            if isinstance(detector, PoisonedDocumentDetector):
                sub_events = detector.detect(
                    list(documents),
                    user_context,
                    query=query,
                    baseline_docs=baseline_documents,
                )
            else:
                sub_events = detector.detect(list(documents), user_context)
            if not sub_events:
                sub_events = [self._low_risk_event(detector)]
            events.extend(sub_events)
        return events

    def run(
        self,
        *,
        user_input: Optional[str] = None,
        documents: Optional[Sequence[RetrievedChunk]] = None,
        user_context: Optional[UserContext] = None,
        baseline_documents: Optional[Sequence[RetrievedChunk]] = None,
    ) -> List[SecurityEvent]:
        """汇总输入阶段 + 检索阶段的全部风险事件。

        每个检测器始终产出一条事件：有命中时为真实风险事件，
        无命中时为低风险占位事件（risk_score≈0, confidence=0.9）。

        新增（v1.2）：`user_input` 会被作为 `query` 传给 PoisonedDocumentDetector
        的语义离群路径；`baseline_documents` 是已知干净语料样本，
        供"基线偏离"信号使用，未传入时该信号自动跳过。
        """
        events: List[SecurityEvent] = []
        if user_input:
            events.extend(self.check_input(user_input, user_context))
        if documents:
            events.extend(
                self.check_retrieval(
                    documents,
                    user_context,
                    query=user_input,
                    baseline_documents=baseline_documents,
                )
            )
        return events

    # 语义别名，方便按调用习惯使用
    scan = run
    check = run
