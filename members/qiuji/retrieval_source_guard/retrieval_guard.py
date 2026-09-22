# -*- coding: utf-8 -*-
"""检索阶段检测（retrieval_guard，v1.0 重点）。

包含三个独立检测器，输入均为 List[RetrievedChunk]（可选 UserContext），
逐个文档产出事件并以列表返回：

1. SourceTrustDetector       —— 来源白名单 / 低可信来源上报（只上报，不丢弃文档）
2. PoisonedDocumentDetector  —— 投毒规则检测（文档内嵌注入指令）
3. RetrievalAuthzDetector    —— 检索侧越权检测（基于 metadata ACL / 密级标签）

只输出 SecurityEvent，不做任何流程控制。
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

from .base import BaseDetector
from .input_guard import STRONG_WEIGHT
from .schemas import RetrievedChunk, RiskType, SecurityStage, UserContext
from .scoring import (
    evidence_snippet,
    hit_confidence,
    make_event,
    noisy_or,
    scan_patterns,
)


def _as_documents(payload: Any) -> List[RetrievedChunk]:
    if payload is None:
        return []
    if isinstance(payload, RetrievedChunk):
        return [payload]
    return list(payload)


class SourceTrustDetector(BaseDetector):
    """来源白名单 / 低可信来源检测。

    遵循"未命中白名单不等于恶意"原则，三态判定：
    - 白名单命中 -> trust_status=TRUSTED，risk_score 低（≤0.1），不产出事件；
    - 白名单未命中 -> trust_status=UNKNOWN，risk_score 中性区间 0.1~0.2；
    - 黑名单命中 -> trust_status=BLOCKED，risk_score 高（0.9）。

    evidence 中明确标注 trust_status。本检测器只上报风险信号，
    不丢弃、不阻断、不改写检索结果，最终处置由 Policy Engine 决定。
    """

    name = "source_trust_detector"
    stage = SecurityStage.RETRIEVAL

    # UNKNOWN 中性区间的中位值（落在 0.1~0.2 之间）
    UNKNOWN_RISK_SCORE = 0.15
    # BLOCKED 高风险分
    BLOCKED_RISK_SCORE = 0.90

    def _match_level(self, doc: RetrievedChunk) -> Tuple[str, bool]:
        candidates = [doc.source or "unknown"]
        url = (doc.metadata or {}).get("url")
        if url:
            candidates.append(str(url))
        haystack = " ".join(candidates).lower()
        for needle, level in self.config.trust_sources:
            if needle and needle.lower() in haystack:
                return level, True
        return "unknown", False

    def _is_blacklisted(self, doc: RetrievedChunk) -> bool:
        """检查 source 是否命中黑名单（默认空，可配置扩展）。"""
        blacklist = getattr(self.config, "blacklisted_sources", set()) or set()
        if not blacklist:
            return False
        haystack = (doc.source or "unknown").lower()
        url = (doc.metadata or {}).get("url")
        if url:
            haystack = f"{haystack} {str(url).lower()}"
        for needle in blacklist:
            if needle and needle.lower() in haystack:
                return True
        return False

    def detect_one(self, doc: RetrievedChunk) -> Optional[Any]:
        # 1. 黑名单优先：trust_status=BLOCKED，risk_score 高
        if self._is_blacklisted(doc):
            return make_event(
                self.stage,
                RiskType.LOW_TRUST_SOURCE,
                self.BLOCKED_RISK_SCORE,
                confidence=0.95,
                detector_name=self.name,
                evidence=[
                    f"trust_status=BLOCKED, source={doc.source or 'N/A'}, "
                    f"命中黑名单"
                ],
                chunk_id=doc.chunk_id,
            )

        # 2. 白名单匹配
        level, matched = self._match_level(doc)
        trust_score = self.config.trust_levels.get(
            level, self.config.trust_levels.get("unknown", 0.15)
        )
        # RetrievedChunk 显式携带 trust_score 时以其为准
        if doc.trust_score is not None:
            trust_score = float(doc.trust_score)

        if matched:
            # 3. 白名单命中 -> TRUSTED，risk_score 低（≤0.1），不产出事件
            #    （与 v1.0 行为一致：可信来源不产生事件）
            return None

        # 4. 白名单未命中 -> UNKNOWN，risk_score 中性区间 0.1~0.2
        #    "未命中白名单不等于恶意"，只作为中性风险信号上报
        return make_event(
            self.stage,
            RiskType.LOW_TRUST_SOURCE,  # TODO: 新增类型，接入前与团队统一命名
            self.UNKNOWN_RISK_SCORE,
            confidence=0.55,  # 未知来源：归属判断本身不确定
            detector_name=self.name,
            evidence=[
                f"trust_status=UNKNOWN, trust_score={trust_score:.2f}, "
                f"source={doc.source or 'N/A'}"
            ],
            chunk_id=doc.chunk_id,
        )

    def detect(self, payload: Any, context: Any = None) -> List[Any]:
        return [
            event
            for doc in _as_documents(payload)
            if (event := self.detect_one(doc)) is not None
        ]


class PoisonedDocumentDetector(BaseDetector):
    """知识库投毒检测：规则版（v1.0）+ 语义离群可选增强（v1.2）。

    调用策略：
    - 开关关闭（默认）：纯规则路径，与 v1.0 行为完全一致；
    - 开关开启且 encoder 可用：在规则事件之外**额外**跑一次语义离群，
      合并去重（同 chunk_id 取 risk_score 更高者）；不丢弃、不阻断、不改写检索结果；
    - 开关开启但 encoder 不可用 / encode 失败：静默降级为纯规则结果。
    """

    name = "poisoned_document_detector"
    stage = SecurityStage.RETRIEVAL

    def __init__(self, config: Any = None) -> None:
        super().__init__(config)
        self._encoder: Any = None  # 懒加载：仅在开关开启且首次需要时创建

    def _get_encoder(self) -> Any:
        if self._encoder is None:
            from .models.bge_m3 import BgeM3Encoder

            self._encoder = BgeM3Encoder(self.config)
        return self._encoder

    def detect_one(self, doc: RetrievedChunk) -> Optional[Any]:
        """v1.0 规则路径：复用注入正则扫描文档内容。"""
        hits = scan_patterns(doc.content or "", self.config.injection_rules)
        if not hits:
            return None

        weights = [h.rule.weight for h in hits]
        score = noisy_or(weights)
        top_weight = max(weights)
        has_strong = any(w >= STRONG_WEIGHT for w in weights)
        confidence = hit_confidence(top_weight, len(hits))
        evidence = [evidence_snippet(h.rule.label, h.text) for h in hits[:5]]

        if has_strong or score >= self.config.thresholds.injection_confirm:
            risk_type = RiskType.POISONED_DOCUMENT
        elif score >= self.config.thresholds.injection_suspect:
            risk_type = RiskType.MALICIOUS_CONTEXT
        else:
            return None

        return make_event(
            self.stage,
            risk_type,
            score,
            confidence,
            detector_name=self.name,
            evidence=evidence,
            chunk_id=doc.chunk_id,
        )

    def detect(
        self,
        payload: Any,
        context: Any = None,
        *,
        query: Optional[str] = None,
        baseline_docs: Optional[Sequence[RetrievedChunk]] = None,
    ) -> List[Any]:
        docs = _as_documents(payload)
        # 1. v1.0 规则路径（永远执行）
        rule_events: List[Any] = [
            ev for doc in docs if (ev := self.detect_one(doc)) is not None
        ]
        # 2. 语义离群路径（开关开启时；不可用/编码失败 -> 降级为规则结果）
        if not self.config.bge_m3_enabled:
            return rule_events
        semantic_event = None
        try:
            from .semantic import detect_semantic_outlier

            encoder = self._get_encoder()
            semantic_event = detect_semantic_outlier(
                query=query or "",
                docs=docs,
                baseline_docs=list(baseline_docs or []),
                encoder=encoder,
                threshold=float(self.config.bge_m3_outlier_threshold),
                config=self.config,
            )
        except Exception as exc:  # 任何异常都只记日志，不抛、不阻断
            import logging

            logging.getLogger(__name__).warning(
                "语义离群检测异常，本次降级为规则结果: %s", exc
            )
            return rule_events
        if semantic_event is None:
            return rule_events
        # 3. 合并去重：同 chunk_id 取 risk_score 更高者
        merged: Dict[str, Any] = {}
        for ev in rule_events + [semantic_event]:
            key = ev.chunk_id or ""
            if key not in merged or ev.risk_score > merged[key].risk_score:
                merged[key] = ev
        return list(merged.values())


class RetrievalAuthzDetector(BaseDetector):
    """检索侧越权检测：读取 metadata 中的 ACL / 密级标签与用户角色比对。"""

    name = "retrieval_authz_detector"
    stage = SecurityStage.RETRIEVAL

    def _required_roles(self, doc: RetrievedChunk) -> Tuple[Optional[List[str]], float, str]:
        """返回 (允许访问的角色列表, 置信度, 判定依据)。

        - 返回 [] 表示公开文档，任何人可访问；
        - 返回 None 表示文档未携带任何 ACL 信息，按开放处理（不产生事件）。
        """
        metadata = doc.metadata or {}

        acl = metadata.get("acl_roles")
        if isinstance(acl, list) and acl:
            return [str(r) for r in acl], 0.90, "metadata.acl_roles"

        classification = metadata.get("classification")
        if classification:
            allowed = self.config.classification_roles.get(str(classification).lower())
            if allowed is None:
                return [], 0.75, f"classification={classification}(公开)"
            if allowed:
                return list(allowed), 0.75, f"classification={classification}"
            return [], 0.75, f"classification={classification}"

        return None, 0.0, ""

    def detect_one(self, doc: RetrievedChunk, user: Optional[UserContext]) -> Optional[Any]:
        required, confidence, basis = self._required_roles(doc)
        # None = 未携带 ACL 信息（按开放处理）；[] = public 公开文档（任何人可访问）
        if not required:
            return None

        user_roles = user.roles if user else []
        if "admin" in user_roles or any(role in required for role in user_roles):
            return None

        role_text = "/".join(user_roles) if user_roles else "匿名"
        return make_event(
            self.stage,
            RiskType.UNAUTHORIZED_RETRIEVAL,  # TODO: 新增类型，接入前与团队统一命名
            risk_score=0.85,
            confidence=confidence,
            detector_name=self.name,
            evidence=[
                f"角色[{role_text}] 无权访问要求 {required} 的文档（依据 {basis}）"
            ],
            chunk_id=doc.chunk_id,
        )

    def detect(self, payload: Any, context: Any = None) -> List[Any]:
        user = context if isinstance(context, UserContext) else None
        return [
            event
            for doc in _as_documents(payload)
            if (event := self.detect_one(doc, user)) is not None
        ]
