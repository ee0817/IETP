# -*- coding: utf-8 -*-
"""输入阶段检测（input_guard）。

包含三个独立检测器，均可单独使用：
1. PromptInjectionDetector   —— prompt injection 检测（规则版 + 可选模型增强）
2. MaliciousIntentDetector   —— 规则版恶意意图关键词检测
3. AccessControlDetector     —— 请求侧越权检测（基于角色-资源权限矩阵）

只输出 SecurityEvent（无风险返回 None），不做任何流程控制。
"""
from __future__ import annotations

import re
from typing import Any, List, Optional, Tuple

from .base import BaseDetector
from .config import ADMIN_ONLY_RESOURCES
from .schemas import RiskType, SecurityStage, UserContext
from .scoring import (
    evidence_snippet,
    hit_confidence,
    make_event,
    noisy_or,
    scan_keywords,
    scan_patterns,
)

# 强证据权重门槛：命中权重 >= 该值的规则可直接确认注入
STRONG_WEIGHT = 0.75


class PromptInjectionDetector(BaseDetector):
    """prompt injection 检测：规则为主，Prompt Guard 模型仅增强弱信号。

    调用策略：
    - 规则强命中（强权重或综合分 >= injection_confirm）：直接确认，不调模型；
    - 弱信号且 prompt_guard_enabled：调用 Prompt Guard 复核，
      模型确认 -> 用模型事件；模型未确认或不可用 -> 降级为规则结果；
    - 开关关闭（默认）：纯规则路径，与 v1.0 行为完全一致。
    """

    name = "prompt_injection_detector"
    stage = SecurityStage.INPUT

    def __init__(self, config: Any = None) -> None:
        super().__init__(config)
        self._prompt_guard: Any = None  # 懒加载：仅在弱信号且开关开启时创建

    def _get_prompt_guard(self) -> Any:
        if self._prompt_guard is None:
            from .models.prompt_guard import PromptGuardDetector

            self._prompt_guard = PromptGuardDetector(self.config)
        return self._prompt_guard

    def detect(self, payload: Any, context: Any = None):
        text = str(payload or "")
        hits = scan_patterns(text, self.config.injection_rules)
        if not hits:
            return None

        weights = [h.rule.weight for h in hits]
        score = noisy_or(weights)
        top_weight = max(weights)
        has_strong = any(w >= STRONG_WEIGHT for w in weights)
        confidence = hit_confidence(top_weight, len(hits))
        evidence = [evidence_snippet(h.rule.label, h.text) for h in hits[:5]]

        # 规则强命中：直接确认，不调模型
        if has_strong or score >= self.config.thresholds.injection_confirm:
            return make_event(
                self.stage,
                RiskType.PROMPT_INJECTION,
                score,
                confidence,
                detector_name=self.name,
                evidence=evidence,
            )
        if score >= self.config.thresholds.injection_suspect:
            # 有可疑信号但证据不足：先产出规则结果（suspicious_input）
            weak_event = make_event(
                self.stage,
                RiskType.SUSPICIOUS_INPUT,
                score,
                confidence * 0.9,
                detector_name=self.name,
                evidence=evidence,
            )
            # 弱信号且开关开启：调 Prompt Guard 复核；不可用/未确认则降级为规则结果
            if not self.config.prompt_guard_enabled:
                return weak_event
            model_event = self._get_prompt_guard().detect(text, context)
            return model_event if model_event is not None else weak_event
        return None


class MaliciousIntentDetector(BaseDetector):
    """规则版恶意意图检测（关键词词表，按危害类别加权）。"""

    name = "malicious_intent_detector"
    stage = SecurityStage.INPUT

    def detect(self, payload: Any, context: Any = None):
        text = str(payload or "")
        hits = scan_keywords(text, self.config.malicious_keywords)
        if not hits:
            return None

        weights = [h.weight for h in hits]
        score = noisy_or(weights)
        if score < self.config.thresholds.intent_min:
            return None

        top_weight = max(weights)
        confidence = min(0.95, 0.60 + 0.35 * top_weight + 0.05 * (len(hits) - 1))
        evidence = [
            f"[{h.category}] 命中关键词: {h.keyword}" for h in hits[:5]
        ]
        return make_event(
            self.stage,
            RiskType.MALICIOUS_INTENT,  # TODO: 新增类型，接入前与团队统一命名
            score,
            confidence,
            detector_name=self.name,
            evidence=evidence,
        )


class AccessControlDetector(BaseDetector):
    """请求侧越权检测：抽取"动作 + 目标资源"，对照角色-资源权限矩阵判定。"""

    name = "access_control_detector"
    stage = SecurityStage.INPUT

    @staticmethod
    def _find_spans(text: str, keywords: List[str]) -> List[Tuple[int, int, str]]:
        spans: List[Tuple[int, int, str]] = []
        for keyword in keywords:
            for match in re.finditer(re.escape(keyword), text, re.IGNORECASE):
                spans.append((match.start(), match.end(), keyword))
        return spans

    def _extract_pairs(self, text: str) -> List[Tuple[str, str, int]]:
        """将邻近的动作关键词与资源关键词配对，返回 (action, resource, 间距)。"""
        action_spans: List[Tuple[int, int, str]] = []
        resource_spans: List[Tuple[int, int, str]] = []
        for action, kws in self.config.action_keywords.items():
            for start, end, _ in self._find_spans(text, kws):
                action_spans.append((start, end, action))
        for resource, kws in self.config.resource_keywords.items():
            for start, end, _ in self._find_spans(text, kws):
                resource_spans.append((start, end, resource))

        window = self.config.thresholds.pair_window
        pairs: List[Tuple[str, str, int]] = []
        seen = set()
        for r_start, r_end, resource in resource_spans:
            best = None
            for a_start, a_end, action in action_spans:
                if a_end <= r_start:
                    gap = r_start - a_end          # 动作在前，如"删除审计日志"
                elif r_end <= a_start:
                    gap = a_start - r_end          # 资源在前，如"审计日志给我删掉"
                else:
                    gap = 0                        # 区间重叠
                if gap <= window and (best is None or gap < best[1]):
                    best = (action, gap)
            if best is not None and (best[0], resource) not in seen:
                seen.add((best[0], resource))
                pairs.append((best[0], resource, best[1]))
        return pairs

    def _is_allowed(self, action: str, resource: str, roles: List[str]) -> bool:
        for role in roles or []:
            granted = self.config.role_matrix.get(role, {})
            if "*" in granted:  # 通配资源（admin 全权）
                return True
            actions = granted.get(resource)
            if actions is not None and ("*" in actions or action in actions):
                return True
        return False

    def detect(self, payload: Any, context: Any = None):
        text = str(payload or "")
        user: Optional[UserContext] = context if isinstance(context, UserContext) else None
        roles = user.roles if user else []

        denied: List[Tuple[str, str]] = []
        for action, resource, _gap in self._extract_pairs(text):
            if not self._is_allowed(action, resource, roles):
                denied.append((action, resource))
        if not denied:
            return None

        # 命中管理员专属资源 -> 权限提升；其余 -> 未授权访问
        risk_type = (
            RiskType.PRIVILEGE_ESCALATION  # TODO: 新增类型，接入前与团队统一命名
            if any(resource in ADMIN_ONLY_RESOURCES for _action, resource in denied)
            else RiskType.UNAUTHORIZED_ACCESS  # TODO: 新增类型，接入前与团队统一命名
        )
        role_text = "/".join(roles) if roles else "无角色"
        evidence = [
            f"角色[{role_text}] 缺少权限: {action} -> {resource}"
            for action, resource in denied[:5]
        ]
        return make_event(
            self.stage,
            risk_type,
            risk_score=0.85,
            confidence=0.88,
            detector_name=self.name,
            evidence=evidence,
        )
