# -*- coding: utf-8 -*-
"""规则计分工具：正则编译、命中扫描、分数融合、置信度计算与事件构造。

- 正则在配置加载阶段一次性编译（见 config.load_config），运行期只做匹配；
- 多条规则命中采用 noisy-or 融合：score = 1 - Π(1 - w_i)；
- risk_score 与 confidence 分别计算，最终统一截断到 [0, 1]。
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, List, Optional, Sequence, Tuple

from .config import MaliciousKeyword
from .schemas import SecurityEvent, SecurityStage


def clamp01(value: Any) -> float:
    """强制截断到 [0, 1]，任何异常输入按 0.0 处理。"""
    try:
        value = float(value)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, min(1.0, value))


def noisy_or(weights: Sequence[float]) -> float:
    """多证据融合：任一强证据即可推高分，证据越多分越高。"""
    remain = 1.0
    for w in weights:
        remain *= 1.0 - clamp01(w)
    return clamp01(1.0 - remain)


@dataclass
class PatternRule:
    weight: float
    label: str
    pattern: str
    compiled: re.Pattern


@dataclass
class PatternHit:
    rule: PatternRule
    text: str
    start: int
    end: int


@dataclass
class KeywordHit:
    category: str
    weight: float
    keyword: str
    start: int
    end: int


def compile_rules(raw_rules: Sequence[Tuple[float, str, str]]) -> List[PatternRule]:
    """编译正则规则；非法正则跳过，不影响其余规则。"""
    rules: List[PatternRule] = []
    for weight, label, pattern in raw_rules:
        try:
            rules.append(
                PatternRule(
                    weight=clamp01(weight),
                    label=str(label),
                    pattern=str(pattern),
                    compiled=re.compile(pattern, re.IGNORECASE),
                )
            )
        except re.error:
            continue
    return rules


def scan_patterns(text: str, rules: Sequence[PatternRule]) -> List[PatternHit]:
    """返回全部命中的规则（每条规则取首个命中）。"""
    hits: List[PatternHit] = []
    for rule in rules:
        match = rule.compiled.search(text or "")
        if match:
            hits.append(PatternHit(rule, match.group(0), match.start(), match.end()))
    return hits


def scan_keywords(
    text: str, keywords: Sequence[MaliciousKeyword]
) -> List[KeywordHit]:
    """子串关键词扫描（大小写不敏感）。"""
    text_lower = (text or "").lower()
    hits: List[KeywordHit] = []
    for item in keywords:
        needle = item.keyword.lower()
        idx = text_lower.find(needle)
        if idx >= 0:
            hits.append(
                KeywordHit(item.category, item.weight, item.keyword, idx, idx + len(needle))
            )
    return hits


def hit_confidence(top_weight: float, hit_count: int) -> float:
    """依据最强证据权重与证据条数计算检测器置信度。"""
    return clamp01(0.55 + 0.40 * clamp01(top_weight) + 0.05 * (hit_count - 1))


def evidence_snippet(label: str, matched: str, limit: int = 60) -> str:
    matched = matched.replace("\n", " ").strip()
    if len(matched) > limit:
        matched = matched[:limit] + "..."
    return f"[{label}] {matched}"


def make_event(
    stage: SecurityStage,
    risk_type: str,
    risk_score: float,
    confidence: float,
    *,
    detector_name: Optional[str] = None,
    evidence: Optional[List[str]] = None,
    chunk_id: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> SecurityEvent:
    """统一事件构造入口，保证出参始终满足 SecurityEvent 约束。"""
    return SecurityEvent(
        stage=stage,
        risk_type=risk_type,
        risk_score=round(clamp01(risk_score), 3),
        confidence=round(clamp01(confidence), 3),
        detector_name=detector_name,
        evidence=evidence or [],
        chunk_id=chunk_id,
        timestamp=timestamp,
    )
