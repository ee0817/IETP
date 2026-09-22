# TODO: V0.1 极简测试版，仅用于接口联调。
# 后续 V1 版本将引入 PPL 困惑度检测、语义离群分数、NLI 一致性校验。

"""语义投毒检测模块（V0.1 极简测试版）。

不追求检出率，只追求跑通流程。不依赖任何外部模型或库，只用 Python 标准库。
"""

from __future__ import annotations

import uuid

from schemas import RetrievedChunk, SecurityEvent

# 每条规则的加分
_SCORE_LENGTH_ANOMALY = 0.3        # 长度异常
_SCORE_REPEATED_CHARS = 0.6        # 连续重复字符超过 20 个
_SCORE_SPECIAL_RATIO = 0.3         # 特殊字符占比超过 30%
_SCORE_METADATA_MISSING = 0.3      # metadata 为空且 source 为 unknown

# 常见标点（中英文），不视为特殊字符
_PUNCTUATION = set(
    ".,!?;:\"'()[]{}<>-—–…\n\r\t "
    "，。！？；：""''（）【】《》、…—"
)


def _is_normal_char(ch: str) -> bool:
    """判断字符是否为正常字符（字母、数字、汉字、标点、空白）。"""
    if ch.isalnum():
        return True
    if "\u4e00" <= ch <= "\u9fff":
        return True
    if ch in _PUNCTUATION:
        return True
    return False


def _max_consecutive_run(text: str) -> int:
    """计算 text 中最长连续重复字符的长度。"""
    if not text:
        return 0
    max_run = 1
    current_run = 1
    for i in range(1, len(text)):
        if text[i] == text[i - 1]:
            current_run += 1
            max_run = max(max_run, current_run)
        else:
            current_run = 1
    return max_run


def _special_char_ratio(text: str) -> float:
    """计算特殊字符（非字母、非汉字、非标点）占比。"""
    if not text:
        return 0.0
    special_count = sum(1 for ch in text if not _is_normal_char(ch))
    return special_count / len(text)


def check(chunk: RetrievedChunk, query: str = "") -> SecurityEvent:
    """对 chunk 执行语义投毒检测。

    用简单的启发式规则累加得分：
    1. 长度异常（< 10 或 > 5000）→ 加分
    2. 连续重复字符超过 20 个 → 加分
    3. 特殊字符占比超过 30% → 加分
    4. metadata 为空且 source 为 "unknown" → 加分

    得分 > 0.5 时 risk_type 为 "poisoned_document"，否则 "none"。

    Args:
        chunk: 待检测的检索分块。
        query: 用户原始查询（本版本暂未使用，保留签名以兼容 detector.py）。

    Returns:
        SecurityEvent：risk_score 为累加得分（0.0~1.0）。
    """
    content = chunk.content or ""
    score = 0.0

    # 规则 1：长度异常
    if len(content) < 10 or len(content) > 5000:
        score += _SCORE_LENGTH_ANOMALY

    # 规则 2：连续重复字符超过 20 个
    if _max_consecutive_run(content) > 20:
        score += _SCORE_REPEATED_CHARS

    # 规则 3：特殊字符占比超过 30%
    if _special_char_ratio(content) > 0.3:
        score += _SCORE_SPECIAL_RATIO

    # 规则 4：metadata 为空字典且 source 为 "unknown"
    if not chunk.metadata and chunk.source == "unknown":
        score += _SCORE_METADATA_MISSING

    # 得分限制在 0.0~1.0
    score = max(0.0, min(1.0, score))

    if score > 0.5:
        risk_type = "poisoned_document"
        confidence = 0.7
    else:
        risk_type = "none"
        confidence = 0.9

    return SecurityEvent(
        event_id=uuid.uuid4().hex,
        chunk_id=chunk.chunk_id,
        stage="retrieval",
        risk_score=score,
        risk_type=risk_type,
        confidence=confidence,
    )
