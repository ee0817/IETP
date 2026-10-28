# TODO: V0.1 极简测试版，仅用于接口联调。
# 后续 V1 版本将引入真正的 NLI 模型（如 DeBERTa-MNLI），做 query-premise-hypothesis 的三分类。

"""上下文相关性过滤模块（V0.1 极简测试版）。

用简单的词汇重叠度（Jaccard 相似度）判断 query 和 content 的相关性。
不依赖任何外部模型或库，只用 Python 标准库。
"""

from __future__ import annotations

import uuid

from schemas import RetrievedChunk, SecurityEvent

# 相关性阈值：Jaccard 相似度低于该值视为不相关
_RELEVANCE_THRESHOLD = 0.1

# 不相关时的风险分与置信度
_IRRELEVANT_RISK_SCORE = 0.6
_IRRELEVANT_CONFIDENCE = 0.5


def _tokenize(text: str) -> set[str]:
    """将文本切分为词集合。

    - 中文按字符切分（降级方案）。
    - 英文/数字等非中文字符按空白与中文边界切分为词。
    - 统一转小写。
    """
    tokens: set[str] = set()
    current: list[str] = []
    for ch in text.lower():
        if "\u4e00" <= ch <= "\u9fff":
            # 中文字符：先刷新当前词，再以单字为 token
            if current:
                tokens.add("".join(current))
                current = []
            tokens.add(ch)
        elif ch.isspace():
            if current:
                tokens.add("".join(current))
                current = []
        else:
            current.append(ch)
    if current:
        tokens.add("".join(current))
    return tokens


def _jaccard_similarity(a: set[str], b: set[str]) -> float:
    """计算 Jaccard 相似度：交集大小 / 并集大小。"""
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


def check(chunk: RetrievedChunk, query: str) -> SecurityEvent:
    """对 chunk 执行上下文相关性过滤。

    用 query 与 content 的 Jaccard 词汇重叠度判断相关性：
    - query 为空：跳过检测，返回无风险。
    - 相似度 < 0.1：不相关，risk_type="suspicious_document"，risk_score=0.6。
    - 相似度 >= 0.1：相关，无风险。

    Args:
        chunk: 待检测的检索分块。
        query: 用户原始查询。

    Returns:
        SecurityEvent。
    """
    # query 为空，跳过检测，直接返回无风险
    if not query:
        return SecurityEvent(
            event_id=uuid.uuid4().hex,
            chunk_id=chunk.chunk_id,
            stage="retrieval",
            risk_score=0.0,
            risk_type="none",
            confidence=1.0,
        )

    content = chunk.content or ""
    query_tokens = _tokenize(query)
    content_tokens = _tokenize(content)

    similarity = _jaccard_similarity(query_tokens, content_tokens)

    if similarity < _RELEVANCE_THRESHOLD:
        # 完全不相关，可能误导 LLM
        return SecurityEvent(
            event_id=uuid.uuid4().hex,
            chunk_id=chunk.chunk_id,
            stage="retrieval",
            risk_score=_IRRELEVANT_RISK_SCORE,
            risk_type="suspicious_document",
            confidence=_IRRELEVANT_CONFIDENCE,
        )

    # 相关，无风险
    return SecurityEvent(
        event_id=uuid.uuid4().hex,
        chunk_id=chunk.chunk_id,
        stage="retrieval",
        risk_score=0.0,
        risk_type="none",
        confidence=1.0,
    )
