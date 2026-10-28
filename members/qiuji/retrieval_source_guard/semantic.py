# -*- coding: utf-8 -*-
"""语义离群投毒检测：BGE-M3 dense 向量 + 三信号加权融合。

三种信号：
1. **文档间 kNN**：文档与同批其它文档的 Top-K 相似度均值越低越孤立；
2. **查询偏离**：文档与查询的相似度越低越偏离用户意图（疑似注入内容）；
3. **基线偏离**：文档与已知干净语料的 Top-K 相似度均值越低越可疑。

任一信号因数据不足（文档数 <= K、无 baseline 等）跳过时，剩余权重自动归一化。
综合分 >= 阈值且对应文档是同批最离群者 -> 输出单条 poisoned_document 事件；
否则返回 None。事件由 make_event 统一截断到 3 位小数。

不丢弃、不阻断、不改写检索结果，只输出 SecurityEvent。
"""
from __future__ import annotations

import logging
import math
from typing import Any, List, Optional, Sequence, Tuple

from .schemas import RetrievedChunk, RiskType, SecurityEvent, SecurityStage
from .scoring import clamp01, make_event

logger = logging.getLogger(__name__)


# ----------------------------------------------------------------- 相似度计算


def _dot(a: List[float], b: List[float]) -> float:
    """两个已 L2 归一化向量的点积 == 余弦相似度。"""
    if len(a) != len(b):
        return 0.0
    return sum(x * y for x, y in zip(a, b))


def _mean_topk(similarities: List[float], k: int) -> float:
    """取相似度列表的 Top-K 均值；K <= 0 或列表空时返回 0.0。"""
    if not similarities:
        return 0.0
    if k <= 0:
        return 0.0
    # 降序取前 K 个
    top = sorted(similarities, reverse=True)[: min(k, len(similarities))]
    return sum(top) / len(top) if top else 0.0


# ----------------------------------------------------------------- 三信号实现


def _doc_knn_score(
    idx: int, doc_vecs: List[List[float]], k: int
) -> Tuple[float, Optional[str]]:
    """文档 idx 与同批其它文档的 Top-K 平均相似度 -> 离群分 = 1 - 均值。

    文档数 <= 1（无可比对象）或 k < 1 时跳过：返回 (0.0, None)。
    返回 (score, reason)；score=0 表示该信号无贡献。
    """
    n = len(doc_vecs)
    if n <= 1 or k < 1:
        return 0.0, None
    sims = [
        _dot(doc_vecs[idx], doc_vecs[j])
        for j in range(n)
        if j != idx and doc_vecs[j]
    ]
    if not sims:
        return 0.0, None
    mean_sim = _mean_topk(sims, k)
    return clamp01(1.0 - mean_sim), f"knn_mean_sim={mean_sim:.3f}"


def _query_deviation_score(
    doc_vec: List[float], query_vec: Optional[List[float]]
) -> Tuple[float, Optional[str]]:
    """文档与查询的相似度越低越偏离用户意图 -> 分 = 1 - 相似度。"""
    if not query_vec or not doc_vec:
        return 0.0, None
    sim = _dot(doc_vec, query_vec)
    return clamp01(1.0 - sim), f"query_sim={sim:.3f}"


def _baseline_deviation_score(
    doc_vec: List[float], baseline_vecs: List[List[float]], topk: int
) -> Tuple[float, Optional[str]]:
    """文档与基线 Top-K 的平均相似度越低越可疑 -> 分 = 1 - 均值。"""
    if not baseline_vecs or not doc_vec or topk < 1:
        return 0.0, None
    sims = [_dot(doc_vec, b) for b in baseline_vecs if b]
    if not sims:
        return 0.0, None
    mean_sim = _mean_topk(sims, topk)
    return clamp01(1.0 - mean_sim), f"baseline_topk_sim={mean_sim:.3f}"


# ----------------------------------------------------------------- 主入口


def detect_semantic_outlier(
    query: str,
    docs: Sequence[RetrievedChunk],
    baseline_docs: Sequence[RetrievedChunk],
    encoder: Any,
    threshold: float,
    *,
    config: Any = None,
) -> Optional[SecurityEvent]:
    """对 docs 跑三信号加权融合，输出**针对最离群文档**的单条事件。

    参数：
        query: 用户查询文本（用于"查询偏离"信号）；
        docs: 本批检索结果（非空）；
        baseline_docs: 已知干净语料样本（可空，空则跳过基线信号）；
        encoder: 任何带 encode(texts)->List[List[float]] 的对象；
                  available=False 或 encode 返回空 -> 直接返回 None；
        threshold: 综合离群分阈值，>= 该值判 poisoned_document；
        config: 用于读取三信号权重与 K 值；缺省时用全局 load_config()。

    返回：Optional[SecurityEvent]（stage=retrieval, risk_type=poisoned_document）。
    """
    if not docs:
        return None
    if encoder is None or not getattr(encoder, "available", False):
        return None  # 调用方据此降级为规则路径

    # 读取权重与 K（缺省时回退内置默认，保持函数可独立测试）
    if config is None:
        from .config import load_config

        config = load_config()
    w_knn = float(getattr(config, "bge_m3_weight_doc_knn", 0.40))
    w_query = float(getattr(config, "bge_m3_weight_query_deviation", 0.30))
    w_baseline = float(getattr(config, "bge_m3_weight_baseline_deviation", 0.30))
    k_knn = int(getattr(config, "bge_m3_doc_knn_k", 3))
    k_baseline = int(getattr(config, "bge_m3_baseline_topk", 5))

    # 编码：query + docs + baseline 一次性编码，减少调用次数
    doc_texts = [d.content or "" for d in docs]
    baseline_texts = [d.content or "" for d in baseline_docs]
    all_texts: List[str] = []
    if query:
        all_texts.append(query)
    all_texts.extend(doc_texts)
    all_texts.extend(baseline_texts)

    vecs = encoder.encode(all_texts)
    if not vecs or len(vecs) != len(all_texts):
        # 编码失败或返回长度不匹配：调用方据此降级
        logger.warning(
            "BGE-M3 编码返回长度异常（期望 %d，实际 %d），跳过语义离群",
            len(all_texts),
            len(vecs),
        )
        return None

    cursor = 0
    query_vec: Optional[List[float]] = None
    if query:
        query_vec = vecs[cursor]
        cursor += 1
    doc_vecs = vecs[cursor : cursor + len(doc_texts)]
    cursor += len(doc_texts)
    baseline_vecs = vecs[cursor : cursor + len(baseline_texts)]

    # 逐文档算三信号 + 加权融合（任一信号跳过则剩余权重归一化）
    per_doc: List[Tuple[int, float, List[str]]] = []  # (idx, score, evidence)
    for i, doc in enumerate(docs):
        dvec = doc_vecs[i] if i < len(doc_vecs) else []
        s_knn, r_knn = _doc_knn_score(i, doc_vecs, k_knn)
        s_query, r_query = _query_deviation_score(dvec, query_vec)
        s_base, r_base = _baseline_deviation_score(dvec, baseline_vecs, k_baseline)

        signals = [
            (s_knn, w_knn, r_knn, "doc_knn"),
            (s_query, w_query, r_query, "query_dev"),
            (s_base, w_baseline, r_base, "baseline_dev"),
        ]
        active = [(s, w, r, name) for s, w, r, name in signals if r is not None]
        if not active:
            continue
        total_w = sum(w for _, w, _, _ in active)
        if total_w <= 0:
            continue
        fused = sum(s * w for s, w, _, _ in active) / total_w
        fused = clamp01(fused)

        ev_bits: List[str] = []
        for s, w, r, name in active:
            ev_bits.append(f"{name}={s:.3f}(w={w / total_w:.2f}, {r})")
        per_doc.append((i, fused, ev_bits))

    if not per_doc:
        return None

    # 选综合分最高的文档作为离群代表
    per_doc.sort(key=lambda x: x[1], reverse=True)
    top_idx, top_score, top_evidence = per_doc[0]
    if top_score < float(threshold):
        return None

    doc = docs[top_idx]
    confidence = clamp01(0.55 + 0.40 * top_score)  # 离群分越高置信度越高
    return make_event(
        stage=SecurityStage.RETRIEVAL,
        risk_type=RiskType.POISONED_DOCUMENT,
        risk_score=top_score,
        confidence=confidence,
        detector_name="semantic_outlier_detector",
        evidence=[
            f"chunk_id={doc.chunk_id}, 综合离群分={top_score:.3f} >= 阈值={float(threshold):.3f}",
            *top_evidence,
        ],
        chunk_id=doc.chunk_id,
    )
