"""NLI 相关性模型（占位）。

V1 计划接入真实 NLI 模型（如交叉编码器）做 query-content 相关性判定。
当前相关性检测由 checks/relevance_check.py 的 Jaccard 词汇重叠实现，
本模块尚未启用，调用即抛 NotImplementedError，避免误以为已接入。
"""

from __future__ import annotations


def predict_entailment(query: str, content: str) -> float:
    """返回 query 与 content 的蕴含概率（0~1）。未实现。"""
    raise NotImplementedError(
        "nli_model 为占位模块，V1 才接入真实 NLI 模型；"
        "当前请使用 checks/relevance_check.py 的 Jaccard 实现。"
    )
