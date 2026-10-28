"""困惑度（PPL）模型（占位）。

V1 计划接入真实语言模型计算困惑度，用于投毒文本识别。
当前投毒检测由 checks/poisoning_check.py 的启发式规则实现，
本模块尚未启用，调用即抛 NotImplementedError，避免误以为已接入。
"""

from __future__ import annotations


def compute_perplexity(text: str) -> float:
    """返回文本困惑度。未实现。"""
    raise NotImplementedError(
        "ppl_model 为占位模块，V1 才接入真实语言模型；"
        "当前请使用 checks/poisoning_check.py 的启发式实现。"
    )
