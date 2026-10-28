"""公共数据适配器（占位）。

用于将外部系统的检索结果转换为 schemas.RetrievedChunk。
当前 detect() 已在入口显式校验必填字段（chunk_id/content/source/score/metadata），
公共 dataclass 版对象可直接传入，无需适配器；本模块保留给后续
格式差异更大的接入方使用，调用即抛 NotImplementedError。
"""

from __future__ import annotations

from typing import Any


def adapt(data: Any) -> Any:
    """将外部检索结果适配为 RetrievedChunk。未实现。"""
    raise NotImplementedError(
        "loca_adapter 为占位模块；公共对象若已具备 chunk_id/content/source/"
        "score/metadata 字段，可直接传入 detect()。"
    )
