"""检索输出的 Chunk 数据模型。

使用 Pydantic BaseModel（联调阶段统一）。
字段：chunk_id、source_id、content、score、metadata。
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class RetrievedChunk(BaseModel):
    """RAG 知识库检索输出的单个分块。

    必填字段：chunk_id、source_id、content、score、metadata。
    - source_id: 来源标识，没有来源时标 "unknown"。
    - score: 检索相关性分数（来自 Retriever），不是安全风险分。
    - metadata: 必须存在，允许空字典 {}；timestamp、tenant 为可选字段。
    """

    chunk_id: str
    source_id: str
    content: str
    score: float
    metadata: dict[str, Any] = {}
