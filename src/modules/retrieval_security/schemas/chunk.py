"""检索输出的 Chunk 数据模型。

使用 Python 标准库 dataclass（最新接口约定）。
字段：chunk_id、content、source、score、metadata。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class RetrievedChunk:
    """RAG 知识库检索输出的单个分块。

    必填字段：chunk_id、content、source、score、metadata。
    - source: 来源标识，没有来源时标 "unknown"。
    - score: 检索相关性分数（来自 Retriever），不是安全风险分。
    - metadata: 必须存在，允许空字典 {}；timestamp、tenant 为可选字段。
    """

    chunk_id: str
    content: str
    source: str
    score: float
    metadata: Dict[str, Any] = field(default_factory=dict)
