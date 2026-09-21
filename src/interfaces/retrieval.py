from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class RetrievedChunk:
    """Retrieval 安全模块 V1 的统一输入结构。"""

    chunk_id: str
    content: str
    source: str
    score: float
    metadata: Dict[str, Any] = field(default_factory=dict)
