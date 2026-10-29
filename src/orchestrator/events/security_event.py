from dataclasses import dataclass
from enum import Enum
from datetime import datetime
import uuid
import math
from numbers import Real


class SecurityStage(Enum):
    """
    RAG流程阶段
    """

    INPUT = "input"

    RETRIEVAL = "retrieval"

    CONTEXT = "context"

    GENERATION = "generation"

    OUTPUT = "output"



@dataclass
class SecurityEvent:
    """
    安全事件统一数据结构

    所有检测模块最终输出这个格式
    """

    # 哪个阶段产生风险
    stage: SecurityStage

    # 风险分数 0-1
    risk_score: float

    # 风险类型
    risk_type: str

    # 检测可信度
    confidence: float


    # 自动生成
    event_id: str = None

    timestamp: str = None

    # Optional attribution; appended to preserve existing positional calls.
    chunk_id: str = None
    detector_name: str = None



    def __post_init__(self):

        if self.event_id is None:
            self.event_id = str(uuid.uuid4())


        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


        self.validate()

    def validate(self):
        """Validate again at ingestion because events remain mutable."""
        if not isinstance(self.stage, SecurityStage):
            raise ValueError("stage必须是SecurityStage枚举")
        for name in ("risk_score", "confidence"):
            value = getattr(self, name)
            if (isinstance(value, bool) or not isinstance(value, Real)
                    or not math.isfinite(value) or not 0 <= value <= 1):
                raise ValueError(name + "必须是0和1之间的有限数值")
        for name in ("risk_type", "event_id", "timestamp"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(name + "必须是非空字符串")

        for name in ("chunk_id", "detector_name"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise ValueError(name + "必须是非空字符串或None")

    def to_dict(self):

        return {

            "event_id":
                self.event_id,

            "stage":
                self.stage.value,

            "risk_score":
                self.risk_score,

            "risk_type":
                self.risk_type,

            "confidence":
                self.confidence,

            "timestamp":
                self.timestamp,

            "chunk_id": self.chunk_id,
            "detector_name": self.detector_name
        }



    def __str__(self):

        return (
            f"[SecurityEvent] "
            f"stage={self.stage.value}, "
            f"risk={self.risk_score}, "
            f"type={self.risk_type}"
        )