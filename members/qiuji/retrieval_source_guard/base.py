# -*- coding: utf-8 -*-
"""检测器抽象基类：统一 detect 接口。

内部算法（规则 / 分类器 / LLM）可自由替换，对外接口保持一致：
detect(...) -> SecurityEvent 或 List[SecurityEvent]，不返回任何流程控制指令。
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, List, Optional, Union

from .config import GuardConfig, load_config
from .schemas import SecurityEvent, SecurityStage

# 输入检测器通常返回单条事件（无风险返回 None）；
# 文档级检测器对每个文档各产生一条事件，返回事件列表。
DetectResult = Optional[Union[SecurityEvent, List[SecurityEvent]]]


class BaseDetector(ABC):
    name: str = "base_detector"
    stage: SecurityStage = SecurityStage.INPUT

    def __init__(self, config: Optional[GuardConfig] = None) -> None:
        # 未显式传入时使用全局缓存配置（规则只在加载阶段编译一次）
        self.config = config or load_config()

    @abstractmethod
    def detect(self, payload: Any, context: Any = None) -> DetectResult:
        """对输入数据做风险检测，只输出 SecurityEvent，不做流程控制。"""
        raise NotImplementedError
