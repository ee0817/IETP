# -*- coding: utf-8 -*-
"""retrieval_source_guard：检索源头控制模块（v1.2 规则 + 可选模型增强）。

输入防御：prompt injection / 恶意意图 / 请求侧越权
检索源头防御：来源可信度上报 / 知识库投毒 / 检索侧越权
可选增强：Prompt Guard 2 22M 注入分类、BGE-M3 语义离群（默认关闭）

对外统一输出 SecurityEvent，不包含任何流程控制逻辑。
"""
from .base import BaseDetector
from .config import GuardConfig, load_config
from .input_guard import (
    AccessControlDetector,
    MaliciousIntentDetector,
    PromptInjectionDetector,
)
from .models import BgeM3Encoder, PromptGuardDetector
from .pipeline import SourceGuardPipeline
from .retrieval_guard import (
    PoisonedDocumentDetector,
    RetrievalAuthzDetector,
    SourceTrustDetector,
)
from .schemas import (
    RetrievedChunk,
    RiskType,
    SecurityEvent,
    SecurityStage,
    UserContext,
)
from .semantic import detect_semantic_outlier

__all__ = [
    "BaseDetector",
    "GuardConfig",
    "load_config",
    # 输入检测器
    "PromptInjectionDetector",
    "MaliciousIntentDetector",
    "AccessControlDetector",
    # 检索检测器
    "SourceTrustDetector",
    "PoisonedDocumentDetector",
    "RetrievalAuthzDetector",
    # 可选模型增强
    "BgeM3Encoder",
    "PromptGuardDetector",
    # 语义离群检测函数
    "detect_semantic_outlier",
    # 串联入口
    "SourceGuardPipeline",
    # 数据模型
    "SecurityEvent",
    "SecurityStage",
    "RiskType",
    "RetrievedChunk",
    "UserContext",
]

__version__ = "1.2.0"
