# -*- coding: utf-8 -*-
"""BGE-M3 语义编码器封装（需 transformers + torch，可选增强）。

设计约束：
- 仅提供 encode(texts) -> List[List[float]]，对外不暴露模型 / 分词器对象；
- 模型 / 依赖 / 网络任一环节失败都只标记 available=False，
  encode 恒返回空列表，绝不抛异常，调用方（retrieval_guard）据此降级为规则结果；
- 推理在 encode 内完成，便于测试时替换为假编码器（注入固定向量）。

BGE-M3 同时支持 dense / sparse / colbert 三种向量，本封装**仅用 dense**：
- 取 last_hidden_state[:, 0]（CLS token）做 mean-pooling 的等价简化；
- L2 归一化，使点积 == 余弦相似度，便于下游 cosine 计算。
"""
from __future__ import annotations

import logging
from typing import Any, List, Optional

from ..config import PACKAGE_DIR
from ..schemas import RetrievedChunk

logger = logging.getLogger(__name__)

# 与 Prompt Guard 保持一致的输入长度上限（BGE-M3 官方支持 8192，这里保守取 512）
MAX_INPUT_TOKENS = 512


class BgeM3Encoder:
    """BGE-M3 dense embedding 编码器（可选增强）。

    未安装 transformers/torch、模型加载失败或 encode 异常时 available=False，
    encode 返回 []；调用方应据此降级为纯规则结果，不抛异常。
    """

    def __init__(self, config: Any = None) -> None:
        # 兼容未显式传 config：用全局缓存配置（与 BaseDetector 行为一致）
        if config is None:
            from ..config import load_config

            config = load_config()
        self.config = config
        self.available = False
        self.load_error: str = ""
        self._tokenizer: Any = None
        self._model: Any = None
        self._load_model()

    # ---------------------------------------------------------------- 模型加载

    def _load_model(self) -> None:
        """尝试加载模型与分词器；任何失败都只标记不可用，不抛异常。

        local_files_only 透传给 from_pretrained：使用本地快照时强制 True，
        保证离线环境下绝不发起网络请求；模型路径为 HF 仓库 ID 时允许联网下载。
        """
        try:
            import torch  # noqa: F401  仅用于早期暴露 torch 缺失
            from transformers import AutoModel, AutoTokenizer

            model_path = self.config.bge_m3_model_path
            local_files_only = bool(
                getattr(self.config, "bge_m3_local_files_only", False)
            )
            self._tokenizer = AutoTokenizer.from_pretrained(
                model_path, local_files_only=local_files_only
            )
            self._model = AutoModel.from_pretrained(
                model_path, local_files_only=local_files_only
            )
            self._model.eval()
            self.available = True
            logger.info(
                "BGE-M3 模型加载成功: %s (local_files_only=%s)",
                model_path,
                local_files_only,
            )
        except Exception as exc:  # 依赖缺失 / 网络失败 / 模型不存在等
            self.available = False
            self.load_error = f"{type(exc).__name__}: {exc}"
            logger.warning("BGE-M3 模型不可用，已降级为规则路径: %s", self.load_error)

    # ---------------------------------------------------------------- 编码

    def encode(self, texts: List[str]) -> List[List[float]]:
        """对一批文本做 dense embedding，返回与输入同长度的向量列表。

        - available=False 或输入为空 -> 返回 []；
        - 推理异常 -> 记日志并返回 []（绝不抛异常，调用方据此降级）；
        - 向量已 L2 归一化，下游可直接用点积当余弦相似度。
        """
        if not self.available or not texts:
            return []
        try:
            import torch

            inputs = self._tokenizer(
                list(texts),
                padding=True,
                truncation=True,
                max_length=MAX_INPUT_TOKENS,
                return_tensors="pt",
            )
            with torch.no_grad():
                outputs = self._model(**inputs)
            # CLS pooling + L2 normalize：BGE-M3 dense 推荐取 CLS（位置 0）
            embeddings = outputs.last_hidden_state[:, 0]
            embeddings = torch.nn.functional.normalize(embeddings, p=2, dim=1)
            return embeddings.cpu().tolist()
        except Exception as exc:
            logger.warning("BGE-M3 编码失败，本次返回空列表: %s", exc)
            return []

    # ---------------------------------------------------------------- 便捷工具

    def encode_documents(self, docs: List[RetrievedChunk]) -> List[List[float]]:
        """对 RetrievedChunk 列表按 content 编码；不可用或异常时返回 []。"""
        texts = [d.content or "" for d in docs]
        return self.encode(texts)
