# -*- coding: utf-8 -*-
"""Llama Prompt Guard 2 22M 可选增强检测器（需 transformers + torch）。

设计约束：
- 遵循 BaseDetector 接口，输出统一 SecurityEvent（stage=input,
  risk_type=prompt_injection），不做任何流程控制；
- 模型 / 依赖 / 网络任一环节失败都只标记 available=False，detect 恒返回 None，
  绝不抛异常，调用方（input_guard）据此降级为纯规则结果；
- 推理放在 _infer，便于测试时替换为固定分数。

已知局限（2026-09 核实）：
- 项目内 ModelScope 快照 LLM-Research--Llama-Prompt-Guard-2-22M 只有
  **二分类 injection 头**（0=benign, 1=attack），**不含 jailbreak 头**。
  因此 DAN、角色扮演等越狱诱导（如 "You are DAN, do anything now"）
  不会被本检测器识别为攻击；此类样本目前只能依赖规则正则
  （en_dan / zh_role_play 等）兜底。
- 官方 meta-llama/Prompt-Guard-2-22M 为三分类头（benign/injection/jailbreak），
  代码已按 num_labels/id2label 动态解析攻击列，两种头均可加载。
- 后续如需补齐越狱检测，方案二选一（v1.1+ 再做）：
  1) 下载官方三分类权重替换本地快照，_attack_indices 会自动变为 (1, 2)；
  2) 新增独立的 jailbreak 检测模型（配置占位见 config.PROMPT_GUARD_HF_MODEL_ID
     附近），本类再扩展一个并列检测器。
"""
from __future__ import annotations

import logging
from typing import Any, Optional, Tuple

from ..base import BaseDetector
from ..schemas import RiskType, SecurityStage
from ..scoring import make_event

logger = logging.getLogger(__name__)

# 官方 meta-llama/Prompt-Guard-2-22M 三分类头：0=benign, 1=injection, 2=jailbreak；
# 社区二分类快照（如 ModelScope LLM-Research）只有单头：0=benign, 1=attack。
# 实际取哪些列在模型加载后依据 num_labels / id2label 动态确定。
_ATTACK_LABEL_KEYWORDS = ("injection", "jailbreak", "attack", "malicious", "harmful")
MAX_INPUT_TOKENS = 512


class PromptGuardDetector(BaseDetector):
    """基于 Llama Prompt Guard 2 22M 的注入概率检测（可选增强）。

    未安装 transformers/torch、模型加载失败或推理异常时 available=False，
    detect 返回 None；risk_score / confidence 由 make_event 统一截断到 3 位小数。
    注意：当前本地快照仅含 injection 头，不能识别 jailbreak（见模块文档）。
    """

    name = "prompt_guard_detector"
    stage = SecurityStage.INPUT

    def __init__(self, config: Any = None) -> None:
        super().__init__(config)
        self.available = False
        self.load_error: str = ""
        self._attack_indices: Tuple[int, ...] = ()
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
            from transformers import (  # 延迟导入：未安装时不影响规则路径
                AutoModelForSequenceClassification,
                AutoTokenizer,
            )

            model_id = self.config.prompt_guard_model_id
            local_files_only = bool(
                getattr(self.config, "prompt_guard_local_files_only", False)
            )
            self._tokenizer = AutoTokenizer.from_pretrained(
                model_id, local_files_only=local_files_only
            )
            self._model = AutoModelForSequenceClassification.from_pretrained(
                model_id, local_files_only=local_files_only
            )
            self._model.eval()
            self._attack_indices = self._resolve_attack_indices()
            self.available = True
            logger.info(
                "Prompt Guard 模型加载成功: %s (attack_indices=%s)",
                model_id,
                self._attack_indices,
            )
        except Exception as exc:  # 依赖缺失 / 网络失败 / 模型不存在等
            self.available = False
            self.load_error = f"{type(exc).__name__}: {exc}"
            logger.warning("Prompt Guard 模型不可用，已降级为规则路径: %s", self.load_error)

    @staticmethod
    def _resolve_attack_indices_from_config(model_config: Any) -> Tuple[int, ...]:
        """依据 id2label / num_labels 确定"攻击类"概率所在的列索引。

        - id2label 可读时：选择标签名含 injection/jailbreak/attack 等关键词的列；
        - 无标签信息：2 类头取列 1；3 类头取列 1、2；其他取除列 0 外全部列。
        """
        id2label = dict(getattr(model_config, "id2label", None) or {})
        matched = tuple(
            int(i)
            for i, label in id2label.items()
            if any(k in str(label).lower() for k in _ATTACK_LABEL_KEYWORDS)
        )
        if matched:
            return matched
        num_labels = int(getattr(model_config, "num_labels", 2) or 2)
        if num_labels == 2:
            return (1,)
        if num_labels == 3:
            return (1, 2)
        return tuple(range(1, num_labels))

    def _resolve_attack_indices(self) -> Tuple[int, ...]:
        num_labels = int(getattr(self._model.config, "num_labels", 2) or 2)
        indices = self._resolve_attack_indices_from_config(self._model.config)
        # 越界保护：保证所有索引都在合法范围内
        return tuple(i for i in indices if 0 <= i < num_labels)

    # ---------------------------------------------------------------- 推理

    def _infer(self, text: str) -> Tuple[float, float]:
        """返回 (攻击概率, 最高类别概率)，仅在 available=True 时调用。

        攻击概率 = 各攻击列（injection / jailbreak / attack）概率之和；
        最高类别概率作为检测置信度。列索引按模型实际类别数动态确定，
        兼容官方三分类头与社区二分类头。
        """
        import torch

        inputs = self._tokenizer(
            text, return_tensors="pt", truncation=True, max_length=MAX_INPUT_TOKENS
        )
        with torch.no_grad():
            logits = self._model(**inputs).logits
        probs = logits.softmax(dim=-1)[0]
        attack_indices = self._attack_indices or (1,)
        attack_score = float(sum(probs[i] for i in attack_indices if i < len(probs)))
        top_class_prob = float(probs.max())
        return attack_score, top_class_prob

    # ---------------------------------------------------------------- 检测

    def detect(self, payload: Any, context: Any = None) -> Optional[Any]:
        """不可用 / 空文本 / 阈值以下 / 推理异常 -> 返回 None（绝不抛异常）。"""
        if not self.available:
            return None
        text = str(payload or "")
        if not text.strip():
            return None

        try:
            injection_score, top_class_prob = self._infer(text)
        except Exception as exc:
            logger.warning("Prompt Guard 推理失败，本次返回 None: %s", exc)
            return None

        threshold = float(self.config.prompt_guard_threshold)
        if injection_score < threshold:
            return None

        return make_event(
            self.stage,
            RiskType.PROMPT_INJECTION,
            injection_score,
            top_class_prob,
            detector_name=self.name,
            evidence=[
                f"Prompt Guard 模型判定: injection_score={injection_score:.3f} "
                f">= threshold={threshold}"
            ],
        )
