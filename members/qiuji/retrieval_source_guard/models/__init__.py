# -*- coding: utf-8 -*-
"""可选模型增强层：v1.0 纯规则路径保持不变，模型仅作为弱信号增强。

- PromptGuardDetector：Llama Prompt Guard 2 22M 注入分类器（仅 injection 头，
  越狱诱导暂由规则正则兜底），详见 prompt_guard 模块文档；
- BgeM3Encoder：BAAI/bge-m3 dense 编码器，用于检索阶段语义离群检测，
  详见 bge_m3 模块文档。
"""
from .bge_m3 import BgeM3Encoder
from .prompt_guard import PromptGuardDetector

__all__ = ["BgeM3Encoder", "PromptGuardDetector"]
