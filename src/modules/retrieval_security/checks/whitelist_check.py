"""白名单检测模块。

只检查 chunk.source，从 config/whitelist.yaml 读取规则，支持三种匹配：
1. domain_suffix：域名后缀匹配（带边界校验，防绕过）
2. url_prefix：URL 前缀匹配
3. exact：精确匹配

命中则放行（risk_score=0.0, risk_type="none", confidence=1.0）。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

# 配置文件路径
_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "whitelist.yaml"


class WhitelistResult(tuple):
    """白名单匹配结果，继承 tuple 以兼容 (bool, str) 解包。

    重写 __bool__ 使其在布尔上下文（如 detector.py 的 `if is_whitelisted(...)`）
    中表现为命中标志，避免非空 tuple 恒为 True 的问题。
    """

    def __new__(cls, hit: bool, reason: str) -> "WhitelistResult":
        return super().__new__(cls, (hit, reason))

    def __bool__(self) -> bool:
        return self[0]


def _load_rules() -> list[dict[str, Any]]:
    """从 config/whitelist.yaml 加载白名单规则。"""
    if not _CONFIG_PATH.exists():
        return []
    with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data.get("rules", []) or []


def _extract_domain(source: str) -> str:
    """从 source 中提取域名（netloc），用于 domain_suffix 匹配。

    若 source 不含 scheme（纯域名），直接返回。
    """
    if "://" not in source:
        return source
    try:
        parsed = urlparse(source)
        return parsed.netloc or source
    except Exception:  # noqa: BLE001
        return source


def is_whitelisted(source: str) -> WhitelistResult:
    """检查 source 是否命中白名单。

    Args:
        source: RetrievedChunk.source

    Returns:
        WhitelistResult，即 (是否命中, 命中的规则描述)。
        source 为 "unknown" 或空字符串时直接返回 (False, "")。
    """
    # source 为 "unknown" 或空字符串，直接视为未命中
    if not source or source == "unknown":
        return WhitelistResult(False, "")

    norm = source.strip().lower()
    domain = _extract_domain(source).strip().lower()

    for rule in _load_rules():
        rule_type = (rule.get("type") or "").strip()
        value = (rule.get("value") or "").strip().lower()
        note = rule.get("note", "")
        if not value:
            continue

        if rule_type == "domain_suffix":
            # 域名后缀匹配：带边界校验，防止 internal.company.com.evil.com 绕过
            if domain == value or domain.endswith("." + value):
                return WhitelistResult(True, f"domain_suffix: {value} ({note})")

        elif rule_type == "url_prefix":
            # URL 前缀匹配
            if norm.startswith(value):
                return WhitelistResult(True, f"url_prefix: {value} ({note})")

        elif rule_type == "exact":
            # 精确匹配
            if norm == value:
                return WhitelistResult(True, f"exact: {value} ({note})")

    return WhitelistResult(False, "")
