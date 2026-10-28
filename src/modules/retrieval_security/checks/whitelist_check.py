"""白名单检测模块。

只检查 chunk.source，从 config/whitelist.yaml 读取规则，支持三种匹配：
1. domain_suffix：域名后缀匹配（带边界校验，防绕过）
2. url_prefix：URL 前缀匹配
3. exact：精确匹配

注意（PR3 修订）：白名单命中是"来源信任"信号，不等于内容免检。
detector.py 中注入检测与投毒检测始终执行；白名单命中仅跳过
相关性检测（适用条件：可信来源的内容默认与业务相关）。
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

# 配置文件路径
_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "whitelist.yaml"

# 规则缓存：启动后首次加载并缓存，避免每次检测都读盘；
# 也使运行时对配置文件的篡改不会在进程生命周期内静默生效（见 PR4 P0-2）。
# 生产环境应对 whitelist.yaml 做文件权限收敛 + 哈希签名校验。
_rules_cache: list[dict[str, Any]] | None = None
_rules_lock = threading.Lock()  # N5：与 reload_rules() 配套的读写同步


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
    """从 config/whitelist.yaml 加载白名单规则（带进程内缓存）。

    首次调用后缓存结果；reload_rules() 可强制重新加载（运维变更配置时使用）。
    """
    global _rules_cache
    if _rules_cache is not None:
        return _rules_cache
    with _rules_lock:
        # double-checked locking
        if _rules_cache is not None:
            return _rules_cache
        if not _CONFIG_PATH.exists():
            _rules_cache = []
            return _rules_cache
        with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        _rules_cache = data.get("rules", []) or []
        return _rules_cache


def reload_rules() -> None:
    """清空缓存并重新加载白名单规则（配置变更后显式调用）。"""
    global _rules_cache
    with _rules_lock:
        _rules_cache = None
    _load_rules()


def _extract_domain(source: str) -> str:
    """从 source 中提取主机名（hostname），用于 domain_suffix 匹配。

    使用 urlparse().hostname，自动剥离端口与用户信息：
    - "https://internal.company.com:8443/x" → "internal.company.com"
    - "https://internal.company.com@evil.com/" → "evil.com"（userinfo 绕过被阻断）
    若 source 不含 scheme（纯域名），直接返回。
    """
    if "://" not in source:
        return source
    try:
        parsed = urlparse(source)
        return parsed.hostname or source
    except Exception:  # noqa: BLE001
        return source


def _normalize_for_exact(url: str) -> str:
    """N4：exact 匹配用的归一化——仅对 scheme+host 小写化，path/query 保持原样。

    URL path 大小写敏感，整串 lowercase 会让 "Doc-001" 误配 "doc-001" 规则。
    """
    s = url.strip()
    if "://" not in s:
        return s
    try:
        p = urlparse(s)
        host = (p.hostname or "").lower()
        port = f":{p.port}" if p.port else ""
        rebuilt = f"{p.scheme.lower()}://{host}{port}{p.path}"
        if p.query:
            rebuilt += "?" + p.query
        return rebuilt
    except Exception:  # noqa: BLE001
        return s


def is_whitelisted(source: str) -> WhitelistResult:
    """检查 source 是否命中白名单。

    Args:
        source: RetrievedChunk.source（与公共接口字段名一致）

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
        raw_value = (rule.get("value") or "").strip()
        value = raw_value.lower()
        note = rule.get("note", "")
        if not value:
            continue

        if rule_type == "domain_suffix":
            # 域名后缀匹配：带边界校验，防止 internal.company.com.evil.com 绕过
            if domain == value or domain.endswith("." + value):
                return WhitelistResult(True, f"domain_suffix: {value} ({note})")

        elif rule_type == "url_prefix":
            # URL 前缀匹配。
            # N3 修复：边界校验——若规则值未以 '/'、'?'、'#' 结尾，
            # 要求命中后紧跟的字符必须是路径/查询分隔符，
            # 防止 "https://trusted.wiki.org" 误配 "https://trusted.wiki.org.evil.com"
            if norm.startswith(value):
                if value.endswith(("/", "?", "#")):
                    return WhitelistResult(True, f"url_prefix: {value} ({note})")
                nxt = norm[len(value) : len(value) + 1]
                if nxt in ("", "/", "?", "#"):
                    return WhitelistResult(True, f"url_prefix: {value} ({note})")

        elif rule_type == "exact":
            # 精确匹配：仅 host/scheme 归一化，path 大小写敏感（N4）
            if _normalize_for_exact(source) == _normalize_for_exact(raw_value):
                return WhitelistResult(True, f"exact: {raw_value} ({note})")

    return WhitelistResult(False, "")
