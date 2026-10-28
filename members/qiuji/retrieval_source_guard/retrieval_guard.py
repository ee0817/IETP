# -*- coding: utf-8 -*-
"""检索阶段检测（retrieval_guard，v1.0 重点）。

包含三个独立检测器，输入均为 List[RetrievedChunk]（可选 UserContext），
逐个文档产出事件并以列表返回：

1. SourceTrustDetector       —— 来源白名单 / 低可信来源上报（只上报，不丢弃文档）
2. PoisonedDocumentDetector  —— 投毒规则检测（文档内嵌注入指令）
3. RetrievalAuthzDetector    —— 检索侧越权检测（基于 metadata ACL / 密级标签）

只输出 SecurityEvent，不做任何流程控制。
"""
from __future__ import annotations

from urllib.parse import urlparse
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .base import BaseDetector
from .input_guard import STRONG_WEIGHT
from .schemas import RetrievedChunk, RiskType, SecurityStage, UserContext, UserContextAdapter
from .scoring import (
    evidence_snippet,
    hit_confidence,
    make_event,
    noisy_or,
    scan_patterns,
)


def _as_documents(payload: Any) -> List[RetrievedChunk]:
    if payload is None:
        return []
    if isinstance(payload, RetrievedChunk):
        return [payload]
    return list(payload)


class SourceTrustDetector(BaseDetector):
    """来源白名单 / 低可信来源检测。

    遵循"未命中白名单不等于恶意"原则，三态判定：
    - 白名单命中 -> trust_status=TRUSTED，risk_score 低（≤0.1），不产出事件；
    - 白名单未命中 -> trust_status=UNKNOWN，risk_score 中性区间 0.1~0.2；
    - 黑名单命中 -> trust_status=BLOCKED，risk_score 高（0.9）。

    域名匹配安全策略（已替换原裸子串匹配）：
    - 用 urlparse 从 source 提取 hostname，禁止裸子串匹配（防域名仿真如 corp.evil.com）；
    - 精确 hostname 匹配 + 点边界子域名匹配（wiki.corp.example.com 匹配 corp.example.com）；
    - metadata.url 仅作 source 无可用 hostname 时的兜底，优先级低于 source；
    - 无解析 hostname 时退化为整个 source 的精确相等比较（仍禁止裸子串）。

    evidence 中明确标注 trust_status。本检测器只上报风险信号，
    不丢弃、不阻断、不改写检索结果，最终处置由 Policy Engine 决定。
    """

    name = "source_trust_detector"
    stage = SecurityStage.RETRIEVAL

    # UNKNOWN 中性区间的中位值（落在 0.1~0.2 之间）
    UNKNOWN_RISK_SCORE = 0.15
    # BLOCKED 高风险分
    BLOCKED_RISK_SCORE = 0.90

    # ------------------------------------------------ 域名解析与匹配工具

    @staticmethod
    def _extract_hostname(value: str) -> Optional[str]:
        """从字符串提取 hostname。

        优先用 urlparse 解析完整 URL；无 scheme 时自动补 https:// 再解析；
        最后兜底：形如 hostname（含点、不含斜杠/空格/冒号）则直接返回。
        解析失败或无明显 hostname 返回 None。
        """
        if not value:
            return None
        v = str(value).strip()
        # 1) 有 scheme 的完整 URL
        try:
            parsed = urlparse(v)
            if parsed.hostname:
                return parsed.hostname.lower()
        except Exception:
            pass
        # 2) 无 scheme：补 https:// 再试
        if not v.startswith(("http://", "https://", "//")):
            try:
                parsed = urlparse(f"https://{v}")
                if parsed.hostname:
                    return parsed.hostname.lower()
            except Exception:
                pass
        # 3) 裸 hostname：含点、无斜杠/空格/冒号
        if "." in v and "/" not in v and " " not in v and ":" not in v:
            return v.lower().rstrip(".")
        return None

    @staticmethod
    def _match_hostname(hostname: str, needle: str) -> bool:
        """hostname 匹配：精确相等 或 点边界子域名后缀。

        - 精确：wiki.corp == wiki.corp
        - 子域名：wiki.corp.example.com 匹配 corp.example.com（因为前者以
          ".corp.example.com" 结尾，点边界保证不是 corp.evil.example.com）
        - 点边界：corp.evil.com 不匹配 corp.gov.cn（既不相等也不后缀）
        """
        if not hostname or not needle:
            return False
        h = hostname.lower().rstrip(".")
        n = needle.lower().rstrip(".")
        if h == n:
            return True
        # 点边界子域名后缀：h 以 "." + n 结尾
        if h.endswith("." + n):
            return True
        return False

    def _hostnames_from_doc(self, doc: RetrievedChunk) -> List[str]:
        """按优先级提取候选 hostname 列表：source > metadata.url（兜底）。

        metadata.url 只在 source 未提供可用 hostname 时才尝试，
        因为 metadata.url 可能来自不可信内容（如页面内嵌入链接）。
        """
        hostnames: List[str] = []
        source = doc.source or ""
        h = self._extract_hostname(source)
        if h:
            hostnames.append(h)
        # metadata.url 兜底（仅当 source 没有 hostname 时）
        if not hostnames:
            url = (doc.metadata or {}).get("url")
            if url:
                h = self._extract_hostname(str(url))
                if h:
                    hostnames.append(h)
        return hostnames

    # ------------------------------------------------ 白名单 / 黑名单匹配

    def _match_level(self, doc: RetrievedChunk) -> Tuple[str, bool]:
        """安全域名匹配：精确 hostname 或点边界子域名，禁止裸子串。

        无可用 hostname 时退化为整个 source 精确相等比较（仍无裸子串）。
        """
        hostnames = self._hostnames_from_doc(doc)
        if hostnames:
            for hostname in hostnames:
                for needle, level in self.config.trust_sources:
                    if needle and self._match_hostname(hostname, needle):
                        return level, True
        else:
            # 无 hostname：source 全文精确相等（仍禁止裸子串）
            source_text = (doc.source or "").lower()
            for needle, level in self.config.trust_sources:
                if needle and needle.lower() == source_text:
                    return level, True
        return "unknown", False

    def _is_blacklisted(self, doc: RetrievedChunk) -> bool:
        """黑名单匹配：同白名单安全策略，用 hostname + 点边界匹配。"""
        blacklist = getattr(self.config, "blacklisted_sources", set()) or set()
        if not blacklist:
            return False
        hostnames = self._hostnames_from_doc(doc)
        if hostnames:
            for hostname in hostnames:
                for needle in blacklist:
                    if needle and self._match_hostname(hostname, needle):
                        return True
        else:
            source_text = (doc.source or "").lower()
            for needle in blacklist:
                if needle and needle.lower() == source_text:
                    return True
        return False

    def check_trust(self, doc: RetrievedChunk) -> Any:
        """结构化信任判定：三态均返回 TrustResult，供编排层直接消费。

        返回 TrustResult(source_id, trust_status, trust_score, reason)：
        - 黑名单命中   -> TrustStatus.BLOCKED，trust_score=0.0；
        - 白名单命中   -> TrustStatus.TRUSTED，trust_score=对应级别分；
        - 白名单未命中 -> TrustStatus.UNKNOWN，trust_score=级别分或 doc 显式携带值。
        """
        from .schemas import TrustResult, TrustStatus

        source_id = doc.source or "unknown"
        # 黑名单优先
        if self._is_blacklisted(doc):
            return TrustResult(
                source_id=source_id,
                trust_status=TrustStatus.BLOCKED,
                trust_score=0.0,
                reason="命中黑名单",
            )
        # 白名单匹配
        level, matched = self._match_level(doc)
        trust_score = self.config.trust_levels.get(
            level, self.config.trust_levels.get("unknown", 0.15)
        )
        # RetrievedChunk 显式携带 trust_score 时以其为准；
        # 用 getattr 兼容公共接口 RetrievedChunk（无 trust_score 字段）
        explicit = getattr(doc, "trust_score", None)
        if explicit is not None:
            trust_score = float(explicit)
        if matched:
            return TrustResult(
                source_id=source_id,
                trust_status=TrustStatus.TRUSTED,
                trust_score=trust_score,
                reason=f"白名单命中 level={level}",
            )
        return TrustResult(
            source_id=source_id,
            trust_status=TrustStatus.UNKNOWN,
            trust_score=trust_score,
            reason="未命中白名单（不等于恶意）",
        )

    def detect_one(self, doc: RetrievedChunk) -> Optional[Any]:
        from .schemas import TrustStatus

        result = self.check_trust(doc)

        # 1. BLOCKED：高风险事件
        if result.trust_status == TrustStatus.BLOCKED:
            return make_event(
                self.stage,
                RiskType.LOW_TRUST_SOURCE,
                self.BLOCKED_RISK_SCORE,
                confidence=0.95,
                detector_name=self.name,
                evidence=[
                    f"trust_status=BLOCKED, source={result.source_id}, {result.reason}"
                ],
                chunk_id=doc.chunk_id,
                details={
                    "trust_status": result.trust_status.value,
                    "trust_score": result.trust_score,
                    "source_id": result.source_id,
                    "reason": result.reason,
                },
            )

        # 2. TRUSTED：不是风险，不产出风险事件；
        #    结构化信任结果经 check_trust() 交付编排层
        if result.trust_status == TrustStatus.TRUSTED:
            return None

        # 3. UNKNOWN：中性区间 0.1~0.2，"未命中白名单不等于恶意"
        return make_event(
            self.stage,
            RiskType.LOW_TRUST_SOURCE,  # TODO: 新增类型，接入前与团队统一命名
            self.UNKNOWN_RISK_SCORE,
            confidence=0.55,  # 未知来源：归属判断本身不确定
            detector_name=self.name,
            evidence=[
                f"trust_status=UNKNOWN, trust_score={result.trust_score:.2f}, "
                f"source={result.source_id}"
            ],
            chunk_id=doc.chunk_id,
            details={
                "trust_status": result.trust_status.value,
                "trust_score": result.trust_score,
                "source_id": result.source_id,
                "reason": result.reason,
            },
        )

    def detect(self, payload: Any, context: Any = None) -> List[Any]:
        return [
            event
            for doc in _as_documents(payload)
            if (event := self.detect_one(doc)) is not None
        ]


class PoisonedDocumentDetector(BaseDetector):
    """知识库投毒检测：规则版（v1.0）+ 语义离群可选增强（v1.2）。

    调用策略：
    - 开关关闭（默认）：纯规则路径，与 v1.0 行为完全一致；
    - 开关开启且 encoder 可用：在规则事件之外**额外**跑一次语义离群，
      合并去重（同 chunk_id 取 risk_score 更高者）；不丢弃、不阻断、不改写检索结果；
    - 开关开启但 encoder 不可用 / encode 失败：静默降级为纯规则结果。
    """

    name = "poisoned_document_detector"
    stage = SecurityStage.RETRIEVAL

    def __init__(self, config: Any = None) -> None:
        super().__init__(config)
        self._encoder: Any = None  # 懒加载：仅在开关开启且首次需要时创建

    def _get_encoder(self) -> Any:
        if self._encoder is None:
            from .models.bge_m3 import BgeM3Encoder

            self._encoder = BgeM3Encoder(self.config)
        return self._encoder

    def detect_one(self, doc: RetrievedChunk) -> Optional[Any]:
        """v1.0 规则路径：复用注入正则扫描文档内容。"""
        hits = scan_patterns(doc.content or "", self.config.injection_rules)
        if not hits:
            return None

        weights = [h.rule.weight for h in hits]
        score = noisy_or(weights)
        top_weight = max(weights)
        has_strong = any(w >= STRONG_WEIGHT for w in weights)
        confidence = hit_confidence(top_weight, len(hits))
        evidence = [evidence_snippet(h.rule.label, h.text) for h in hits[:5]]

        if has_strong or score >= self.config.thresholds.injection_confirm:
            risk_type = RiskType.POISONED_DOCUMENT
        elif score >= self.config.thresholds.injection_suspect:
            risk_type = RiskType.MALICIOUS_CONTEXT
        else:
            return None

        return make_event(
            self.stage,
            risk_type,
            score,
            confidence,
            detector_name=self.name,
            evidence=evidence,
            chunk_id=doc.chunk_id,
        )

    def detect(
        self,
        payload: Any,
        context: Any = None,
        *,
        query: Optional[str] = None,
        baseline_docs: Optional[Sequence[RetrievedChunk]] = None,
    ) -> List[Any]:
        docs = _as_documents(payload)
        # 1. v1.0 规则路径（永远执行）
        rule_events: List[Any] = [
            ev for doc in docs if (ev := self.detect_one(doc)) is not None
        ]
        # 2. 语义离群路径（开关开启时；不可用/编码失败 -> 降级为规则结果）
        if not self.config.bge_m3_enabled:
            return rule_events
        semantic_event = None
        try:
            from .semantic import detect_semantic_outlier

            encoder = self._get_encoder()
            semantic_event = detect_semantic_outlier(
                query=query or "",
                docs=docs,
                baseline_docs=list(baseline_docs or []),
                encoder=encoder,
                threshold=float(self.config.bge_m3_outlier_threshold),
                config=self.config,
            )
        except Exception as exc:  # 任何异常都只记日志，不抛、不阻断
            import logging

            logging.getLogger(__name__).warning(
                "语义离群检测异常，本次降级为规则结果: %s", exc
            )
            return rule_events
        if semantic_event is None:
            return rule_events
        # 3. 合并去重：同 chunk_id 合并 evidence（去重），risk_score 取更高者
        #    避免同一 chunk 的注入证据被重复累计或被低优先级检测器覆盖丢失
        merged: Dict[str, Any] = {}
        for ev in rule_events + [semantic_event]:
            key = ev.chunk_id or ""
            if key not in merged:
                merged[key] = ev
            else:
                existing = merged[key]
                # 合并 evidence：去重，保持原顺序
                existing_ev = list(existing.evidence or [])
                new_ev = list(ev.evidence or [])
                for e in new_ev:
                    if e not in existing_ev:
                        existing_ev.append(e)
                existing.evidence = existing_ev
                # risk_score 取更高者
                if ev.risk_score > existing.risk_score:
                    existing.risk_score = ev.risk_score
                    existing.confidence = ev.confidence
                    # risk_type 也跟随高风险者
                    existing.risk_type = ev.risk_type
        return list(merged.values())


class RetrievalAuthzDetector(BaseDetector):
    """检索侧越权检测：读取 metadata 中的 ACL / 密级标签与用户角色比对。

    四态判定（密级语义不得混淆）：
    - PUBLIC      —— 密级明确为 public，或 classification_roles 显式映射为 None；
                    任何人可访问，不产出事件；
    - RESTRICTED  —— acl_roles 非空列表，或 classification 映射到具体角色列表；
                    执行正常的角色-密级比对，越权产出事件；
    - UNKNOWN     —— classification 值不在已知分类表中；
                    无法验证访问控制，risk_score 中高，必须产出事件交 Orchestrator；
    - INVALID     —— classification 类型异常（非字符串），或 acl_roles 类型异常（非列表）；
                    metadata 密级数据损坏，risk_score 高，必须产出事件。

    完全无 ACL 信息（无 classification、无 acl_roles）仍按开放处理，不产出事件；
    这是"文档方未配置 ACL"的情况，不得等同于"未知密级"。
    """

    name = "retrieval_authz_detector"
    stage = SecurityStage.RETRIEVAL

    # UNKNOWN 密级：中高风险（无法验证访问控制）
    UNKNOWN_RISK_SCORE = 0.55
    # INVALID 密级：高风险（metadata 损坏可能意味着攻击）
    INVALID_RISK_SCORE = 0.75

    # 四态常量
    STATE_PUBLIC = "PUBLIC"
    STATE_RESTRICTED = "RESTRICTED"
    STATE_UNKNOWN = "UNKNOWN"
    STATE_INVALID = "INVALID"
    STATE_NONE = "NONE"  # 完全无 ACL 信息（按开放处理）

    def _classify(
        self, doc: RetrievedChunk
    ) -> Tuple[str, Optional[List[str]], float, str]:
        """四态分类，返回 (state, allowed_roles_or_None, confidence, basis)。

        state 取值：PUBLIC / RESTRICTED / UNKNOWN / INVALID / NONE
          - PUBLIC    -> allowed_roles=None（任何人可访问）
          - RESTRICTED-> allowed_roles=具体角色列表
          - UNKNOWN   -> allowed_roles=None（需产出事件交 Orchestrator）
          - INVALID   -> allowed_roles=None（需产出事件交 Orchestrator）
          - NONE      -> allowed_roles=None（完全无 ACL 配置，不产出事件）
        """
        metadata = doc.metadata or {}

        # ---------- 1) acl_roles 显式授权（优先于 classification）----------
        acl = metadata.get("acl_roles")
        if acl is not None:
            if isinstance(acl, list):
                if acl:
                    # 非空列表 -> RESTRICTED
                    return (
                        self.STATE_RESTRICTED,
                        [str(r) for r in acl],
                        0.90,
                        "metadata.acl_roles",
                    )
                else:
                    # 空列表：acl_roles=[] 语义上等价于 public（显式开放）
                    return self.STATE_PUBLIC, None, 0.85, "metadata.acl_roles=[]"
            else:
                # acl_roles 类型异常
                actual_type = type(acl).__name__
                return (
                    self.STATE_INVALID,
                    None,
                    0.85,
                    f"metadata.acl_roles 类型异常 ({actual_type})",
                )

        # ---------- 2) classification 密级映射 ----------
        classification = metadata.get("classification")
        if classification is not None:
            if not isinstance(classification, str):
                actual_type = type(classification).__name__
                return (
                    self.STATE_INVALID,
                    None,
                    0.80,
                    f"metadata.classification 类型异常 ({actual_type})",
                )
            key = classification.lower()
            roles_map = self.config.classification_roles
            if key in roles_map:
                allowed = roles_map[key]
                if allowed is None:
                    # 显式 PUBLIC
                    return self.STATE_PUBLIC, None, 0.75, f"classification={classification}"
                if allowed:
                    # RESTRICTED with specific roles
                    return (
                        self.STATE_RESTRICTED,
                        list(allowed),
                        0.75,
                        f"classification={classification}",
                    )
                # roles_map[key] == []（空列表）：语义不明，按 INVALID
                return (
                    self.STATE_INVALID,
                    None,
                    0.70,
                    f"classification={classification} 映射为空角色列表",
                )
            else:
                # key 不在 classification_roles 中 -> UNKNOWN
                # 注意：必须用 `key in roles_map` 而非 `.get(key)`，
                # 因为 roles_map.get("unknown_key") 也返回 None，和显式
                # PUBLIC 的 roles_map["public"] = None 会被混淆
                return (
                    self.STATE_UNKNOWN,
                    None,
                    0.65,
                    f"classification={classification} 不在已知分类表中",
                )

        # ---------- 3) 完全无 ACL 配置 ----------
        return self.STATE_NONE, None, 0.0, ""

    def detect_one(self, doc: RetrievedChunk, user: Optional[UserContext]) -> Optional[Any]:
        state, allowed_roles, confidence, basis = self._classify(doc)

        # --- PUBLIC / NONE：不产出事件 ---
        if state in (self.STATE_PUBLIC, self.STATE_NONE):
            return None

        # --- UNKNOWN：密级未知，中高风险，交 Orchestrator ---
        if state == self.STATE_UNKNOWN:
            return make_event(
                self.stage,
                RiskType.UNAUTHORIZED_RETRIEVAL,  # TODO: 新增类型，接入前与团队统一命名
                risk_score=self.UNKNOWN_RISK_SCORE,
                confidence=confidence,
                detector_name=self.name,
                evidence=[
                    f"密级未知，无法验证访问控制：{basis}；"
                    f"risk_score={self.UNKNOWN_RISK_SCORE} 中高，"
                    "最终处置交 Orchestrator"
                ],
                chunk_id=doc.chunk_id,
            )

        # --- INVALID：密级数据损坏，高风险 ---
        if state == self.STATE_INVALID:
            return make_event(
                self.stage,
                RiskType.UNAUTHORIZED_RETRIEVAL,
                risk_score=self.INVALID_RISK_SCORE,
                confidence=confidence,
                detector_name=self.name,
                evidence=[
                    f"密级数据异常：{basis}；"
                    f"risk_score={self.INVALID_RISK_SCORE} 高，"
                    "metadata 可能被篡改，需人工核查"
                ],
                chunk_id=doc.chunk_id,
            )

        # --- RESTRICTED：正常角色-密级比对 ---
        if state == self.STATE_RESTRICTED:
            user_roles = user.roles if user else []
            if "admin" in user_roles or any(
                role in (allowed_roles or []) for role in user_roles
            ):
                return None  # 有权限
            role_text = "/".join(user_roles) if user_roles else "匿名"
            return make_event(
                self.stage,
                RiskType.UNAUTHORIZED_RETRIEVAL,
                risk_score=0.85,
                confidence=confidence,
                detector_name=self.name,
                evidence=[
                    f"角色[{role_text}] 无权访问要求 {allowed_roles} 的文档（依据 {basis}）"
                ],
                chunk_id=doc.chunk_id,
            )

        return None  # 兜底：未知 state 不产出事件

    def detect(self, payload: Any, context: Any = None) -> List[Any]:
        user = UserContextAdapter.validate(context, raise_on_invalid=False)
        return [
            event
            for doc in _as_documents(payload)
            if (event := self.detect_one(doc, user)) is not None
        ]
