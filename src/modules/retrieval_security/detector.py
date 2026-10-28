"""检索后内容过滤模块入口。

模块名：retrieval_content_filter
职责：接收用户原始查询 query 与检索输出的 documents（list[RetrievedChunk]），
      对整批 documents 执行安全检测，输出每个 Chunk 对应的 SecurityEvent 列表。
不参与流程决策（不返回 BLOCK/ROLLBACK/RESTRICT/VERIFY/CONTINUE）。

执行流程（PR3 修订）：
1. 遍历 documents，对每个 Chunk 依次执行：
   a. source → 白名单检查（source 为 "unknown" 时视为未命中）
      - 白名单是"来源信任"信号，不等于内容免检：
        注入检测与投毒检测（内容安全检测）始终执行；
        仅跳过相关性检测（适用条件：可信来源的内容默认与业务语料相关，
        剩余检测范围 = 注入 + 投毒）。
   b. 任一子检测器异常 → 生成 detection_error 事件（保留检测器名与失败原因），
      绝不将故障转换为"无风险"安全结论。
   c. 汇总：取最高 risk_score 的事件本身（保留其自身 confidence，
      不与其他事件的 confidence 混合）；若全部检测失败，返回 detection_error。
2. 返回 list[SecurityEvent]，与 documents 一一对应
3. 审计日志：按 event.chunk_id 关联真实来源逐条写入 SQLite
"""

from __future__ import annotations

import uuid

from checks import injection_check, poisoning_check, relevance_check, whitelist_check
from schemas import RetrievedChunk, SecurityEvent
from utils import logger


# 公共 RetrievedChunk 必填字段（与 schemas/Q&A.md 公共接口一致）
_REQUIRED_CHUNK_FIELDS = ("chunk_id", "content", "source", "score", "metadata")

# P2-15：单个 chunk.content 的最大长度上限（字符数）。
# 超限内容会被截断后再送入各检测器，防止超大输入造成 DoS（正则/分词均为 O(n)）。
# 截断动作会记录到 error 字段，保证可追溯。
MAX_CONTENT_LENGTH = 100_000


def _validate_chunk(chunk: object) -> None:
    """显式校验入参对象是否具备公共 RetrievedChunk 的字段。

    字段不兼容（如公共对象与本模块字段命名不一致）时立即抛出 TypeError，
    而不是依赖后续异常兜底返回零风险 none 事件、掩盖接入错误。
    """
    missing = [f for f in _REQUIRED_CHUNK_FIELDS if not hasattr(chunk, f)]
    if missing:
        raise TypeError(
            f"传入对象缺少 RetrievedChunk 必填字段 {missing}，"
            f"实际类型为 {type(chunk).__name__}；"
            "请确认字段命名与公共接口（source 等）一致。"
        )


def _make_error_event(detector_name: str, exc: Exception, chunk_id: str) -> SecurityEvent:
    """生成检测失败事件：明确标记检测未完成，保留检测器名与失败原因。

    检测器只报告风险或故障，是否复核/重试/限制由编排层决定。
    """
    return SecurityEvent(
        event_id=uuid.uuid4().hex,
        chunk_id=chunk_id,
        stage="retrieval",
        risk_score=0.0,  # 0 分不代表无风险，risk_type=detection_error 明确表示检测未完成
        risk_type="detection_error",
        confidence=0.0,
        error=f"{detector_name} failed: {type(exc).__name__}: {exc}",
    )


# ---------------------------------------------------------------------------
# 风险汇总
# ---------------------------------------------------------------------------
def _aggregate_events(events: list[SecurityEvent]) -> SecurityEvent:
    """汇总同一 Chunk 的多个 SecurityEvent。

    规则：
    - 返回 risk_score 最高的事件本身（保留其自身 confidence，
      风险与置信度属于同一判断，不跨事件混合）。
    - 存在 detection_error 时：将其失败原因合并记录到返回事件的 error 字段，
      保证故障可追溯。
    - 所有事件均为 detection_error（或列表为空）→ 返回 detection_error，
      明确表示检测未完成，不得包装成"无风险"。
    """
    if not events:
        return SecurityEvent(
            event_id=uuid.uuid4().hex,
            stage="retrieval",
            risk_score=0.0,
            risk_type="detection_error",
            confidence=0.0,
            error="no detector produced a result",
        )

    errors = [e for e in events if e.risk_type == "detection_error"]
    non_errors = [e for e in events if e.risk_type != "detection_error"]

    if not non_errors:
        # 全部检测器失败：检测未完成
        reasons = "; ".join(e.error or "unknown" for e in errors)
        return SecurityEvent(
            event_id=uuid.uuid4().hex,
            stage="retrieval",
            risk_score=0.0,
            risk_type="detection_error",
            confidence=0.0,
            error=reasons,
        )

    # 取最高风险分的事件本身（保留其 confidence 与 evidence 字段）
    highest = max(non_errors, key=lambda e: e.risk_score)
    if errors:
        # 部分检测器失败：风险结论保留，但失败原因必须可追溯
        reasons = "; ".join(e.error or "unknown" for e in errors)
        highest.error = (highest.error + "; " if highest.error else "") + reasons
    return highest


# ---------------------------------------------------------------------------
# 单 Chunk 检测
# ---------------------------------------------------------------------------
def _detect_single_chunk(chunk: RetrievedChunk, query: str) -> SecurityEvent:
    """对单个 Chunk 执行白名单识别 + 内容安全检测。

    白名单策略（PR3）：来源信任是独立信号，不等于内容免检。
    - 注入检测、投毒检测：始终执行（可信来源的内容也可能被篡改）。
    - 相关性检测：白名单命中时跳过（适用条件：可信来源默认与业务相关；
      剩余检测范围 = 注入 + 投毒，已在模块文档中注明）。

    Returns:
        SecurityEvent：该 Chunk 的安全事件（含 detection_error 故障事件）。
    """
    # 步骤 1：source → 白名单检查
    # is_whitelisted 内部已处理 "unknown"/空串（返回未命中），无需额外判断
    is_white = bool(whitelist_check.is_whitelisted(chunk.source))

    chunk_events: list[SecurityEvent] = []

    # 步骤 2：content → 指令/提示注入检测（始终执行）
    try:
        chunk_events.append(injection_check.check(chunk, query))
    except Exception as exc:  # noqa: BLE001
        # 容错：单个检测器报错不影响其他检测器，但必须显式标记故障
        chunk_events.append(_make_error_event("injection_check", exc, chunk.chunk_id))

    # 步骤 3：content / score → 投毒检测（始终执行）
    try:
        chunk_events.append(poisoning_check.check(chunk))
    except Exception as exc:  # noqa: BLE001
        chunk_events.append(_make_error_event("poisoning_check", exc, chunk.chunk_id))

    # 步骤 4：query + content → 相关性检测（白名单命中时跳过，见模块文档）
    if not is_white:
        try:
            chunk_events.append(relevance_check.check(chunk, query))
        except Exception as exc:  # noqa: BLE001
            chunk_events.append(_make_error_event("relevance_check", exc, chunk.chunk_id))

    result = _aggregate_events(chunk_events)
    # 回填 chunk_id 与 event_id，便于审计与追踪
    result.chunk_id = chunk.chunk_id
    result.event_id = uuid.uuid4().hex
    return result


def _truncate_chunk(chunk: RetrievedChunk) -> tuple[RetrievedChunk, str | None]:
    """超长 content 截断（防 DoS），返回 (新 chunk 副本, 截断说明)。

    N1 修复：不原地修改调用方对象，避免副作用泄漏——
    编排层后续若需原始 content（如送 LLM 生成），不应拿到被截断的版本。
    """
    content = getattr(chunk, "content", None)
    if not isinstance(content, str) or len(content) <= MAX_CONTENT_LENGTH:
        return chunk, None
    original_len = len(content)
    truncated = content[:MAX_CONTENT_LENGTH]
    note = f"content truncated from {original_len} to {MAX_CONTENT_LENGTH} chars"
    # pydantic BaseModel：model_copy 返回副本，不动原对象
    if hasattr(chunk, "model_copy"):
        return chunk.model_copy(update={"content": truncated}), note
    # dataclass（公共接口对象）：replace 返回副本
    import dataclasses

    if dataclasses.is_dataclass(chunk) and not isinstance(chunk, type):
        return dataclasses.replace(chunk, content=truncated), note
    # 其他鸭子类型：浅拷贝后改副本
    import copy

    new_chunk = copy.copy(chunk)
    try:
        object.__setattr__(new_chunk, "content", truncated)
        return new_chunk, note
    except Exception:  # noqa: BLE001
        # 完全不可变的对象：放弃截断，按原样检测（不退化为错误）
        return chunk, None


# ---------------------------------------------------------------------------
# 入口函数
# ---------------------------------------------------------------------------
def detect(query: str, documents: list[RetrievedChunk]) -> list[SecurityEvent]:
    """检索后内容过滤主入口。

    对整批 documents 做检测，返回与 documents 一一对应的 SecurityEvent 列表。

    Args:
        query: 用户原始查询字符串，用于相关性过滤（query + content）。
        documents: 检索输出的文档列表，同一批共用同一个 query。

    Returns:
        list[SecurityEvent]：每个 Chunk 对应一个安全事件，长度与 documents 相同。

    Raises:
        TypeError: 任一 document 缺少公共 RetrievedChunk 必填字段时立即抛出，
                   不做异常兜底，避免字段不兼容被掩盖为零风险事件。
    """
    # 入口显式校验：字段不兼容（如公共对象与本模块命名不一致）立即失败
    for chunk in documents:
        _validate_chunk(chunk)

    results: list[SecurityEvent] = []
    chunk_by_id = {c.chunk_id: c for c in documents}

    # 遍历 documents，对每个 Chunk 执行检测
    for chunk in documents:
        # 超长 content 截断（副本，不改原对象），截断痕迹写入事件的 error 字段
        chunk, truncated_note = _truncate_chunk(chunk)
        try:
            event = _detect_single_chunk(chunk, query)
        except Exception as exc:  # noqa: BLE001
            # 容错：单个 Chunk 整体失败不影响整批，但必须显式标记检测未完成，
            # 绝不返回"无风险"占位事件
            event = _make_error_event("detector", exc, chunk.chunk_id)
        if truncated_note:
            event.error = (event.error + "; " if event.error else "") + truncated_note
        results.append(event)

    # 审计日志 —— 按每个事件的 chunk_id 关联真实来源逐条写入，
    # 避免把高风险事件错误归到 documents[0]；action_taken 留空由下游回填
    for event in results:
        try:
            src_chunk = chunk_by_id.get(event.chunk_id)
            logger.write_log(
                event,
                chunk_id=event.chunk_id,
                source=src_chunk.source if src_chunk is not None else None,
            )
        except Exception:  # noqa: BLE001
            # 日志写入失败不影响主流程返回结果
            pass

    # 返回每个 Chunk 对应的 SecurityEvent 列表
    return results
