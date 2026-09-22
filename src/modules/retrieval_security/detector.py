"""检索后内容过滤模块入口。

模块名：retrieval_content_filter
职责：接收用户原始查询 query 与检索输出的 documents（list[RetrievedChunk]），
      对整批 documents 执行安全检测，输出每个 Chunk 对应的 SecurityEvent 列表。
不参与流程决策（不返回 BLOCK/ROLLBACK/RESTRICT/VERIFY/CONTINUE）。

执行流程：
1. 遍历 documents，对每个 Chunk 依次执行：
   a. source_id → 白名单检查（source_id 为 "unknown" 时视为未命中）
      - 命中则跳过该 Chunk 的后续检测，返回 none 事件
   b. content → 指令/提示注入检测
   c. content / score → 投毒检测
   d. query + content → NLI 相关性检测
   e. 汇总该 Chunk 所有检测结果为单个 SecurityEvent（取最高 risk_score）
2. 返回 list[SecurityEvent]，与 documents 一一对应
3. 审计日志：将整批中最高风险的事件写入 SQLite
"""

from __future__ import annotations

import uuid

from checks import injection_check, poisoning_check, relevance_check, whitelist_check
from schemas import RetrievedChunk, SecurityEvent
from utils import logger


# ---------------------------------------------------------------------------
# 风险汇总
# ---------------------------------------------------------------------------
def _aggregate_events(events: list[SecurityEvent]) -> SecurityEvent:
    """汇总同一 Chunk 的多个 SecurityEvent。

    规则：
    - 取最高 risk_score 作为最终 risk_score
    - 取最高风险分对应的 risk_type 作为最终 risk_type
    - 取最高 confidence 作为最终 confidence
    - 若列表为空，返回 risk_type="none"
    """
    if not events:
        return SecurityEvent(
            stage="retrieval",
            risk_score=0.0,
            risk_type="none",
            confidence=1.0,
        )

    highest = max(events, key=lambda e: e.risk_score)
    max_confidence = max(e.confidence for e in events)

    return SecurityEvent(
        stage="retrieval",
        risk_score=highest.risk_score,
        risk_type=highest.risk_type,
        confidence=max_confidence,
    )


# ---------------------------------------------------------------------------
# 单 Chunk 检测
# ---------------------------------------------------------------------------
def _detect_single_chunk(chunk: RetrievedChunk, query: str) -> SecurityEvent:
    """对单个 Chunk 依次执行白名单、注入、投毒、NLI 相关性检测。

    Returns:
        SecurityEvent：该 Chunk 的安全事件（白名单命中时为 none 事件）。
    """
    # 步骤 1：source_id → 白名单检查
    # source_id 为 "unknown" 时，视为未命中白名单
    if chunk.source_id and chunk.source_id != "unknown" and whitelist_check.is_whitelisted(chunk.source_id):
        # 命中白名单：跳过后续检测，返回无风险事件
        event = SecurityEvent(
            stage="retrieval",
            risk_score=0.0,
            risk_type="none",
            confidence=1.0,
        )
        event.event_id = uuid.uuid4().hex
        event.chunk_id = chunk.chunk_id
        return event

    chunk_events: list[SecurityEvent] = []

    # 步骤 2：content → 指令/提示注入检测（最高优先级）
    try:
        inj_event = injection_check.check(chunk, query)
        chunk_events.append(inj_event)
    except Exception:  # noqa: BLE001
        # 容错：单个检测模块报错不能导致该 Chunk 或整批崩溃
        pass

    # 步骤 3：content / score → 投毒检测
    try:
        poi_event = poisoning_check.check(chunk)
        chunk_events.append(poi_event)
    except Exception:  # noqa: BLE001
        pass

    # 步骤 4：query + content → NLI 相关性检测
    try:
        rel_event = relevance_check.check(chunk, query)
        chunk_events.append(rel_event)
    except Exception:  # noqa: BLE001
        pass

    result = _aggregate_events(chunk_events)
    # 回填 chunk_id 与 event_id，便于审计与追踪
    result.chunk_id = chunk.chunk_id
    result.event_id = uuid.uuid4().hex
    return result


# ---------------------------------------------------------------------------
# 入口函数
# ---------------------------------------------------------------------------
def detect(query: str, documents: list[RetrievedChunk]) -> list[SecurityEvent]:
    """检索后内容过滤主入口。

    对整批 documents 做检测，返回与 documents 一一对应的 SecurityEvent 列表。

    Args:
        query: 用户原始查询字符串，用于 NLI 相关性过滤（query + content）。
        documents: 检索输出的文档列表，同一批共用同一个 query。

    Returns:
        list[SecurityEvent]：每个 Chunk 对应一个安全事件，长度与 documents 相同。
    """
    results: list[SecurityEvent] = []

    # 遍历 documents，对每个 Chunk 执行检测
    for chunk in documents:
        try:
            event = _detect_single_chunk(chunk, query)
        except Exception:  # noqa: BLE001
            # 容错：某个 Chunk 检测失败不影响整批，返回 none 事件占位
            event = SecurityEvent(
                stage="retrieval",
                risk_score=0.0,
                risk_type="none",
                confidence=0.0,
            )
            event.chunk_id = chunk.chunk_id
            event.event_id = uuid.uuid4().hex
        results.append(event)

    # 审计日志 —— 将整批中最高风险的事件写入 SQLite，action_taken 留空由下游回填
    if results:
        try:
            max_event = max(results, key=lambda e: e.risk_score)
            # 取第一个 Chunk 的信息作为日志关联
            sample_chunk = documents[0]
            logger.write_log(
                max_event,
                chunk_id=sample_chunk.chunk_id,
                source_id=sample_chunk.source_id,
            )
        except Exception:  # noqa: BLE001
            # 日志写入失败不影响主流程返回结果
            pass

    # 返回每个 Chunk 对应的 SecurityEvent 列表
    return results
