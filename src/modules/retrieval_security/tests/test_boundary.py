"""边界样例测试：未命中白名单但无明显风险的 Chunk。"""

from detector import detect
from schemas import RetrievedChunk, SecurityEvent


def test_boundary_low_risk():
    chunk = RetrievedChunk(
        chunk_id="doc-003#chunk-2",
        content="这是一段普通的业务文档。",
        source_id="unknown",
        score=0.75,
        metadata={},
    )
    events = detect("市场活动计划", [chunk])

    assert isinstance(events, list)
    assert len(events) == 1
    event = events[0]
    assert isinstance(event, SecurityEvent)

    # 无明显注入/投毒，风险分应在低区间，风险类型为 none 或 suspicious_document
    assert 0.0 <= event.risk_score <= 0.6
    assert event.risk_type in ("none", "suspicious_document")

