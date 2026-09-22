"""语义投毒检测测试（V0.1）。"""

from checks.poisoning_check import check
from schemas import RetrievedChunk


def _make_chunk(content: str, source_id: str = "https://example.com/doc", metadata=None) -> RetrievedChunk:
    return RetrievedChunk(
        chunk_id="test-chunk-1",
        content=content,
        source_id=source_id,
        score=0.8,
        metadata=metadata if metadata is not None else {"tenant": "a"},
    )


def test_normal_text():
    event = check(_make_chunk("这是一段长度适中且没有任何重复字符的正常文档内容。"), "query")
    assert event.risk_score < 0.5
    assert event.risk_type == "none"


def test_very_short_text():
    event = check(_make_chunk("短"), "query")
    assert event.risk_score > 0.0


def test_very_long_text():
    event = check(_make_chunk("正" * 5001), "query")
    assert event.risk_score > 0.0


def test_repeated_chars():
    event = check(_make_chunk("a" * 30), "query")
    assert event.risk_score > 0.5
    assert event.risk_type == "poisoned_document"


def test_empty_content():
    event = check(_make_chunk(""), "query")
    assert event.risk_score > 0.0


def test_metadata_missing_unknown_source():
    # metadata 为空且 source_id 为 "unknown"，应比正常文本得分更高
    normal = check(_make_chunk("这是一段正常的文本内容", source_id="https://example.com", metadata={"k": "v"}), "q")
    suspicious = check(_make_chunk("这是一段正常的文本内容", source_id="unknown", metadata={}), "q")
    assert suspicious.risk_score > normal.risk_score
