"""上下文相关性过滤测试（V0.1）。"""

from checks.relevance_check import check
from schemas import RetrievedChunk


def _make_chunk(content: str) -> RetrievedChunk:
    return RetrievedChunk(
        chunk_id="test-chunk-1",
        content=content,
        source="https://example.com/doc",
        score=0.8,
        metadata={},
    )


def test_relevant_overlap():
    # query 与 content 有重叠词 RAG，视为相关
    event = check(_make_chunk("RAG是检索增强生成技术"), "什么是RAG")
    assert event.risk_score < 0.6
    assert event.risk_type == "none"


def test_irrelevant_no_overlap():
    # query 与 content 毫无重叠，视为不相关
    event = check(_make_chunk("今天天气很好"), "什么是RAG")
    assert event.risk_score >= 0.6
    assert event.risk_type == "suspicious_document"


def test_empty_query():
    # 空查询跳过检测，无风险
    event = check(_make_chunk("任意内容"), "")
    assert event.risk_score == 0.0
    assert event.risk_type == "none"


def test_empty_content():
    # 空文档，交集为 0，视为不相关
    event = check(_make_chunk(""), "security")
    assert event.risk_score >= 0.6


def test_case_insensitive():
    # 大小写不敏感，RAG 与 rag 视为重叠
    event = check(_make_chunk("rag"), "RAG")
    assert event.risk_score < 0.6
    assert event.risk_type == "none"
