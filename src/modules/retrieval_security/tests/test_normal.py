"""正常样例测试：白名单命中应返回 risk_score == 0.0。"""

from detector import detect
from schemas import RetrievedChunk


def test_normal_whitelisted():
    chunk = RetrievedChunk(
        chunk_id="doc-001#chunk-3",
        content="公司内部安全策略要求所有员工定期更换密码。",
        source="https://internal.company.com/policy",
        score=0.92,
        metadata={"tenant": "tenant-a"},
    )
    events = detect("如何更换密码", [chunk])
    assert isinstance(events, list)
    assert len(events) == 1
    assert events[0].risk_score == 0.0
