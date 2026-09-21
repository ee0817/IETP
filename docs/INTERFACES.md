# 模块接入规范 V1

## 总原则

**Detector 报告风险，Orchestrator 决定流程。**

检测模块不要直接返回最终的 BLOCK / ROLLBACK 决策；检测结果由全流程编排层统一转换为流程动作。

## Retrieval 输入

```python
detect(query: str, documents: list[RetrievedChunk])
```

```python
@dataclass
class RetrievedChunk:
    chunk_id: str
    content: str
    source: str
    score: float
    metadata: Dict[str, Any]
```

- source：必须提供；无法确认来源时使用明确的 unknown 标识，不伪造来源。
- score：必须提供，表示检索相关度/相似度。真实 Retriever 接入时应统一其语义/范围。
- metadata：必须为 dict；timestamp、tenant 当前为可选字段。
- query：作为 request-level 参数单独传入，不重复塞进每个 chunk。

## Trust/Whitelist V1

白名单第一版可以是静态列表。命中返回 TRUSTED，未命中返回 UNKNOWN；未命中不等于恶意。

推荐结果字段：source_id、trust_status、trust_score、reason。
