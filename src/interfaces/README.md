# Shared Interfaces

组员模块联调时统一使用这里约定的数据格式。

## Retrieval V1

调用形式：

```python
detect(query: str, documents: list[RetrievedChunk])
```

RetrievedChunk 必须包含：
- chunk_id
- content
- source
- score
- metadata

其中 source、score 必须提供；metadata 必须是 dict，但 timestamp、tenant 暂不强制。

注意：chunk.score 表示检索相关度/相似度，不是安全 risk_score。
