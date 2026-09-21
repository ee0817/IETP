# Retrieval Security

检索/上下文阶段安全模块上传位置。

V1 入口：

```python
detect(query: str, documents: list[RetrievedChunk])
```

可在模块内部组合白名单/Trust Registry、投毒检测、NLI 相关性检测等逻辑。
