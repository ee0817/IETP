# 任务
实现检索后内容过滤模块的上下文相关性过滤算法（V0.1 极简测试版）。

# 文件
`checks/relevance_check.py`

# 函数签名（不可更改）
def check(chunk: RetrievedChunk, query: str) -> SecurityEvent:
    ...

# 实现原则
- 本版本仅为“接口联调测试版”，不追求语义理解的准确性，只追求跑通流程。
- 不依赖任何外部模型或库，只用 Python 标准库。
- 用简单的词汇重叠度来判断 query 和 content 的相关性。

# 检测要求
1. 如果 query 为空字符串，跳过检测，直接返回无风险。
2. 将 query 和 content 都转为小写，并按空白字符切分为词集合。
3. 计算 Jaccard 相似度：交集大小 / 并集大小。
4. 如果相似度 < 0.1（完全不相关），给出中等风险分。
5. 如果相似度 >= 0.1，视为相关，无风险。
6. 由于中英文分词差异，V0.1 仅使用简单空格切分（英文场景），中文场景按字符切分作为降级方案。

# 输出要求
返回 SecurityEvent：
- event_id: uuid.uuid4().hex
- chunk_id: chunk.chunk_id
- stage: "retrieval"
- risk_type:
  - 不相关时："suspicious_document"（逻辑不相关，可能会误导 LLM）
  - 相关或跳过时："none"
- risk_score:
  - 不相关时：0.6（中等风险，交给下游去决策是否过滤）
  - 相关或跳过时：0.0
- confidence:
  - 不相关时：0.5（V0.1 规则简单，置信度不宜过高）
  - 相关或跳过时：1.0
- 必须包含 event_id 和 chunk_id。

# 代码结构要求
- 保留函数签名不变。
- 在文件顶部加注释：
  # TODO: V0.1 极简测试版，仅用于接口联调。
  # 后续 V1 版本将引入真正的 NLI 模型（如 DeBERTa-MNLI），做 query-premise-hypothesis 的三分类。

# 测试要求
在 `tests/test_relevance.py` 写以下测试：
1. query="什么是RAG"，content="RAG是检索增强生成技术"（有重叠词RAG） → risk_score < 0.6, risk_type == "none"
2. query="什么是RAG"，content="今天天气很好"（毫无重叠） → risk_score >= 0.6, risk_type == "suspicious_document"
3. query=""（空查询），content="任意内容" → risk_score == 0.0, risk_type == "none"
4. query="security"，content=""（空文档） → risk_score >= 0.6（交集为0）或按逻辑处理
5. 大小写测试：query="RAG"，content="rag" → 视为相关（大小写不敏感）

# 禁止事项
- 不要决定流程动作。
- 不要修改 SecurityEvent 字段定义。
- 不要修改 detector.py。
- 不要引入外部模型或库。

# 输出
- 完整 `checks/relevance_check.py`
- 完整 `tests/test_relevance.py`