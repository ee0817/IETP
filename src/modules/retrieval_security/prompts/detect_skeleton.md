# 任务
根据 system_prompt.md 的规范，生成检索后内容过滤模块的入口函数 `detect()` 骨架。

# 输入输出
- 输入：data（按照 RetrievedChunk 结构）
- 输出：SecurityEvent（stage, risk_score, risk_type, confidence）

# 执行流程要求（必须严格遵守顺序）
1. 数据适配：将 data 转换为标准 RetrievedChunk（调用适配层，当前先用占位逻辑）。
2. 白名单前置：调用 `whitelist_check.is_whitelisted(chunk.source)`。
   - 如果命中：直接返回 `SecurityEvent(stage="retrieval", risk_score=0.0, risk_type="none", confidence=1.0)`，跳过后续所有检测。
3. 指令/提示注入检测（最高优先级）：调用 `injection_check.check(chunk)`。
4. 语义投毒检测：调用 `poisoning_check.check(chunk)`。
5. 上下文相关性过滤：调用 `relevance_check.check(chunk, query)`。（注意：query 可能不存在，骨架中要写好容错处理）
6. 风险汇总：将步骤 3、4、5 返回的 SecurityEvent 进行汇总，取最高风险分作为最终 risk_score，对应的事件类型作为 risk_type，最高置信度作为 confidence。
7. 审计日志：调用 `logger.write_log(final_event)` 写入 SQLite。
8. 返回最终的 SecurityEvent。

# 代码要求
- 用 Python 3.10+，带完整类型标注。
- 骨架中所有检测函数的调用先写占位逻辑（返回一个默认的 SecurityEvent），不用实现具体算法。
- 必须包含 try-except 容错：如果某个检测模块报错，不能导致主流程崩溃。
- 主入口函数只负责调度，不写具体检测逻辑。

# 输出要求
- 完整 Python 文件：`detector.py`
- 用 `pydantic` 定义输入输出结构（如果 `system_prompt.md` 里已定义，直接引用）。
- 代码中必须带详细注释，说明每一步在干什么。