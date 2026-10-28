# Retrieval Content Filter（检索后内容过滤模块）

RAG 全流程安全架构中的"检索后内容过滤"环节：对 Retriever 输出的整批
`RetrievedChunk` 执行白名单识别与内容安全检测，输出每个 Chunk 对应的
`SecurityEvent`。本模块只报告风险或故障，最终决定（BLOCK/ROLLBACK 等）
由编排层做出。

## 原型范围（当前版本）

- 白名单检查：domain_suffix / url_prefix / exact（`config/whitelist.yaml`）。
  白名单 = 来源信任信号，不等于内容免检：注入、投毒检测始终执行，
  白名单命中仅跳过相关性检测（可信来源默认与业务相关）。
- 注入检测（`checks/injection_check.py`）：V1.0，优先使用 llm-guard
  PromptInjection 扫描器，不可用时降级到 6 条正则规则。
- 投毒检测（`checks/poisoning_check.py`）：V0.1 启发式（长度/重复字符/
  特殊字符占比/元数据缺失）。
- 相关性检测（`checks/relevance_check.py`）：V0.1 Jaccard 词汇重叠
  （NLI 模型 `models/nli_model.py` 为占位，尚未接入）。
- 审计日志：SQLite（`data/audit.db`），按 chunk_id 逐条关联真实来源。
- 检测失败：返回 `risk_type="detection_error"` 事件（confidence=0.0，
  error 字段保留检测器名与原因），不会包装成"无风险"。

## 接口

```python
from detector import detect
events = detect(query: str, documents: list[RetrievedChunk])  # -> list[SecurityEvent]
```

`RetrievedChunk` 字段：`chunk_id / content / source / score / metadata`
（与公共接口 schemas/Q&A.md 一致）。

## 运行方式

```bash
pip install -r requirements.txt
pytest tests/ -q        # 从仓库根目录运行
```

## 生产环境部署安全建议

> 本节为部署前的强制检查项。当前仓库为原型实现，以下事项必须在生产上线前落实。

### 1. 锁定第三方模型供应链（关键）

`injection_check.py` 使用的 llm-guard `PromptInjection` 扫描器默认在首次运行时
从 HuggingFace 下载模型权重。**如果上游模型被恶意替换，检测器本身就会成为"内鬼"**。
上线前必须：

- **离线预下载模型**，生产环境禁用运行时下载（设置 `HF_HUB_OFFLINE=1` /
  `TRANSFORMERS_OFFLINE=1`）；
- **固定模型 revision**：下载时指定具体 commit hash
  （`huggingface_hub.snapshot_download(..., revision="<commit-sha>")`），
  并记录到部署清单；
- **校验模型文件哈希**：对下载后的权重文件计算 SHA-256，与可信来源比对；
- 模型目录设置只读权限，纳入配置变更审计。

### 2. 白名单配置文件保护

`config/whitelist.yaml` 是信任锚，任何能写该文件的进程都能把恶意域名加入白名单：

- 文件权限收敛为仅部署账户可写；
- 对文件内容做哈希签名校验，启动时校验；
- 配置变更走审批 + 审计流程，变更后显式调用 `whitelist_check.reload_rules()`。

### 3. 审计日志完整性

审计库 `data/audit.db` 已内置 SHA-256 哈希链（`verify_chain()` 可检测篡改），
上线后还应：

- DB 文件权限收敛，定期离线备份；
- 在编排层接入 `verify_chain()` 的定期校验任务，校验失败时告警；
- 监控审计写入失败的 `logging.warning` 输出（写失败可能意味着有人试图
  通过使 DB 不可用抹去痕迹）。

### 4. 已知限制（V0.1/V1.0 原型）

- 投毒检测（`poisoning_check.py`）为启发式规则，检出率有限；
  规则公开在代码中，攻击者可针对性构造规避文本。V1.1 计划接入
  PPL 困惑度模型并重新标定长度规则权重（见代码 TODO）。
- 相关性检测为 Jaccard 词汇重叠，非语义级。V1 计划接入 NLI 模型
  （`models/nli_model.py` 占位）。
- llm-guard 不可用时注入检测降级为正则规则，降级路径返回的
  `SecurityEvent` 会以较低 confidence 及 `error` 字段标注 `degraded`，
  编排层应据此决定是否提高复核等级。
