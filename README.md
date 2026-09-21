# IETP · RAG-FlowShield

> 面向 RAG 系统的全流程安全防御项目  
> **Detector 报告风险，Orchestrator 决定流程。**

## 项目简介

本项目围绕 RAG（Retrieval-Augmented Generation，检索增强生成）系统的安全问题展开，目标是在 **输入 → 检索/上下文 → 生成 → 输出** 的完整链路中加入安全检测与统一编排机制。

RAG-FlowShield 不只是增加单独的检测器，而是将各阶段产生的风险结果统一转换为全流程控制信号，由安全编排层维护风险状态，并根据风险动态决定继续、验证、限制、回滚或终止流程。

当前项目处于原型开发与模块联调阶段。

## 核心思路

```text
User Input
    ↓
Input Security
    ↓
Retrieval / Context Security
    ↓
Generation Security
    ↓
Output Security
    ↓
Final Response

各阶段 Detector
    ↓
SecurityEvent
    ↓
RiskState + RiskBudget
    ↓
PolicyEngine
    ↓
FlowController
    ↓
CONTINUE / VERIFY / RESTRICT / ROLLBACK / BLOCK
```

安全编排遵循一个重要原则：

> **执行状态可以回滚，但安全代价不可回滚。**

当流程回滚到之前的 Checkpoint 时，工作流状态和对应风险状态可以恢复，但已经消耗的 Risk Budget、重试次数和回滚次数不会被清零，从而避免无限重试和反复利用回滚机制。

## 项目结构

```text
IETP/
├── src/
│   ├── orchestrator/          # 全流程安全编排
│   ├── interfaces/            # 公共数据结构与接口
│   └── modules/               # 各阶段安全检测模块
│       ├── input_security/
│       ├── retrieval_security/
│       ├── generation_security/
│       └── output_security/
├── docs/                      # 架构、接口和实验文档
├── data/                      # 测试与实验数据
├── members/                   # 成员个人开发区
│   ├── HK/
│   ├── e/
│   ├── qiuji/
│   └── xinyue/
└── assets images/             # 图片素材
```

## 模块职责

### Orchestrator

`src/orchestrator/` 负责全流程安全控制，主要包括：

- SecurityEvent：统一安全事件
- RiskState：聚合各阶段风险状态
- RiskBudget：记录生命周期累计安全代价
- PolicyEngine：根据风险决定流程动作
- FlowController：执行动态路由
- CheckpointManager：保存和恢复安全工作流状态
- CircuitBreaker：限制重试和回滚次数
- WorkflowRunner：驱动完整工作流

### Security Modules

`src/modules/` 存放各阶段安全检测模块。

检测模块负责发现并报告风险，不直接决定整个系统应该 BLOCK 或 ROLLBACK。最终流程控制由 Orchestrator 统一完成。

## 统一接口

以 Retrieval Security V1 为例：

```python
detect(query: str, documents: list[RetrievedChunk])
```

统一检索结果结构：

```python
@dataclass
class RetrievedChunk:
    chunk_id: str
    content: str
    source: str
    score: float
    metadata: Dict[str, Any]
```

其中：

- `source`：文档来源，必须提供；未知来源使用明确的 `unknown` 标识。
- `score`：Retriever 给出的相关度/相似度，不代表安全风险。
- `metadata`：附加信息字典。
- `query`：作为请求级参数单独传入。

详细规范见 `docs/INTERFACES.md`。

## 团队成员

| 姓名 | 角色 |
| --- | --- |
| 胡康若旗 | 组长 |
| 李晓依 | 组员 |
| 陈秋吉 | 组员 |
| 张欣悦 | 组员 |

## 开发规范

1. 未完成的实验代码、个人笔记可以先放入 `members/<name>/`。
2. 可以进行联调的模块整理到 `src/modules/` 对应目录。
3. 公共数据结构统一放在 `src/interfaces/`，避免不同成员自行定义不兼容接口。
4. 全流程安全控制代码统一放入 `src/orchestrator/`。
5. Detector 只报告风险，最终流程决策统一交给 Orchestrator。
6. 接口发生变化时，先同步更新 `docs/INTERFACES.md`。
7. `main` 只保留稳定版本，不直接推送；功能开发通过独立分支和 Pull Request 合并。

## 当前进度

- [x] 全流程安全架构设计
- [x] SecurityEvent 统一事件设计
- [x] RiskState 风险状态设计
- [x] RiskBudget 风险预算设计
- [x] PolicyEngine 策略决策设计
- [x] FlowController 动态路由设计
- [x] Checkpoint 回滚机制设计
- [x] CircuitBreaker 熔断机制设计
- [x] WorkflowRunner 原型闭环测试
- [x] Retrieval V1 公共接口定义
- [ ] 各组员检测模块接入
- [ ] Audit / Trace
- [ ] 接入真实 RAG 流程
- [ ] 安全实验与效果评估

---

当前阶段以 **接口统一、模块联调和完整闭环跑通** 为主要目标。
