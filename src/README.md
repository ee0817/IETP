# src

RAG-FlowShield 的公共集成代码放在这里。

## 目录
- `orchestrator/`：全流程安全编排（RiskState / RiskBudget / PolicyEngine / FlowController / Checkpoint / CircuitBreaker）
- `interfaces/`：组员之间共享的数据结构与接口协议
- `modules/`：各阶段安全检测模块接入位置

## 约定
检测模块只报告风险，不直接决定 BLOCK / ROLLBACK。最终流程动作统一由 orchestrator 的 PolicyEngine 决定。
