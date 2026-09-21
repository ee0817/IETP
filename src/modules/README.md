# Security Modules

各阶段检测模块放在这里，便于最后统一接入 RAG-FlowShield。

建议目录：
- input_security/
- retrieval_security/
- generation_security/
- output_security/

统一原则：Detector 报告风险，Orchestrator 决定流程。
