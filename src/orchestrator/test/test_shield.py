from events.security_event import (
    SecurityEvent,
    SecurityStage
)

from core.shield import RAGFlowShield


# =====================================
# 创建 RAG-FlowShield
# =====================================

shield = RAGFlowShield(
    total_budget=3.0,
    max_retries=3,
    max_rollbacks=2
)


# =====================================
# 保存 Retrieval 安全状态
# =====================================

workflow_state = {
    "query": "什么是RAG？",
    "documents": [
        "安全文档1",
        "安全文档2"
    ],
    "answer": None
}

shield.save_checkpoint(
    node="retrieval",
    workflow_state=workflow_state,
    trusted=True
)


# =====================================
# 模拟 Generation 风险
# =====================================

event = SecurityEvent(
    stage=SecurityStage.GENERATION,
    risk_score=0.7,
    risk_type="unsafe_generation",
    confidence=0.9
)


# =====================================
# 只需要这一句
# =====================================

result = shield.process(event)


print("===== RAG-FLOWSHIELD RESULT =====")

print(
    "Global Risk:",
    result["global_risk"]
)

print(
    "Risk State:",
    result["risk_state"]
)

print(
    "Remaining Budget:",
    result["remaining_budget"]
)

print(
    "Decision:",
    result["decision"]
)

print(
    "Flow Action:",
    result["flow_action"]
)

if "rollback" in result:

    print(
        "Rollback:",
        result["rollback"]
    )

print(
    "Circuit Breaker:",
    result["circuit_breaker"]
)