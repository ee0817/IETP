from events.security_event import (
    SecurityEvent,
    SecurityStage
)

from core.shield import RAGFlowShield


shield = RAGFlowShield(
    total_budget=3.0,
    max_retries=3,
    max_rollbacks=2
)


# =========================
# 1. Input 风险
# =========================

input_event = SecurityEvent(
    stage=SecurityStage.INPUT,
    risk_score=0.2,
    risk_type="normal_input",
    confidence=0.9
)

shield.risk_state.update(input_event)


# =========================
# 2. 保存安全 Checkpoint
# =========================

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

print("===== CHECKPOINT STATE =====")
print(shield.risk_state.get_state())


# =========================
# 3. Generation 出现严重风险
# =========================

generation_event = SecurityEvent(
    stage=SecurityStage.GENERATION,
    risk_score=0.9,
    risk_type="unsafe_generation",
    confidence=0.95
)

result = shield.process(
    generation_event
)


print("\n===== AFTER PROCESS =====")

print(
    "Decision:",
    result["decision"]
)

print(
    "Rollback:",
    result.get("rollback")
)


# =========================
# 4. 看 Shield 内部真实状态
# =========================

print("\n===== REAL INTERNAL STATE =====")

print(
    shield.risk_state.get_state()
)