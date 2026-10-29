from events.security_event import (
    SecurityEvent,
    SecurityStage
)

from core.shield import RAGFlowShield


shield = RAGFlowShield(
    total_budget=2.0,
    max_retries=3,
    max_rollbacks=2
)


# =====================================
# 1. 建立一个安全状态
# =====================================

input_event = SecurityEvent(
    stage=SecurityStage.INPUT,
    risk_score=0.2,
    risk_type="normal_input",
    confidence=0.9
)

shield.risk_state.update(input_event)
shield.risk_budget.consume(input_event)


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


print("===== BEFORE ATTACK =====")

print(
    "Risk State:",
    shield.risk_state.get_state()
)

print(
    "Risk Budget:",
    shield.risk_budget.get_state()
)


# =====================================
# 2. Generation 出现风险
# =====================================

attack_event = SecurityEvent(
    stage=SecurityStage.GENERATION,
    risk_score=0.7,
    risk_type="unsafe_generation",
    confidence=0.9
)

result = shield.process(
    attack_event
)


print("\n===== ROLLBACK RESULT =====")

print(
    "Decision:",
    result["decision"]
)

print(
    "Rollback:",
    result.get("rollback")
)


# =====================================
# 3. 查看真正恢复后的系统
# =====================================

print("\n===== AFTER ROLLBACK =====")

print(
    "Risk State:",
    shield.risk_state.get_state()
)

print(
    "Risk Budget:",
    shield.risk_budget.get_state()
)

print(
    "Circuit Breaker:",
    shield.circuit_breaker.get_state()
)