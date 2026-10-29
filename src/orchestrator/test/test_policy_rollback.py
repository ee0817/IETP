from events.security_event import (
    SecurityEvent,
    SecurityStage
)

from core.risk_state import RiskState
from core.policy_engine import PolicyEngine
from checkpoint.manager import CheckpointManager


risk_state = RiskState()
policy_engine = PolicyEngine()
checkpoint_manager = CheckpointManager()


# =========================
# 保存 Input Checkpoint
# =========================

input_state = {
    "query": "什么是RAG？",
    "documents": [],
    "answer": None
}

checkpoint_manager.save(
    node="input",
    workflow_state=input_state,
    risk_state={
        "global_risk": 0.1,
        "state": "NORMAL"
    },
    trusted=True
)


# =========================
# 保存 Retrieval Checkpoint
# =========================

retrieval_state = {
    "query": "什么是RAG？",
    "documents": [
        "安全文档1",
        "安全文档2"
    ],
    "answer": None
}

checkpoint_manager.save(
    node="retrieval",
    workflow_state=retrieval_state,
    risk_state={
        "global_risk": 0.3,
        "state": "CAUTIOUS"
    },
    trusted=True
)


# =========================
# Generation 出现风险
# =========================

event = SecurityEvent(
    stage=SecurityStage.GENERATION,
    risk_score=0.9,
    risk_type="unsafe_generation",
    confidence=0.96
)

risk_state.update(event)


# =========================
# Policy Engine 做最终决策
# =========================

decision = policy_engine.decide_action(
    risk_state,
    event
)

print("===== POLICY DECISION =====")
print(decision)


# =========================
# Checkpoint Manager 执行
# =========================

if decision["action"] == "ROLLBACK":

    result = checkpoint_manager.rollback_to(
        decision["rollback_to"]
    )

    print("\n===== CHECKPOINT EXECUTION =====")
    print(result)

else:

    print(
        "\nNo rollback:",
        decision["action"]
    )