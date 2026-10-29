from events.security_event import (
    SecurityEvent,
    SecurityStage
)

from core.risk_state import RiskState
from core.policy_engine import PolicyEngine
from core.flow_controller import FlowController
from checkpoint.manager import CheckpointManager


risk_state = RiskState()
policy_engine = PolicyEngine()
flow_controller = FlowController()
checkpoint_manager = CheckpointManager()


# =====================================
# 1. 保存安全的 Retrieval Checkpoint
# =====================================

workflow_state = {
    "query": "什么是RAG？",
    "documents": [
        "安全文档1",
        "安全文档2"
    ],
    "answer": None
}

checkpoint_manager.save(
    node="retrieval",
    workflow_state=workflow_state,
    risk_state={
        "global_risk": 0.3,
        "state": "CAUTIOUS"
    },
    trusted=True
)


# =====================================
# 2. Generation 出现风险
# =====================================

workflow_state["answer"] = "危险回答"

event = SecurityEvent(
    stage=SecurityStage.GENERATION,
    risk_score=0.9,
    risk_type="unsafe_generation",
    confidence=0.96
)

risk_state.update(event)


# =====================================
# 3. Policy Engine：决定怎么办
# =====================================

decision = policy_engine.decide_action(
    risk_state,
    event
)

print("===== POLICY ENGINE =====")
print(decision)


# =====================================
# 4. Flow Controller：转换成流程动作
# =====================================

flow_action = flow_controller.execute_decision(
    decision
)

print("\n===== FLOW CONTROLLER =====")
print(flow_action)


# =====================================
# 5. 执行 Rollback
# =====================================

if flow_action["flow_action"] == "rollback":

    result = checkpoint_manager.rollback_to(
        flow_action["target_node"]
    )

    print("\n===== CHECKPOINT MANAGER =====")
    print(result)

elif flow_action["flow_action"] == "terminate":

    print("\n===== TERMINATED =====")
    print("流程已被安全策略终止")