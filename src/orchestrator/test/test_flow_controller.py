from events.security_event import (
    SecurityEvent,
    SecurityStage
)

from core.risk_state import RiskState
from core.policy_engine import PolicyEngine
from core.flow_controller import FlowController


risk_state = RiskState()
policy_engine = PolicyEngine()
flow_controller = FlowController()


# ---------- 输入阶段 ----------

input_event = SecurityEvent(
    stage=SecurityStage.INPUT,
    risk_score=0.4,
    risk_type="prompt_injection",
    confidence=0.9
)

risk_state.update(input_event)

policy = policy_engine.decide(risk_state)

next_node = flow_controller.route(
    policy,
    current_stage="input"
)

print("===== 输入阶段 =====")
print("Risk State:", risk_state.state)
print("Policy:", policy["policy"])
print("Next Node:", next_node)


# ---------- 检索阶段 ----------

retrieval_event = SecurityEvent(
    stage=SecurityStage.RETRIEVAL,
    risk_score=0.7,
    risk_type="poisoned_document",
    confidence=0.92
)

risk_state.update(retrieval_event)

policy = policy_engine.decide(risk_state)

next_node = flow_controller.route(
    policy,
    current_stage="retrieval"
)

print("\n===== 检索阶段 =====")
print("Risk State:", risk_state.state)
print("Policy:", policy["policy"])
print("Next Node:", next_node)