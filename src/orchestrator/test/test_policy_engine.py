from events.security_event import (
    SecurityEvent,
    SecurityStage
)

from core.risk_state import RiskState
from core.policy_engine import PolicyEngine


risk_state = RiskState()
policy_engine = PolicyEngine()


# 第一个风险事件
input_event = SecurityEvent(
    stage=SecurityStage.INPUT,
    risk_score=0.4,
    risk_type="prompt_injection",
    confidence=0.90
)

risk_state.update(input_event)

print("===== 输入阶段 =====")
print(risk_state.get_state())
print(policy_engine.decide(risk_state))


# 第二个风险事件
retrieval_event = SecurityEvent(
    stage=SecurityStage.RETRIEVAL,
    risk_score=0.7,
    risk_type="poisoned_document",
    confidence=0.92
)

risk_state.update(retrieval_event)

print("\n===== 检索阶段 =====")
print(risk_state.get_state())
print(policy_engine.decide(risk_state))