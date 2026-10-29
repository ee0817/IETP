from events.security_event import (
    SecurityEvent,
    SecurityStage
)

from core.risk_state import RiskState
from core.policy_engine import PolicyEngine


risk_state = RiskState()
policy_engine = PolicyEngine()


# 模拟生成阶段出现严重风险
event = SecurityEvent(
    stage=SecurityStage.GENERATION,
    risk_score=0.9,
    risk_type="unsafe_generation",
    confidence=0.96
)

risk_state.update(event)

print("Global Risk:", risk_state.global_risk)
print("Risk State:", risk_state.state)


decision = policy_engine.decide_action(
    risk_state,
    event
)

print("Final Decision:", decision)