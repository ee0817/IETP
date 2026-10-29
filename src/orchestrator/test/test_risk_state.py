from events.security_event import (
    SecurityEvent,
    SecurityStage
)

from core.risk_state import RiskState


risk_state = RiskState()


# ---------- 第一阶段：输入检测 ----------

input_event = SecurityEvent(
    stage=SecurityStage.INPUT,
    risk_score=0.4,
    risk_type="prompt_injection",
    confidence=0.90
)

risk_state.update(input_event)

print("===== 输入阶段结束 =====")
print(risk_state.get_state())


# ---------- 第二阶段：检索检测 ----------

retrieval_event = SecurityEvent(
    stage=SecurityStage.RETRIEVAL,
    risk_score=0.7,
    risk_type="poisoned_document",
    confidence=0.92
)

risk_state.update(retrieval_event)

print("\n===== 检索阶段结束 =====")
print(risk_state.get_state())