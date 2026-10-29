from events.security_event import (
    SecurityEvent,
    SecurityStage
)

from core.risk_budget import RiskBudget


budget = RiskBudget(
    total_budget=1.0
)


# =========================
# Input
# =========================

event1 = SecurityEvent(
    stage=SecurityStage.INPUT,
    risk_score=0.2,
    risk_type="suspicious_input",
    confidence=0.9
)

budget.consume(event1)

print("===== INPUT =====")
print(budget.get_state())


# =========================
# Retrieval
# =========================

event2 = SecurityEvent(
    stage=SecurityStage.RETRIEVAL,
    risk_score=0.3,
    risk_type="suspicious_document",
    confidence=0.9
)

budget.consume(event2)

print("\n===== RETRIEVAL =====")
print(budget.get_state())


# =========================
# Generation
# =========================

event3 = SecurityEvent(
    stage=SecurityStage.GENERATION,
    risk_score=0.7,
    risk_type="unsafe_generation",
    confidence=0.9
)

budget.consume(event3)

print("\n===== GENERATION =====")
print(budget.get_state())