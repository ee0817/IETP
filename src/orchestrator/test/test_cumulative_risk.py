from events.security_event import (
    SecurityEvent,
    SecurityStage
)

from core.risk_state import RiskState
from core.risk_budget import RiskBudget
from core.policy_engine import PolicyEngine


risk_state = RiskState()
risk_budget = RiskBudget(total_budget=1.0)
policy_engine = PolicyEngine()


events = [
    SecurityEvent(
        stage=SecurityStage.INPUT,
        risk_score=0.25,
        risk_type="minor_risk",
        confidence=0.9
    ),

    SecurityEvent(
        stage=SecurityStage.RETRIEVAL,
        risk_score=0.25,
        risk_type="minor_risk",
        confidence=0.9
    ),

    SecurityEvent(
        stage=SecurityStage.CONTEXT,
        risk_score=0.25,
        risk_type="minor_risk",
        confidence=0.9
    ),

    SecurityEvent(
        stage=SecurityStage.GENERATION,
        risk_score=0.25,
        risk_type="minor_risk",
        confidence=0.9
    ),

    SecurityEvent(
        stage=SecurityStage.OUTPUT,
        risk_score=0.25,
        risk_type="minor_risk",
        confidence=0.9
    )
]


for event in events:

    risk_state.update(event)
    risk_budget.consume(event)

    decision = policy_engine.decide_with_budget(
        risk_state,
        risk_budget,
        event
    )

    print(
        f"\n===== {event.stage.value.upper()} ====="
    )

    print(
        "Global Risk:",
        round(risk_state.global_risk, 3)
    )

    print(
        "Risk State:",
        risk_state.state
    )

    print(
        "Remaining Budget:",
        round(
            risk_budget.remaining_budget,
            3
        )
    )

    print(
        "Decision:",
        decision["action"]
    )