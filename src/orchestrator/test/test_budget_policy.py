from events.security_event import (
    SecurityEvent,
    SecurityStage
)

from core.risk_state import RiskState
from core.risk_budget import RiskBudget
from core.policy_engine import PolicyEngine


risk_state = RiskState()

risk_budget = RiskBudget(
    total_budget=1.0
)

policy_engine = PolicyEngine()


events = [

    SecurityEvent(
        stage=SecurityStage.INPUT,
        risk_score=0.2,
        risk_type="suspicious_input",
        confidence=0.9
    ),

    SecurityEvent(
        stage=SecurityStage.RETRIEVAL,
        risk_score=0.3,
        risk_type="suspicious_document",
        confidence=0.9
    ),

    SecurityEvent(
        stage=SecurityStage.CONTEXT,
        risk_score=0.25,
        risk_type="suspicious_context",
        confidence=0.9
    )
]


for event in events:

    print(
        f"\n===== {event.stage.value.upper()} ====="
    )

    # 更新全局风险
    risk_state.update(event)

    # 消耗风险预算
    risk_budget.consume(event)

    # 综合决策
    decision = policy_engine.decide_with_budget(
        risk_state,
        risk_budget,
        event
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
        decision
    )