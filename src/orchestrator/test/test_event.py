from events.security_event import (
    SecurityEvent,
    SecurityStage
)



event = SecurityEvent(

    stage=SecurityStage.INPUT,

    risk_score=0.8,

    risk_type="prompt_injection",

    confidence=0.95

)



print(event)


print(
    event.to_dict()
)