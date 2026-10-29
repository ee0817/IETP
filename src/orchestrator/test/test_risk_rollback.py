from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core.shield import RAGFlowShield
from events.security_event import SecurityEvent,SecurityStage
for stage,kind,target in [(SecurityStage.GENERATION,"unsafe_generation","retrieval"),(SecurityStage.RETRIEVAL,"poisoned_document","input")]:
 shield=RAGFlowShield(total_budget=10)
 shield.save_checkpoint(target,{"answer":None,"documents":["safe"]})
 result=shield.process(SecurityEvent(stage,.7,kind,1))
 assert result["decision"]["action"]=="ROLLBACK"
 assert result["rollback"]["rollback_to"]==target
 assert result["rollback"]["workflow_state"]["answer"] is None
 assert shield.risk_budget.consumed_budget==.7
 shield=RAGFlowShield(total_budget=10)
 result=shield.process(SecurityEvent(stage,.7,kind,1))
 assert result["decision"]["action"]=="BLOCK"
 assert result["flow_action"]["flow_action"]=="terminate"
shield=RAGFlowShield(total_budget=10)
result=shield.process(SecurityEvent(SecurityStage.INPUT,.7,"prompt_injection",1))
assert result["flow_action"]["flow_action"]=="terminate"
assert shield.circuit_breaker.rollback_count==0
print("Risk routing and missing checkpoint assertions passed")
