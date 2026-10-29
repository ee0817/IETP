import sys,unittest
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core.policy_engine import PolicyEngine
from core.shield import RAGFlowShield
from events.security_event import SecurityEvent,SecurityStage
class Budget:
 def __init__(self,remaining):self.remaining_budget=remaining
 def is_exhausted(self):return self.remaining_budget<=0
class Priority(unittest.TestCase):
 def test_blocked_matrix(self):
  p=PolicyEngine()
  for remaining in [0,.1,.3,.30001,10]:
   for kind in ["normal_input","prompt_injection","poisoned_document","malicious_context","unsafe_generation","sensitive_information"]:
    with self.subTest(remaining=remaining,kind=kind):
     state=SimpleNamespace(state="BLOCKED");event=SimpleNamespace(risk_type=kind, risk_score=.5)
     self.assertEqual(p.decide_with_budget(state,Budget(remaining),event)["action"],"BLOCK")
     self.assertEqual(p.decide_action(state,event)["action"],"BLOCK")
 def test_nonblocked_rules(self):
  p=PolicyEngine()
  for state,remaining,kind,expected in [
   ("NORMAL",1,"normal_input","CONTINUE"),
   ("CAUTIOUS",1,"normal_input","VERIFY"),
   ("RESTRICTED",1,"normal_input","RESTRICT"),
   ("NORMAL",.3,"normal_input","RESTRICT"),
   ("CAUTIOUS",.3,"normal_input","RESTRICT"),
   ("NORMAL",0,"unsafe_generation","BLOCK"),
   ("NORMAL",1,"prompt_injection","BLOCK"),
   ("RESTRICTED",.2,"poisoned_document","ROLLBACK"),
   ("CAUTIOUS",1,"unsafe_generation","ROLLBACK")]:
   with self.subTest(state=state,remaining=remaining,kind=kind):
    self.assertEqual(p.decide_with_budget(SimpleNamespace(state=state),Budget(remaining),SimpleNamespace(risk_type=kind, risk_score=.5))["action"],expected)
 def test_end_to_end(self):
  shield=RAGFlowShield(total_budget=1.1)
  result=shield.process(SecurityEvent(SecurityStage.INPUT,.9,"suspicious_input",1))
  self.assertEqual(result["decision"]["action"],"BLOCK")
  self.assertEqual(result["flow_action"]["flow_action"],"terminate")
if __name__=="__main__":unittest.main(verbosity=2)
