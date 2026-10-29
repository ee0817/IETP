import sys,unittest
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core.policy_engine import PolicyEngine
from core.shield import RAGFlowShield
from events.security_event import SecurityEvent,SecurityStage
class Budget:
 def __init__(self,x):self.remaining_budget=x
 def is_exhausted(self):return self.remaining_budget<=0
class ZeroRisk(unittest.TestCase):
 def test_zero_type_matrix(self):
  p=PolicyEngine()
  for kind in ["prompt_injection","poisoned_document","malicious_context","unsafe_generation","sensitive_information"]:
   e=SecurityEvent(SecurityStage.OUTPUT,0,kind,1)
   for state,expected in [("NORMAL","CONTINUE"),("CAUTIOUS","VERIFY"),("RESTRICTED","RESTRICT"),("BLOCKED","BLOCK")]:
    with self.subTest(kind=kind,state=state):
     st=SimpleNamespace(state=state)
     self.assertEqual(p.decide_action(st,e)["action"],expected)
     self.assertEqual(p.decide_with_budget(st,Budget(10),e)["action"],expected)
     self.assertEqual(p.decide_with_budget(st,Budget(0),e)["action"],"BLOCK")
     self.assertEqual(p.decide_with_budget(st,Budget(.2),e)["action"],"BLOCK" if state=="BLOCKED" else "RESTRICT")
 def test_positive_risks_unchanged(self):
  p=PolicyEngine()
  for kind,expected in [("prompt_injection","BLOCK"),("poisoned_document","ROLLBACK"),("malicious_context","ROLLBACK"),("unsafe_generation","ROLLBACK"),("sensitive_information","ROLLBACK")]:
   e=SecurityEvent(SecurityStage.OUTPUT,.001,kind,1)
   self.assertEqual(p.decide_with_budget(SimpleNamespace(state="NORMAL"),Budget(10),e)["action"],expected)
 def test_no_rollback_for_zero(self):
  s=RAGFlowShield(total_budget=10)
  r=s.process(SecurityEvent(SecurityStage.OUTPUT,0,"sensitive_information",1))
  self.assertEqual(r["decision"]["action"],"CONTINUE")
  self.assertEqual(s.circuit_breaker.rollback_count,0)
  self.assertEqual(s.risk_budget.consumed_budget,0)
if __name__=="__main__":unittest.main(verbosity=2)
