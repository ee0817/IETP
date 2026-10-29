import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core.shield import RAGFlowShield
from events.security_event import SecurityEvent,SecurityStage
class StateReturn(unittest.TestCase):
 def test_restored_state_and_evidence(self):
  s=RAGFlowShield(total_budget=10)
  s.process(SecurityEvent(SecurityStage.INPUT,.1,"normal_input",1))
  s.save_checkpoint("retrieval",{})
  r=s.process(SecurityEvent(SecurityStage.GENERATION,.7,"unsafe_generation",1))
  self.assertEqual(r["risk_state"],s.risk_state.state)
  self.assertEqual(r["global_risk"],round(s.risk_state.global_risk,3))
  self.assertEqual(r["risk_after"],s.risk_state.get_state())
  self.assertGreater(r["risk_before"]["global_risk"],r["risk_after"]["global_risk"])
  self.assertEqual(r["event"]["risk_score"],.7)
  self.assertEqual(r["decision"]["action"],"ROLLBACK")
  self.assertAlmostEqual(s.risk_budget.consumed_budget,.8)
  r["risk_after"]["stage_risks"]["input"]=999
  self.assertAlmostEqual(s.risk_state.stage_risks["input"],.1)
 def test_no_restore(self):
  for kind in ["normal_input","unsafe_generation"]:
   with self.subTest(kind=kind):
    s=RAGFlowShield(total_budget=10)
    r=s.process(SecurityEvent(SecurityStage.GENERATION,.2,kind,1))
    self.assertEqual(r["risk_before"],r["risk_after"])
if __name__=="__main__":unittest.main(verbosity=2)
