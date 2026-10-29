import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core.risk_state import RiskState
from core.shield import RAGFlowShield
from events.security_event import SecurityEvent,SecurityStage
class Aggregation(unittest.TestCase):
 def event(self,stage,score,kind="suspicious"):return SecurityEvent(stage,score,kind,1)
 def test_no_dilution_all_stages(self):
  r=RiskState();r.update(self.event(SecurityStage.INPUT,.8))
  high=r.global_risk
  for stage in [SecurityStage.RETRIEVAL,SecurityStage.CONTEXT,SecurityStage.GENERATION,SecurityStage.OUTPUT]:
   for score in [0,.01,.2]:
    r.update(self.event(stage,score));self.assertGreaterEqual(r.global_risk,high)
  self.assertEqual(r.state,"RESTRICTED")
 def test_escalation(self):
  r=RiskState();r.update(self.event(SecurityStage.INPUT,.8))
  r.update(self.event(SecurityStage.RETRIEVAL,.95))
  self.assertGreater(r.global_risk,.8);self.assertEqual(r.state,"BLOCKED")
 def test_restore_budget_and_new_branch(self):
  s=RAGFlowShield(total_budget=10)
  s.process(self.event(SecurityStage.INPUT,.1));s.save_checkpoint("retrieval",{})
  r=s.process(self.event(SecurityStage.GENERATION,.7,"unsafe_generation"))
  self.assertGreater(r["risk_before"]["global_risk"],r["risk_after"]["global_risk"])
  self.assertAlmostEqual(s.risk_state.global_risk,.1)
  self.assertAlmostEqual(s.risk_budget.consumed_budget,.8)
  s.process(self.event(SecurityStage.OUTPUT,.01))
  self.assertGreaterEqual(s.risk_state.global_risk,.1)
  s.reset_request();self.assertEqual(s.risk_state.global_risk,0)
 def test_snapshot_isolated(self):
  r=RiskState();r.update(self.event(SecurityStage.INPUT,.2));snap=r.get_state()
  r.update(self.event(SecurityStage.RETRIEVAL,.9));r.restore(snap)
  self.assertAlmostEqual(r.global_risk,.2)
  r.update(self.event(SecurityStage.OUTPUT,.01));self.assertGreaterEqual(r.global_risk,.2)
if __name__=="__main__":unittest.main(verbosity=2)
