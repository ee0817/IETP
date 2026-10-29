import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core.shield import RAGFlowShield
from events.security_event import SecurityEvent,SecurityStage
class Rollback(unittest.TestCase):
 def test_unavailable_targets(self):
  for target,stage,kind in [("input",SecurityStage.RETRIEVAL,"poisoned_document"),("retrieval",SecurityStage.GENERATION,"unsafe_generation")]:
   for mode in ["missing","untrusted","wrong_target"]:
    with self.subTest(target=target,mode=mode):
     s=RAGFlowShield(total_budget=10)
     if mode=="untrusted":s.save_checkpoint(target,{},trusted=False)
     if mode=="wrong_target":s.save_checkpoint("generation",{})
     r=s.process(SecurityEvent(stage,.7,kind,1))
     self.assertEqual(r["decision"]["action"],"BLOCK")
     self.assertEqual(r["flow_action"],{"flow_action":"terminate"})
     self.assertEqual(r["reason"],"rollback_failed")
     self.assertEqual(r["requested_decision"]["rollback_to"],target)
     self.assertEqual(r["rollback"]["action"],"block")
     self.assertEqual(s.circuit_breaker.rollback_count,0)
     self.assertEqual(s.circuit_breaker.retry_count,0)
     self.assertAlmostEqual(s.risk_budget.consumed_budget,.7)
     self.assertAlmostEqual(s.risk_state.global_risk,.7)
 def test_trusted_target(self):
  s=RAGFlowShield(total_budget=10)
  s.save_checkpoint("retrieval",{"answer":None})
  r=s.process(SecurityEvent(SecurityStage.GENERATION,.7,"unsafe_generation",1))
  self.assertEqual(r["flow_action"]["flow_action"],"rollback")
  self.assertEqual(r["decision"]["action"],"ROLLBACK")
  self.assertEqual(r["rollback"]["rollback_to"],"retrieval")
  self.assertEqual(s.circuit_breaker.rollback_count,1)
  self.assertNotIn("requested_decision",r)
if __name__=="__main__":unittest.main(verbosity=2)
