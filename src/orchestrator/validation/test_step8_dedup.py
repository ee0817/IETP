import sys,unittest,copy
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core.shield import RAGFlowShield
from core.risk_budget import RiskBudget
from events.security_event import SecurityEvent,SecurityStage
class Dedup(unittest.TestCase):
 def event(self):return SecurityEvent(SecurityStage.GENERATION,.7,"unsafe_generation",1)
 def test_replay_no_side_effects(self):
  s=RAGFlowShield(total_budget=10);s.save_checkpoint("retrieval",{})
  e=self.event();first=s.process(e)
  before=(s.risk_state.get_state(),s.risk_budget.get_state(),s.circuit_breaker.get_state())
  replay=s.process(copy.deepcopy(e))
  self.assertTrue(replay.pop("duplicate_event"));self.assertEqual(first,replay)
  self.assertEqual(before,(s.risk_state.get_state(),s.risk_budget.get_state(),s.circuit_breaker.get_state()))
  replay["decision"]["action"]="tamper"
  self.assertEqual(s.process(e)["decision"]["action"],"ROLLBACK")
 def test_conflict_blocks(self):
  s=RAGFlowShield(total_budget=10);e=self.event();s.process(e)
  before=s.risk_budget.get_state();e.risk_score=.8
  r=s.process(e);self.assertEqual(r["decision"]["action"],"BLOCK");self.assertEqual(before,s.risk_budget.get_state())
 def test_distinct_ids_and_new_request(self):
  s=RAGFlowShield(total_budget=10);a=self.event();b=self.event()
  s.process(a);s.process(b);self.assertAlmostEqual(s.risk_budget.consumed_budget,1.4)
  s.reset_request();s.process(a);self.assertAlmostEqual(s.risk_budget.consumed_budget,.7)
 def test_budget_direct(self):
  b=RiskBudget(10);e=self.event()
  b.consume(e);b.consume(copy.deepcopy(e));self.assertAlmostEqual(b.consumed_budget,.7)
  e.confidence=.5
  with self.assertRaises(ValueError):b.consume(e)
  self.assertAlmostEqual(b.consumed_budget,.7)
if __name__=="__main__":unittest.main(verbosity=2)
