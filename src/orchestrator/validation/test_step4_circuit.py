import sys,unittest,io,contextlib
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from workflow.runner import WorkflowRunner
from core.shield import RAGFlowShield
from events.security_event import SecurityEvent,SecurityStage
class CircuitResponse(unittest.TestCase):
 def test_open_response(self):
  s=RAGFlowShield(total_budget=10,max_rollbacks=1)
  s.save_checkpoint("retrieval",{})
  s.process(SecurityEvent(SecurityStage.GENERATION,.7,"unsafe_generation",1))
  self.assertTrue(s.circuit_breaker.is_open())
  before=(s.risk_state.get_state(),s.risk_budget.get_state(),s.circuit_breaker.get_state(),s.checkpoint_manager.get_history())
  for event in [SecurityEvent(SecurityStage.INPUT,.9,"prompt_injection",1),None]:
   result=s.process(event)
   self.assertEqual(result["flow_action"],{"flow_action":"terminate"})
   self.assertEqual(result["decision"]["action"],"BLOCK")
   self.assertEqual(result["reason"],"circuit_breaker_open")
   self.assertIsNone(result["event"])
   self.assertEqual(result["risk_state"],s.risk_state.state)
   self.assertEqual(result["remaining_budget"],round(s.risk_budget.remaining_budget,3))
   runner=WorkflowRunner()
   with contextlib.redirect_stdout(io.StringIO()):
    runner._show_result(result)
    self.assertTrue(runner._is_terminated(result))
    self.assertFalse(runner._allow_progress(result))
  after=(s.risk_state.get_state(),s.risk_budget.get_state(),s.circuit_breaker.get_state(),s.checkpoint_manager.get_history())
  self.assertEqual(before,after)
if __name__=="__main__":unittest.main(verbosity=2)
