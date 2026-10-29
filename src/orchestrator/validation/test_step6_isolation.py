import sys,unittest,contextlib,io
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from workflow.runner import WorkflowRunner
from core.shield import RAGFlowShield
from events.security_event import SecurityEvent,SecurityStage
class Isolation(unittest.TestCase):
 def run_quiet(self,r,q):
  with contextlib.redirect_stdout(io.StringIO()):r.run(q)
 def test_repeated_runner(self):
  r=WorkflowRunner();self.run_quiet(r,"A")
  first=(r.shield.risk_budget.get_state(),r.shield.circuit_breaker.get_state(),len(r.shield.checkpoint_manager.checkpoints))
  old=r.shield.checkpoint_manager
  self.run_quiet(r,"B")
  self.assertEqual(first,(r.shield.risk_budget.get_state(),r.shield.circuit_breaker.get_state(),len(r.shield.checkpoint_manager.checkpoints)))
  self.assertIsNot(old,r.shield.checkpoint_manager)
  self.assertTrue(all(x["workflow_state"]["query"]=="B" for x in r.shield.checkpoint_manager.checkpoints))
 def test_reset_after_open_preserves_configuration(self):
  s=RAGFlowShield(total_budget=7,max_retries=4,max_rollbacks=1)
  s.save_checkpoint("retrieval",{})
  s.process(SecurityEvent(SecurityStage.GENERATION,.7,"unsafe_generation",1))
  self.assertTrue(s.circuit_breaker.is_open())
  policy=s.policy_engine;flow=s.flow_controller;s.reset_request()
  self.assertFalse(s.circuit_breaker.is_open())
  self.assertEqual(s.risk_budget.remaining_budget,7)
  self.assertEqual(s.circuit_breaker.max_rollbacks,1)
  self.assertEqual(s.circuit_breaker.max_retries,4)
  self.assertEqual(s.risk_state.event_history,[])
  self.assertEqual(s.checkpoint_manager.checkpoints,[])
  self.assertIs(policy,s.policy_engine);self.assertIs(flow,s.flow_controller)
 def test_new_request_clears_stopped_state_and_keeps_handlers(self):
  verifier=lambda s,r:True;restrictor=lambda s,r:True
  r=WorkflowRunner(verifier,restrictor)
  r.last_stop_reason="previous_failure";r.workflow_state={"query":"old","documents":["old"],"answer":"old"}
  r.shield.circuit_breaker.open=True
  self.run_quiet(r,"new")
  self.assertIsNone(r.last_stop_reason)
  self.assertIs(r.verifier,verifier);self.assertIs(r.restrictor,restrictor)
  self.assertEqual(r.workflow_state["query"],"new")
  self.assertNotIn("old",r.workflow_state["documents"])
if __name__=="__main__":unittest.main(verbosity=2)
