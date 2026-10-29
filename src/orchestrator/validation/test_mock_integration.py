from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import contextlib,io,unittest
from collections import Counter
from workflow.runner import WorkflowRunner
from events.security_event import SecurityEvent
class MockDetector:
 """In-process fixture only: no network, real retrieval or model."""
 def __init__(self,stage,mode):self.stage=stage;self.mode=mode;self.calls=Counter()
 def detect(self,event):
  stage=event.stage.value;self.calls[stage]+=1
  mode=self.mode if stage==self.stage else "normal"
  if mode=="error":raise RuntimeError("mock_detector_error")
  if mode=="missing":return None
  score,kind=.1,"normal_"+stage
  if mode=="verify":score,kind=.4,"suspicious_"+stage
  if mode=="rollback" and self.calls[stage]==1:score,kind=.7,"unsafe_generation"
  if mode=="always_unsafe":score,kind=.7,"unsafe_generation"
  return SecurityEvent(event.stage,score,kind,1,chunk_id="mock-chunk" if stage=="retrieval" else None,detector_name="mock_"+stage)
def run_case(stage,mode,verifier=None):
 runner=WorkflowRunner(verifier=verifier);mock=MockDetector(stage,mode);original=runner.shield.process
 def process(event):
  try:detected=mock.detect(event)
  except RuntimeError:detected=None
  return original(detected)
 runner.shield.process=process
 out=io.StringIO()
 with contextlib.redirect_stdout(out):runner.run("mock integration query")
 return runner,mock,out.getvalue()
class Integration(unittest.TestCase):
 def test_normal_modules(self):
  r,m,out=run_case("generation","normal")
  self.assertIn("FINAL ANSWER",out)
  self.assertEqual(set(m.calls),{"input","retrieval","generation","output"})
  self.assertTrue(all(e.detector_name.startswith("mock_") for e in r.shield.risk_state.event_history))
 def test_missing_and_exception_each_stage(self):
  for stage in ["input","retrieval","generation","output"]:
   for mode in ["missing","error"]:
    with self.subTest(stage=stage,mode=mode):
     r,m,out=run_case(stage,mode);self.assertNotIn("FINAL ANSWER",out)
 def test_verifier_accept_reject_exception(self):
  for stage in ["input","retrieval","generation","output"]:
   for approved in [True,False]:
    with self.subTest(stage=stage,approved=approved):
     calls=[]
     def verify(state,result):calls.append(result);return approved
     r,m,out=run_case(stage,"verify",verify)
     self.assertEqual("FINAL ANSWER" in out,approved);self.assertTrue(calls)
  def broken(state,result):raise RuntimeError("mock verifier error")
  r,m,out=run_case("generation","verify",broken)
  self.assertNotIn("FINAL ANSWER",out)
 def test_rollback_regeneration(self):
  r,m,out=run_case("generation","rollback")
  self.assertIn("FINAL ANSWER",out);self.assertEqual(m.calls["generation"],2)
  self.assertEqual(r.shield.circuit_breaker.rollback_count,1)
 def test_persistent_risk_terminates(self):
  r,m,out=run_case("generation","always_unsafe")
  self.assertNotIn("FINAL ANSWER",out)
  self.assertTrue(r.shield.circuit_breaker.is_open())
if __name__=="__main__":unittest.main(verbosity=2)
