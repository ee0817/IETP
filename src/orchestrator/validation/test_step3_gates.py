import sys,io,contextlib,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from workflow.runner import WorkflowRunner

class Gates(unittest.TestCase):
 def execute(self, stage, action, handler=None):
  calls=[]
  def wrapped(state,result):
   calls.append((state,result))
   return handler(state,result)
  kwargs={}
  if handler is not None:
   kwargs["verifier" if action=="verification" else "restrictor"]=wrapped
  runner=WorkflowRunner(**kwargs)
  original=runner.shield.process
  def inject(event):
   # Use normal generation to isolate gates from the rollback demonstration.
   if event.stage.value=="generation":
    event.risk_score=.1;event.risk_type="normal_generation"
   result=original(event)
   result["flow_action"]["flow_action"]=action if event.stage.value==stage else "continue"
   return result
  runner.shield.process=inject
  output=io.StringIO()
  with contextlib.redirect_stdout(output):runner.run("gate-test")
  return runner,output.getvalue(),calls
 def test_unapproved_all_stages(self):
  for stage in ["input","retrieval","generation","output"]:
   for action in ["verification","restricted"]:
    for handler in [None,lambda s,r:False,lambda s,r:None,lambda s,r:"pass"]:
     with self.subTest(stage=stage,action=action,handler=handler):
      runner,out,calls=self.execute(stage,action,handler)
      self.assertNotIn("FINAL ANSWER",out)
      self.assertIsNotNone(runner.last_stop_reason)
      # The blocked stage must not be saved as trusted.
      self.assertFalse(any(c["node"]==stage for c in runner.shield.checkpoint_manager.checkpoints))
 def test_approved_all_stages(self):
  for stage in ["input","retrieval","generation","output"]:
   for action in ["verification","restricted"]:
    with self.subTest(stage=stage,action=action):
     runner,out,calls=self.execute(stage,action,lambda s,r:True)
     self.assertIn("FINAL ANSWER",out);self.assertEqual(len(calls),1)
 def test_handler_exception(self):
  def broken(s,r):raise RuntimeError("failure")
  for action in ["verification","restricted"]:
   runner,out,calls=self.execute("generation",action,broken)
   self.assertNotIn("FINAL ANSWER",out);self.assertIn("handler_error",runner.last_stop_reason)
 def test_unknown_action(self):
  runner,out,calls=self.execute("output","unknown")
  self.assertNotIn("FINAL ANSWER",out)
 def test_callback_state_isolation(self):
  def check(state,result):
   state["answer"]="tampered"
   return True
  runner,out,calls=self.execute("generation","verification",check)
  self.assertNotEqual(runner.workflow_state["answer"],"tampered")
if __name__=="__main__":unittest.main(verbosity=2)
