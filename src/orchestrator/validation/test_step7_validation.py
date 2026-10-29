import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core.shield import RAGFlowShield
from events.security_event import SecurityEvent,SecurityStage
class Validation(unittest.TestCase):
 def event(self):return SecurityEvent(SecurityStage.INPUT,.2,"normal_input",.9)
 def test_constructor_rejects(self):
  for field,values in {"stage":["input","invalid",None],"risk_score":[True,".5",None,float("nan"),float("inf"),-.1,1.1],"confidence":[False,".5",None,float("nan")],"risk_type":["",None,1],"event_id":["",12],"timestamp":["",12]}.items():
   for value in values:
    with self.subTest(field=field,value=value):
     kwargs=dict(stage=SecurityStage.INPUT,risk_score=.2,risk_type="normal_input",confidence=.9)
     kwargs[field]=value
     with self.assertRaises((ValueError,TypeError)):SecurityEvent(**kwargs)
 def test_missing_wrong_and_mutated_inputs(self):
  s=RAGFlowShield(total_budget=10)
  for bad in [None,{},[],42,"event"]:
   self.check_rejection(s,bad)
  for field,value in [("stage","input"),("risk_score",float("nan")),("confidence",True),("event_id",""),("risk_type",None)]:
   bad=self.event();setattr(bad,field,value);self.check_rejection(s,bad)
 def check_rejection(self,s,event):
  before=(s.risk_state.get_state(),s.risk_budget.get_state(),s.circuit_breaker.get_state())
  r=s.process(event)
  self.assertEqual(r["reason"],"invalid_security_event")
  self.assertEqual(r["flow_action"]["flow_action"],"terminate")
  self.assertEqual(r["decision"]["action"],"BLOCK")
  self.assertEqual(before,(s.risk_state.get_state(),s.risk_budget.get_state(),s.circuit_breaker.get_state()))
 def test_valid_boundaries(self):
  for score in [0,1,.5]:
   e=SecurityEvent(SecurityStage.INPUT,score,"normal_input",1)
   e.validate();self.assertEqual(e.to_dict()["risk_score"],score)
if __name__=="__main__":unittest.main(verbosity=2)
