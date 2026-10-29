import sys,unittest,copy
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core.shield import RAGFlowShield
from events.security_event import SecurityEvent,SecurityStage
class Attribution(unittest.TestCase):
 def event(self,**kwargs):return SecurityEvent(SecurityStage.RETRIEVAL,.2,"suspicious_document",1,**kwargs)
 def test_old_calls(self):
  e=SecurityEvent(SecurityStage.INPUT,.1,"normal_input",1,"old-id","old-time")
  self.assertEqual(e.event_id,"old-id");self.assertIsNone(e.chunk_id)
  self.assertIsNone(e.to_dict()["detector_name"])
 def test_records_and_replay(self):
  s=RAGFlowShield(total_budget=10);e=self.event(chunk_id="doc-2/chunk-3",detector_name="retrieval_filter")
  r=s.process(e)
  for record in [r["event"],s.risk_budget.history[0],s.risk_state.event_history[0].to_dict()]:
   self.assertEqual(record["chunk_id"],"doc-2/chunk-3");self.assertEqual(record["detector_name"],"retrieval_filter")
  self.assertTrue(s.process(copy.deepcopy(e))["duplicate_event"])
  for field in ["chunk_id","detector_name"]:
   conflict=copy.deepcopy(e);setattr(conflict,field,"other")
   self.assertEqual(s.process(conflict)["decision"]["action"],"BLOCK")
  self.assertAlmostEqual(s.risk_budget.consumed_budget,.2)
 def test_optional_validation(self):
  for field in ["chunk_id","detector_name"]:
   for value in ["", " ",12,False,[]]:
    with self.subTest(field=field,value=value):
     with self.assertRaises(ValueError):self.event(**{field:value})
   s=RAGFlowShield();e=self.event();setattr(e,field,"")
   self.assertEqual(s.process(e)["reason"],"invalid_security_event")
 def test_distinct_events_preserve_attribution(self):
  s=RAGFlowShield(total_budget=10)
  for chunk,detector in [("c1","a"),("c2","a"),("c1","b")]:
   s.process(self.event(chunk_id=chunk,detector_name=detector))
  self.assertEqual(len(s.risk_budget.history),3)
  self.assertEqual([(x["chunk_id"],x["detector_name"]) for x in s.risk_budget.history],[("c1","a"),("c2","a"),("c1","b")])
if __name__=="__main__":unittest.main(verbosity=2)
