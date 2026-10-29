from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import contextlib,io
from workflow.runner import WorkflowRunner
runner=WorkflowRunner()
output=io.StringIO()
with contextlib.redirect_stdout(output):runner.run("什么是RAG？")
assert "FINAL ANSWER" in output.getvalue()
assert runner.shield.circuit_breaker.rollback_count==1
assert runner.shield.circuit_breaker.retry_count==1
assert runner.workflow_state["answer"]
assert runner.shield.risk_budget.consumed_budget>0
assert runner.shield.risk_state.state=="NORMAL"
print("Full workflow rollback and retry assertions passed")
