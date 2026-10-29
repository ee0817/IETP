from checkpoint.manager import CheckpointManager


manager = CheckpointManager()


# =========================
# 模拟：输入阶段完成
# =========================

workflow_state = {
    "query": "什么是RAG？",
    "documents": [],
    "answer": None
}

risk_state = {
    "global_risk": 0.2,
    "state": "NORMAL"
}

manager.save(
    node="input",
    workflow_state=workflow_state,
    risk_state=risk_state,
    trusted=True
)

print("保存 Input Checkpoint")


# =========================
# 模拟：检索阶段完成
# =========================

workflow_state["documents"] = [
    "doc_1",
    "doc_2"
]

risk_state["global_risk"] = 0.4
risk_state["state"] = "CAUTIOUS"

manager.save(
    node="retrieval",
    workflow_state=workflow_state,
    risk_state=risk_state,
    trusted=True
)

print("保存 Retrieval Checkpoint")


# =========================
# 模拟：生成阶段发生严重风险
# =========================

workflow_state["answer"] = "unsafe answer"

risk_state["global_risk"] = 0.9
risk_state["state"] = "BLOCKED"

print("\n生成阶段出现风险！")

print(
    "当前状态:",
    workflow_state
)


# =========================
# Rollback
# =========================

result = manager.rollback()

print("\n===== 开始回滚 =====")

print(
    "回滚到:",
    result["rollback_to"]
)

print(
    "恢复后的 Workflow:",
    result["workflow_state"]
)

print(
    "恢复后的 Risk State:",
    result["risk_state"]
)