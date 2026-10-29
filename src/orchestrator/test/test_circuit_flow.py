from events.security_event import (
    SecurityEvent,
    SecurityStage
)

from core.risk_state import RiskState
from core.risk_budget import RiskBudget
from core.policy_engine import PolicyEngine
from core.flow_controller import FlowController
from core.circuit_breaker import CircuitBreaker
from checkpoint.manager import CheckpointManager


# ==========================================
# 初始化
# ==========================================

risk_state = RiskState()
risk_budget = RiskBudget(total_budget=3.0)

policy_engine = PolicyEngine()
flow_controller = FlowController()
checkpoint_manager = CheckpointManager()

circuit_breaker = CircuitBreaker(
    max_retries=3,
    max_rollbacks=2
)


# ==========================================
# 保存一个安全 Retrieval Checkpoint
# ==========================================

workflow_state = {
    "query": "什么是RAG？",
    "documents": [
        "安全文档1",
        "安全文档2"
    ],
    "answer": None
}

checkpoint_manager.save(
    node="retrieval",
    workflow_state=workflow_state,
    risk_state=risk_state.get_state(),
    trusted=True
)


print("========== START ==========")


# ==========================================
# 模拟连续两次生成失败
# ==========================================

for attempt in range(1, 4):

    print(
        f"\n===== Generation Attempt {attempt} ====="
    )

    # --------------------------------------
    # 先检查是否已经熔断
    # --------------------------------------

    if circuit_breaker.is_open():
        print("CIRCUIT OPEN")
        print("流程已经熔断，禁止继续执行")
        break


    # --------------------------------------
    # 模拟生成风险
    # --------------------------------------

    event = SecurityEvent(
        stage=SecurityStage.GENERATION,
        risk_score=0.7,
        risk_type="unsafe_generation",
        confidence=0.9
    )

    risk_state.update(event)
    risk_budget.consume(event)


    # --------------------------------------
    # Policy Engine 决策
    # --------------------------------------

    decision = policy_engine.decide_with_budget(
        risk_state,
        risk_budget,
        event
    )

    print("Decision:", decision)


    # --------------------------------------
    # Flow Controller 执行决策
    # --------------------------------------

    flow_action = flow_controller.execute_decision(
        decision
    )

    print("Flow Action:", flow_action)


    # --------------------------------------
    # 如果需要 Rollback
    # --------------------------------------

    if flow_action["flow_action"] == "rollback":

        result = checkpoint_manager.rollback_to(
            flow_action["target_node"]
        )

        print(
            "Rollback To:",
            result["rollback_to"]
        )

        # 记录一次 rollback
        circuit_breaker.record_rollback()

        print(
            "Circuit State:",
            circuit_breaker.get_state()
        )

        # 如果回滚后已经触发熔断
        if circuit_breaker.is_open():

            print("\n!!! CIRCUIT OPEN !!!")
            print("回滚次数达到安全上限")
            print("当前请求被终止")
            break

        # 模拟重新执行 Generation
        circuit_breaker.record_retry()

        print("重新尝试 Generation...")


    elif flow_action["flow_action"] == "terminate":

        print("Policy Engine 要求终止")
        break


print("\n========== END ==========")