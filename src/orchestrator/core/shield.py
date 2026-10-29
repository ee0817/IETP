from core.risk_state import RiskState
from core.risk_budget import RiskBudget
from core.policy_engine import PolicyEngine
from core.flow_controller import FlowController
from core.circuit_breaker import CircuitBreaker

from checkpoint.manager import CheckpointManager
from events.security_event import SecurityEvent
from copy import deepcopy


class RAGFlowShield:
    """
    RAG-FlowShield 主安全编排控制器

    外部安全模块只需要提供 SecurityEvent，
    本控制器负责统一完成：

    SecurityEvent
        ↓
    Global Risk State
        ↓
    Risk Budget
        ↓
    Policy Engine
        ↓
    Flow Controller
        ↓
    Checkpoint / Circuit Breaker
    """

    def __init__(
        self,
        total_budget=1.0,
        max_retries=3,
        max_rollbacks=2
    ):
        self._request_config = {
            "total_budget": total_budget,
            "max_retries": max_retries,
            "max_rollbacks": max_rollbacks,
        }
        self.policy_engine = PolicyEngine()
        self.flow_controller = FlowController()
        self.reset_request()

    def reset_request(self):
        """Start an independent request; never call during rollback/retry.

        A shield/runner instance supports sequential requests only.
        Concurrent requests must use separate instances.
        """
        self._processed_events = {}
        self.risk_state = RiskState()
        self.risk_budget = RiskBudget(
            total_budget=self._request_config["total_budget"]
        )
        self.checkpoint_manager = CheckpointManager()
        self.circuit_breaker = CircuitBreaker(
            max_retries=self._request_config["max_retries"],
            max_rollbacks=self._request_config["max_rollbacks"],
        )

    def save_checkpoint(
        self,
        node,
        workflow_state,
        trusted=True
    ):
        """
        保存当前安全检查点。
        """

        return self.checkpoint_manager.save(
            node=node,
            workflow_state=workflow_state,
            risk_state=self.risk_state.get_state(),
            trusted=trusted
        )

    def process(self, event):
        """
        处理一个 SecurityEvent，
        返回最终流程控制结果。
        """

        # =========================
        # 1. 熔断检查
        # =========================

        if self.circuit_breaker.is_open():
            return {
                "action": "terminate",
                "reason": "circuit_breaker_open",
                "event": None,
                "global_risk": round(self.risk_state.global_risk, 3),
                "risk_state": self.risk_state.state,
                "remaining_budget": round(self.risk_budget.remaining_budget, 3),
                "decision": {
                    "action": "BLOCK",
                    "reason": "circuit_breaker_open",
                },
                "flow_action": {"flow_action": "terminate"},
                "circuit_breaker": self.circuit_breaker.get_state(),
            }

        # Reject invalid detector responses before changing risk or budget.
        try:
            if not isinstance(event, SecurityEvent):
                raise ValueError("检测结果必须是SecurityEvent")
            event.validate()
            if (event.event_id in self._processed_events
                    and self._processed_events[event.event_id][0] != event.to_dict()):
                raise ValueError("event_id_conflict")
        except (ValueError, TypeError, AttributeError):
            return {
                "action": "terminate",
                "reason": "invalid_security_event",
                "event": None,
                "global_risk": round(self.risk_state.global_risk, 3),
                "risk_state": self.risk_state.state,
                "risk_before": self.risk_state.get_state(),
                "risk_after": self.risk_state.get_state(),
                "remaining_budget": round(self.risk_budget.remaining_budget, 3),
                "decision": {"action": "BLOCK", "reason": "invalid_security_event"},
                "flow_action": {"flow_action": "terminate"},
                "circuit_breaker": self.circuit_breaker.get_state(),
            }

        if event.event_id in self._processed_events:
            # Idempotent replay: return the original response, execute no effects.
            replay = deepcopy(self._processed_events[event.event_id][1])
            replay["duplicate_event"] = True
            return replay

        # =========================
        # 2. 更新全局风险
        # =========================

        self.risk_state.update(event)

        # =========================
        # 3. 消耗 Risk Budget
        # =========================

        self.risk_budget.consume(event)

        # =========================
        # 4. Policy Engine 决策
        # =========================

        decision = self.policy_engine.decide_with_budget(
            self.risk_state,
            self.risk_budget,
            event
        )

        # =========================
        # 5. Flow Controller
        # =========================

        flow_action = self.flow_controller.execute_decision(
            decision
        )

        result = {
            "event": event.to_dict(),
            "global_risk": round(
                self.risk_state.global_risk,
                3
            ),
            "risk_state": self.risk_state.state,
            "remaining_budget": round(
                self.risk_budget.remaining_budget,
                3
            ),
            "decision": decision,
            "flow_action": flow_action
        }

        result["risk_before"] = self.risk_state.get_state()

        # =========================
        # 6. Rollback
        # =========================

        if flow_action["flow_action"] == "rollback":

            rollback_result = (
                self.checkpoint_manager.rollback_to(
                    flow_action["target_node"]
                )
            )

            result["rollback"] = rollback_result

            if rollback_result["action"] != "rollback":
                # Preserve the requested recovery for audit; expose a final block.
                result["requested_decision"] = decision
                result["decision"] = {
                    "action": "BLOCK",
                    "reason": "rollback_failed",
                }
                result["flow_action"] = {
                    "flow_action": "terminate"
                }
                result["reason"] = "rollback_failed"

            if rollback_result["action"] == "rollback":

                # =========================
                # 真正恢复 Global Risk State
                # =========================

                self.risk_state.restore(
                    rollback_result["risk_state"]
                )

                # 记录一次回滚
                self.circuit_breaker.record_rollback()

                # 如果没有触发熔断，
                # 记录接下来的一次重试
                if not self.circuit_breaker.is_open():
                    self.circuit_breaker.record_retry()

            if self.circuit_breaker.is_open():
                result["flow_action"] = {
                    "flow_action": "terminate"
                }

                result["reason"] = (
                    "circuit_breaker_open"
                )

        # =========================
        # 7. 加入熔断状态
        # =========================

        result["circuit_breaker"] = (
            self.circuit_breaker.get_state()
        )

        # Main fields describe the effective state after any restoration.
        result["risk_after"] = self.risk_state.get_state()
        result["global_risk"] = round(self.risk_state.global_risk, 3)
        result["risk_state"] = self.risk_state.state
        self._processed_events[event.event_id] = (deepcopy(event.to_dict()), deepcopy(result))
        return result