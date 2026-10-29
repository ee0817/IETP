from events.security_event import (
    SecurityEvent,
    SecurityStage
)

from core.shield import RAGFlowShield
from copy import deepcopy


class WorkflowRunner:
    """
    RAG-FlowShield 工作流执行器

    当前版本：
    1. 自动执行 RAG 各阶段
    2. Generation 出现风险时自动回滚
    3. 回滚后重新执行 Generation
    4. Circuit Breaker 防止无限重试
    """

    def __init__(self, verifier=None, restrictor=None):

        self.verifier = verifier
        self.restrictor = restrictor
        self.last_stop_reason = None

        self.shield = RAGFlowShield(
            total_budget=3.0,
            max_retries=3,
            max_rollbacks=2
        )

        self.workflow_state = {
            "query": None,
            "documents": [],
            "answer": None
        }

    def run(self, query: str):

        self.shield.reset_request()
        self.last_stop_reason = None
        self.workflow_state = {
            "query": query,
            "documents": [],
            "answer": None,
        }

        print(
            "========== RAG-FLOWSHIELD WORKFLOW =========="
        )

        # ==========================================
        # INPUT
        # ==========================================

        print("\n===== INPUT =====")

        input_event = SecurityEvent(
            stage=SecurityStage.INPUT,
            risk_score=0.1,
            risk_type="normal_input",
            confidence=0.95
        )

        result = self.shield.process(input_event)

        self._show_result(result)

        if not self._allow_progress(result):
            return

        self.shield.save_checkpoint(
            node="input",
            workflow_state=self.workflow_state,
            trusted=True
        )

        # ==========================================
        # RETRIEVAL
        # ==========================================

        print("\n===== RETRIEVAL =====")

        self.workflow_state["documents"] = [
            "RAG 是检索增强生成技术。",
            "RAG 会先检索资料，再由大模型生成回答。"
        ]

        retrieval_event = SecurityEvent(
            stage=SecurityStage.RETRIEVAL,
            risk_score=0.15,
            risk_type="normal_retrieval",
            confidence=0.95
        )

        result = self.shield.process(
            retrieval_event
        )

        self._show_result(result)

        if not self._allow_progress(result):
            return

        self.shield.save_checkpoint(
            node="retrieval",
            workflow_state=self.workflow_state,
            trusted=True
        )

        # ==========================================
        # GENERATION
        # ==========================================

        generation_success = False
        generation_attempt = 0

        while not generation_success:

            generation_attempt += 1

            print(
                f"\n===== GENERATION "
                f"ATTEMPT {generation_attempt} ====="
            )

            # --------------------------------------
            # 第一次生成：故意模拟风险
            # --------------------------------------

            if generation_attempt == 1:

                self.workflow_state["answer"] = (
                    "这是一段模拟的不安全回答"
                )

                generation_event = SecurityEvent(
                    stage=SecurityStage.GENERATION,
                    risk_score=0.7,
                    risk_type="unsafe_generation",
                    confidence=0.9
                )

            # --------------------------------------
            # 第二次生成：模拟安全回答
            # --------------------------------------

            else:

                self.workflow_state["answer"] = (
                    "RAG 是一种结合信息检索和"
                    "大语言模型生成的技术。"
                )

                generation_event = SecurityEvent(
                    stage=SecurityStage.GENERATION,
                    risk_score=0.1,
                    risk_type="normal_generation",
                    confidence=0.95
                )

            result = self.shield.process(
                generation_event
            )

            self._show_result(result)

            action = result[
                "flow_action"
            ]["flow_action"]

            # --------------------------------------
            # 被熔断 / BLOCK
            # --------------------------------------

            if action == "terminate":

                print(
                    "\n!!! WORKFLOW TERMINATED !!!"
                )

                return

            # --------------------------------------
            # 需要 Rollback
            # --------------------------------------

            if action == "rollback":

                print(
                    "\n>>> SECURITY ROLLBACK TRIGGERED"
                )

                rollback_result = result.get(
                    "rollback"
                )

                if (
                    rollback_result
                    and rollback_result["action"]
                    == "rollback"
                ):

                    # 真正恢复 Workflow State
                    self.workflow_state = (
                        rollback_result[
                            "workflow_state"
                        ]
                    )

                    print(
                        "Rollback To:",
                        rollback_result[
                            "rollback_to"
                        ]
                    )

                    print(
                        "Workflow State Restored:",
                        self.workflow_state
                    )

                    print(
                        "Retrying Generation..."
                    )

                    continue

                print(
                    "Rollback failed."
                )

                return

            # --------------------------------------
            # Generation 正常通过
            # --------------------------------------

            if not self._allow_progress(result):
                return

            generation_success = True

        # 保存安全 Generation Checkpoint
        self.shield.save_checkpoint(
            node="generation",
            workflow_state=self.workflow_state,
            trusted=True
        )

        # ==========================================
        # OUTPUT
        # ==========================================

        print("\n===== OUTPUT =====")

        output_event = SecurityEvent(
            stage=SecurityStage.OUTPUT,
            risk_score=0.1,
            risk_type="normal_output",
            confidence=0.95
        )

        result = self.shield.process(
            output_event
        )

        self._show_result(result)

        if not self._allow_progress(result):
            return

        # ==========================================
        # FINAL
        # ==========================================

        print("\n===== FINAL ANSWER =====")

        print(
            self.workflow_state["answer"]
        )

        print(
            "\n========== WORKFLOW FINISHED =========="
        )

    def _allow_progress(self, result):
        """Only explicit approval permits the current stage to advance.

        Handlers receive an isolated state snapshot and the decision result.
        They must return the boolean True after completing their check/action.
        Missing, failed or ambiguous responses stop the request.
        """
        action = result.get("flow_action", {}).get("flow_action")
        if action == "continue":
            return True
        handlers = {
            "verification": self.verifier,
            "restricted": self.restrictor,
        }
        handler = handlers.get(action)
        if action not in handlers:
            self.last_stop_reason = "action_requires_stop:" + str(action)
        elif handler is None:
            self.last_stop_reason = "handler_missing:" + action
        else:
            try:
                approved = handler(deepcopy(self.workflow_state), deepcopy(result))
                if approved is True:
                    return True
                self.last_stop_reason = "handler_not_approved:" + action
            except Exception as exc:
                self.last_stop_reason = "handler_error:" + action + ":" + type(exc).__name__
        print("WORKFLOW STOPPED:", self.last_stop_reason)
        return False

    def _is_terminated(self, result):

        return (
            result["flow_action"]["flow_action"]
            == "terminate"
        )

    def _show_result(self, result):

        print(
            "Global Risk:",
            result["global_risk"]
        )

        print(
            "Risk State:",
            result["risk_state"]
        )

        print(
            "Remaining Budget:",
            result["remaining_budget"]
        )

        print(
            "Decision:",
            result["decision"]["action"]
        )

        print(
            "Circuit:",
            result["circuit_breaker"]
        )