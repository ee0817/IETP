class FlowController:
    """
    根据 Policy Engine 的策略，
    决定工作流下一步执行哪个节点。
    """

    def route(self, policy: dict, current_stage: str):
        action = policy["action"]

        # 直接阻断
        if action == "block":
            return "terminate"

        # 谨慎模式，需要额外验证
        if action == "continue_with_verification":
            return "verification"

        # 限制模式
        if action == "restricted":
            if current_stage == "input":
                return "restricted_retrieval"

            elif current_stage == "retrieval":
                return "verification"

            elif current_stage == "generation":
                return "output_verification"

            return "verification"

        # 正常流程
        if action == "continue":
            normal_routes = {
                "input": "retrieval",
                "retrieval": "generation",
                "generation": "output",
                "output": "finish"
            }

            return normal_routes.get(
                current_stage,
                "finish"
            )

        raise ValueError(
            f"未知策略动作: {action}"
        )

    def execute_decision(self, decision: dict):
        """
        执行 Policy Engine 给出的最终流程决策。

        Flow Controller 不判断风险，
        只把策略决策转换成流程动作。
        """

        action = decision["action"]

        if action == "CONTINUE":
            return {
                "flow_action": "continue"
            }

        if action == "VERIFY":
            return {
                "flow_action": "verification"
            }

        if action == "RESTRICT":
            return {
                "flow_action": "restricted"
            }

        if action == "ROLLBACK":
            return {
                "flow_action": "rollback",
                "target_node": decision["rollback_to"]
            }

        if action == "BLOCK":
            return {
                "flow_action": "terminate"
            }

        raise ValueError(
            f"未知流程动作: {action}"
        )