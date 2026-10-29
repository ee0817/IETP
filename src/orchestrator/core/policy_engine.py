class PolicyEngine:
    """
    根据 Global Risk State 选择对应的安全策略
    """

    def decide(self, risk_state):
        state = risk_state.state

        if state == "NORMAL":
            return {
                "policy": "NORMAL_FLOW",
                "action": "continue",
                "verify": False,
                "restricted_retrieval": False,
                "allow_generation": True
            }

        elif state == "CAUTIOUS":
            return {
                "policy": "CAUTIOUS_FLOW",
                "action": "continue_with_verification",
                "verify": True,
                "restricted_retrieval": False,
                "allow_generation": True
            }

        elif state == "RESTRICTED":
            return {
                "policy": "RESTRICTED_FLOW",
                "action": "restricted",
                "verify": True,
                "restricted_retrieval": True,
                "allow_generation": True
            }

        elif state == "BLOCKED":
            return {
                "policy": "BLOCK_FLOW",
                "action": "block",
                "verify": True,
                "restricted_retrieval": True,
                "allow_generation": False
            }

        else:
            raise ValueError(
                f"未知风险状态: {state}"
            )

    def decide_action(self, risk_state, event):
        """
        综合 Global Risk State 和 SecurityEvent，
        做出最终流程级安全决策。

        最终动作：
        CONTINUE
        VERIFY
        RESTRICT
        ROLLBACK
        BLOCK
        """

        state = risk_state.state
        risk_type = event.risk_type

        # Global blocking takes precedence over recovery actions.
        if state == "BLOCKED":
            return {"action": "BLOCK", "reason": "全局风险超过安全阈值"}

        # =========================
        # 1. 输入源本身存在攻击
        # =========================

        if event.risk_score > 0 and risk_type == "prompt_injection":
            return {
                "action": "BLOCK",
                "reason": "输入本身存在攻击风险，回滚无法消除风险"
            }

        # =========================
        # 2. 检索内容受到污染
        # =========================

        if event.risk_score > 0 and risk_type in [
            "poisoned_document",
            "malicious_context"
        ]:
            return {
                "action": "ROLLBACK",
                "rollback_to": "input",
                "reason": "检索内容存在风险，需要重新执行检索"
            }

        # =========================
        # 3. 生成阶段出现风险
        # =========================

        if event.risk_score > 0 and risk_type in [
            "unsafe_generation",
            "sensitive_information"
        ]:
            return {
                "action": "ROLLBACK",
                "rollback_to": "retrieval",
                "reason": "生成结果存在风险，恢复到生成前安全状态"
            }

        # =========================
        # 4. 没有特殊风险类型
        #    再根据 Global Risk State 决策
        # =========================

        if state == "NORMAL":
            return {
                "action": "CONTINUE"
            }

        if state == "CAUTIOUS":
            return {
                "action": "VERIFY"
            }

        if state == "RESTRICTED":
            return {
                "action": "RESTRICT"
            }

        if state == "BLOCKED":
            return {
                "action": "BLOCK",
                "reason": "全局风险超过安全阈值"
            }

        raise ValueError(
            f"未知风险状态: {state}"
        )

    def decide_with_budget(
            self,
            risk_state,
            risk_budget,
            event
    ):
        """
        综合三个信息做最终决策：

        1. Global Risk State
        2. Risk Budget
        3. 当前 SecurityEvent
        """

        # =====================================
        # 1. Risk Budget 已经耗尽
        # =====================================

        if risk_budget.is_exhausted():
            return {
                "action": "BLOCK",
                "reason": "风险预算已经耗尽"
            }

        # =====================================
        # 2. 输入本身存在攻击
        # =====================================

        # Never downgrade a global block to rollback or restriction.
        if risk_state.state == "BLOCKED":
            return {"action": "BLOCK", "reason": "全局风险超过安全阈值"}

        if event.risk_score > 0 and event.risk_type == "prompt_injection":
            return {
                "action": "BLOCK",
                "reason": "输入本身存在攻击风险"
            }

        # =====================================
        # 3. 检索内容存在污染
        # =====================================

        if event.risk_score > 0 and event.risk_type in [
            "poisoned_document",
            "malicious_context"
        ]:
            return {
                "action": "ROLLBACK",
                "rollback_to": "input",
                "reason": "检索内容存在风险，需要重新检索"
            }

        # =====================================
        # 4. 生成阶段出现风险
        # =====================================

        if event.risk_score > 0 and event.risk_type in [
            "unsafe_generation",
            "sensitive_information"
        ]:
            return {
                "action": "ROLLBACK",
                "rollback_to": "retrieval",
                "reason": "生成结果存在风险，需要恢复到生成前状态"
            }

        # =====================================
        # 5. Budget 较低时，提高防御等级
        # =====================================

        if risk_budget.remaining_budget <= 0.3:
            return {
                "action": "RESTRICT",
                "reason": "剩余风险预算较低"
            }

        # =====================================
        # 6. 最后根据 Global Risk State
        # =====================================

        if risk_state.state == "NORMAL":
            return {
                "action": "CONTINUE"
            }

        if risk_state.state == "CAUTIOUS":
            return {
                "action": "VERIFY"
            }

        if risk_state.state == "RESTRICTED":
            return {
                "action": "RESTRICT"
            }

        if risk_state.state == "BLOCKED":
            return {
                "action": "BLOCK",
                "reason": "全局风险超过安全阈值"
            }

        raise ValueError(
            f"未知风险状态: {risk_state.state}"
        )