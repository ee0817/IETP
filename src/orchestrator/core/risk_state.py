from typing import Dict, List

from events.security_event import SecurityEvent


class RiskState:
    """
    RAG-FlowShield 全局风险状态管理器

    作用：
    1. 接收不同阶段产生的 SecurityEvent
    2. 保存各阶段风险
    3. 保存风险事件历史
    4. 计算当前全局风险值
    5. 根据全局风险判断系统当前状态
    """

    def __init__(self):

        # 各阶段当前风险值
        self.stage_risks: Dict[str, float] = {
            "input": 0.0,
            "retrieval": 0.0,
            "context": 0.0,
            "generation": 0.0,
            "output": 0.0
        }

        # 保存所有收到的安全事件
        self.event_history: List[SecurityEvent] = []

        # 当前全局风险值
        self.global_risk: float = 0.0

        # 当前安全状态
        self.state: str = "NORMAL"

    def update(self, event: SecurityEvent):
        """
        接收一个新的 SecurityEvent，并更新全局风险状态
        """

        stage = event.stage.value

        if stage not in self.stage_risks:
            raise ValueError(f"未知的安全阶段: {stage}")

        # 保存事件
        self.event_history.append(event)

        # 同一阶段出现多个风险事件时，暂时保留最高风险
        self.stage_risks[stage] = max(
            self.stage_risks[stage],
            event.risk_score
        )

        # 重新计算全局风险
        self._calculate_global_risk()

        # 更新风险状态
        self._update_state()

    def _calculate_global_risk(self):
        """
        单次执行分支内保留全局风险高水位；可信回滚可恢复较低状态。
        候选风险融合方法：

        Global Risk =
        0.7 × 当前最高阶段风险
        +
        0.3 × 已发生风险阶段的平均风险
        """

        active_risks = [
            risk
            for risk in self.stage_risks.values()
            if risk > 0
        ]

        if not active_risks:
            self.global_risk = 0.0
            return

        max_risk = max(active_risks)
        avg_risk = sum(active_risks) / len(active_risks)

        candidate = 0.7 * max_risk + 0.3 * avg_risk
        # Within one execution branch, new evidence cannot dilute prior risk.
        # restore() explicitly permits returning to a trusted checkpoint state.
        self.global_risk = max(self.global_risk, candidate)

    def _update_state(self):
        """
        根据 Global Risk 划分当前风险状态
        """

        if self.global_risk < 0.3:
            self.state = "NORMAL"

        elif self.global_risk < 0.6:
            self.state = "CAUTIOUS"

        elif self.global_risk < 0.85:
            self.state = "RESTRICTED"

        else:
            self.state = "BLOCKED"

    def get_state(self):
        """
        返回当前完整风险状态
        """

        return {
            "stage_risks": self.stage_risks.copy(),
            "global_risk": round(self.global_risk, 3),
            "state": self.state,
            "event_count": len(self.event_history)
        }

    def restore(self, snapshot: dict):
        """
        从 Checkpoint 快照恢复全局风险状态。
        """

        self.stage_risks = snapshot[
            "stage_risks"
        ].copy()

        self.global_risk = snapshot[
            "global_risk"
        ]

        self.state = snapshot[
            "state"
        ]