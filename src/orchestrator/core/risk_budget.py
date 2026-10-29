class RiskBudget:
    """
    RAG-FlowShield 风险预算管理器

    用于记录一次请求在整个生命周期中
    已经消耗了多少安全预算。
    """

    def __init__(self, total_budget: float = 1.0):
        self.total_budget = total_budget
        self.remaining_budget = total_budget

        self.consumed_budget = 0.0
        self.history = []
        self._events = {}

    def consume(self, event):
        """
        根据 SecurityEvent 消耗风险预算。
        """

        payload = event.to_dict()
        if event.event_id in self._events:
            if self._events[event.event_id] != payload:
                raise ValueError("event_id_conflict")
            return self.remaining_budget

        # 第一版：
        # 风险分数 × 检测置信度
        cost = event.risk_score * event.confidence

        self._events[event.event_id] = payload
        self.consumed_budget += cost

        self.remaining_budget = max(
            0.0,
            self.total_budget - self.consumed_budget
        )

        self.history.append({
            "event_id": event.event_id,
            "stage": event.stage.value,
            "risk_type": event.risk_type,
            "cost": round(cost, 3),
            "chunk_id": event.chunk_id,
            "detector_name": event.detector_name
        })

        return self.remaining_budget

    def is_exhausted(self):
        """
        判断风险预算是否已经耗尽。
        """
        return self.remaining_budget <= 0

    def get_state(self):
        return {
            "total_budget": self.total_budget,
            "consumed_budget": round(
                self.consumed_budget,
                3
            ),
            "remaining_budget": round(
                self.remaining_budget,
                3
            ),
            "exhausted": self.is_exhausted(),
            "event_count": len(self.history)
        }