class CircuitBreaker:
    """
    RAG-FlowShield 熔断器

    防止工作流因为持续风险而
    无限 Retry / Rollback。
    """

    def __init__(
        self,
        max_retries: int = 3,
        max_rollbacks: int = 2
    ):
        self.max_retries = max_retries
        self.max_rollbacks = max_rollbacks

        self.retry_count = 0
        self.rollback_count = 0

        self.open = False

    def record_retry(self):
        """
        记录一次重试
        """
        self.retry_count += 1
        self._check()

    def record_rollback(self):
        """
        记录一次回滚
        """
        self.rollback_count += 1
        self._check()

    def _check(self):
        """
        判断是否达到熔断条件
        """

        if (
            self.retry_count >= self.max_retries
            or self.rollback_count >= self.max_rollbacks
        ):
            self.open = True

    def is_open(self):
        """
        True = 已经熔断
        """
        return self.open

    def reset(self):
        """
        新请求开始时可以重置
        """
        self.retry_count = 0
        self.rollback_count = 0
        self.open = False

    def get_state(self):
        return {
            "retry_count": self.retry_count,
            "rollback_count": self.rollback_count,
            "max_retries": self.max_retries,
            "max_rollbacks": self.max_rollbacks,
            "circuit_open": self.open
        }