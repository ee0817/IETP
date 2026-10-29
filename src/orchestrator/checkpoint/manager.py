from copy import deepcopy
from datetime import datetime
from typing import Any, Dict, List, Optional


class CheckpointManager:
    """
    RAG-FlowShield 安全检查点管理器

    负责：
    1. 保存关键节点的执行状态
    2. 保存当时的安全状态
    3. 查找最近的可信检查点
    4. 执行状态回滚
    """

    def __init__(self):
        self.checkpoints: List[Dict[str, Any]] = []

    def save(
        self,
        node: str,
        workflow_state: Dict[str, Any],
        risk_state: Dict[str, Any],
        trusted: bool = True
    ):
        """
        保存一个安全检查点
        """

        checkpoint = {
            "checkpoint_id": len(self.checkpoints),
            "timestamp": datetime.now().isoformat(),
            "node": node,

            # deepcopy 防止后面的状态变化影响历史检查点
            "workflow_state": deepcopy(workflow_state),
            "risk_state": deepcopy(risk_state),

            # 当前检查点是否可信
            "trusted": trusted
        }

        self.checkpoints.append(checkpoint)

        return checkpoint

    def get_latest_trusted(
        self,
        before_node: Optional[str] = None
    ):
        """
        获取最近一个可信检查点
        """

        for checkpoint in reversed(self.checkpoints):

            if not checkpoint["trusted"]:
                continue

            if (
                before_node is not None
                and checkpoint["node"] == before_node
            ):
                continue

            return deepcopy(checkpoint)

        return None

    def rollback(self):
        """
        回退到最近一个可信检查点
        """

        checkpoint = self.get_latest_trusted()

        if checkpoint is None:
            raise RuntimeError(
                "没有可用于回滚的可信 Checkpoint"
            )

        return {
            "rollback_to": checkpoint["node"],
            "workflow_state": deepcopy(
                checkpoint["workflow_state"]
            ),
            "risk_state": deepcopy(
                checkpoint["risk_state"]
            )
        }

    def rollback_to(self, target_node: str):
        """
        回滚到 Policy Engine 指定的目标节点。

        Checkpoint Manager 不负责判断为什么回滚，
        只负责找到目标 Checkpoint 并恢复。
        """

        for checkpoint in reversed(self.checkpoints):

            if (
                    checkpoint["node"] == target_node
                    and checkpoint["trusted"]
            ):
                return {
                    "action": "rollback",
                    "rollback_to": checkpoint["node"],
                    "workflow_state": deepcopy(
                        checkpoint["workflow_state"]
                    ),
                    "risk_state": deepcopy(
                        checkpoint["risk_state"]
                    )
                }

        return {
            "action": "block",
            "reason": f"没有找到可信的 {target_node} Checkpoint"
        }

    def mark_untrusted(self, checkpoint_id: int):
        """
        如果后来发现某个检查点其实受到污染，
        可以把它标记为不可信。
        """

        for checkpoint in self.checkpoints:

            if checkpoint["checkpoint_id"] == checkpoint_id:
                checkpoint["trusted"] = False
                return

        raise ValueError(
            f"Checkpoint {checkpoint_id} 不存在"
        )

    def get_history(self):
        """
        查看全部 Checkpoint
        """

        return deepcopy(self.checkpoints)