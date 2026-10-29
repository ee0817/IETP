# RAG-FlowShield Orchestrator 2.0

全流程安全编排原型：SecurityEvent、RiskState、RiskBudget、PolicyEngine、FlowController、CheckpointManager、CircuitBreaker和模拟WorkflowRunner。执行状态可以回滚，安全代价不可回滚。

## 本地验证

仅使用Python标准库，无需API密钥。在仓库根目录运行：

```sh
cd src/orchestrator
python -B -m unittest discover -s validation -p "test_*.py" -v
python -B validation/run_orchestrator_scenarios.py --source . --out validation/latest_run
```

验证基线：32项模拟事件场景、39组专项/联调测试通过，19个演示脚本正常退出。多数演示脚本无断言，退出成功不等于正确性验证。

## 接入与限制

详见[接入说明](INTEGRATION.md)。仓库公共检索接口继续沿用docs/INTERFACES.md，本目录说明补充安全事件与编排契约。

这是可独立运行的模拟编排原型，尚未集成组员真实检测器、真实检索或模型；Runner只内建生成回滚重试，其他回滚目标需真实执行器实现节点跳转。共享实例不支持并发。风险聚合规则尚待真实数据校准，未评估真实攻击效果。
