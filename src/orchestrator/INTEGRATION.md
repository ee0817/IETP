# RAG-FlowShield 2.0 组员接入说明

## 当前范围
本版本为安全编排原型；WorkflowRunner仍使用模拟文档和回答。validation/test_mock_integration.py通过四阶段模拟检测器接入编排层，不代表真实RAG或攻击评估。检测异常转为空结果仅是模拟适配器的示例，生产环境仍需配置真实超时与错误记录。

## 接入入口
每个请求使用独立RAGFlowShield实例；顺序复用时，在新请求开始调用reset_request()。同一次请求的回滚、重试禁止重置。不要跨并发请求共用实例。
检测器应返回SecurityEvent，再调用shield.process(event)。原生字典须由适配器显式转换；process不直接接受字典。stage必须为SecurityStage枚举。

```python
event = SecurityEvent(
    stage=SecurityStage.RETRIEVAL,
    risk_score=0.4,
    risk_type="suspicious_document",
    confidence=0.9,
    chunk_id="doc-02/chunk-03",
    detector_name="retrieval_filter",
)
result = shield.process(event)
action = result["flow_action"]["flow_action"]
```

## 事件约定
- risk_score、confidence：0到1之间的有限数值，不接受布尔值。risk_score=0表示检测完成且未发现风险；检测失败、超时、空结果不能伪装成零风险。
- risk_type：非空字符串。prompt_injection（阻断）；poisoned_document/malicious_context（回滚input）；unsafe_generation/sensitive_information（回滚retrieval）。上述类型仅在风险分大于0时触发；其他类型走全局风险/预算策略。全局BLOCKED、预算耗尽优先阻断。
- chunk_id、detector_name：可选非空字符串，默认None。用于追踪，不提供身份认证。
- event_id、timestamp：默认自动生成。重发同一事件须保留全部字段；相同ID、相同内容为重复；相同ID、不同内容阻断。新的检测尝试生成新ID。不同ID不会自动进行跨检测器语义去重。

## 动作执行
- continue：进入下一阶段。
- verification：调用真实复核器；restricted：执行实际限制措施。Runner中的verifier/restrictor接收(state_snapshot, result_snapshot)，只有严格返回True才放行；缺失、异常或其他返回值停止。此接口暂不支持返回修改后的工作流内容。
- rollback：从result["rollback"]取得恢复状态，按rollback_to重新执行对应流程。真实执行器必须实现节点跳转；当前演示Runner只内建生成回滚重试。禁止将所有目标一律当作重生成。
- terminate：停止，不输出待审核回答。
- duplicate_event=True：响应是原结果的副本，禁止重复执行外部动作；它不代表当前最新状态，查当前状态应读取shield。熔断已打开时优先返回终止。
- 复核和限制器只有完成实际检查/措施后才能返回True，不能用恒True回调接入真实业务。

## 状态与检查点
主global_risk/risk_state反映处理后的有效状态。risk_before为本次事件更新后、回滚前状态，risk_after为处理后状态；熔断提前返回暂无这两项，不要当作必填。event=None表示没有处理新的有效事件。
仅在阶段安全检查及复核通过后保存可信检查点。保存工作流文档、答案等可重建状态，避免把不可逆外部操作当作可回滚状态。
风险候选值=0.7×最高阶段风险+0.3×非零阶段平均风险。执行分支内保留全局风险高水位，可信回滚允许恢复风险；预算和重试计数不回退。此工程规则尚未经过真实样本校准。

## 本地验证
在项目根目录执行：
```
python -B validation/test_mock_integration.py
python -B validation/run_orchestrator_scenarios.py --source . --out validation/latest_run
```
第二个入口会运行32项断言场景及19个旧演示脚本。旧脚本大部分仍无断言，退出正常不能等同于正确性证明。
联调测试覆盖正常链路、四阶段空结果/异常、复核通过/拒绝/异常、生成回滚重试及持续风险熔断；未覆盖真实网络超时、并发、真实模型或跨模块语义去重。
