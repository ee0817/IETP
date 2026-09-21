# Orchestrator

全流程安全编排模块。

计划/当前原型组件：
- events/security_event.py
- core/risk_state.py
- core/risk_budget.py
- core/policy_engine.py
- core/flow_controller.py
- core/circuit_breaker.py
- core/shield.py
- checkpoint/manager.py
- workflow/runner.py

原则：执行状态可以回滚，但安全代价不可回滚。
