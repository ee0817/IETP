from core.circuit_breaker import CircuitBreaker


breaker = CircuitBreaker(
    max_retries=3,
    max_rollbacks=2
)


print("===== 初始状态 =====")
print(breaker.get_state())


# 第一次回滚
breaker.record_rollback()

print("\n===== 第一次 Rollback =====")
print(breaker.get_state())


# 第一次重试
breaker.record_retry()

print("\n===== 第一次 Retry =====")
print(breaker.get_state())


# 第二次回滚
breaker.record_rollback()

print("\n===== 第二次 Rollback =====")
print(breaker.get_state())


# 判断是否熔断
if breaker.is_open():

    print("\n!!! CIRCUIT OPEN !!!")
    print("达到安全限制，终止当前工作流")

else:

    print("\nCircuit Closed")
    print("允许继续执行")