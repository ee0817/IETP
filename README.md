# IETP - RAG-FlowShield

能修复的叫 bug，修不好的叫特性。

## 项目简介

本仓库用于团队共同开发 RAG 安全防御系统。当前主线是将输入、检索/上下文、生成、输出阶段的安全检测结果统一接入全流程安全编排层，实现风险状态聚合、策略决策、动态路由、Checkpoint 回滚、风险预算与熔断。

## 团队成员

| 成员 | 角色 |
| --- | --- |
| 胡康若旗 | 组长 |
| 李晓依 | 组员 / 全流程安全编排 |
| qiuji | 组员 |
| 张欣悦 | 组员 |

## 目录结构

```text
IETP/
├── src/
│   ├── orchestrator/       # 全流程安全编排
│   ├── interfaces/         # 统一数据结构和模块接口
│   └── modules/            # 各阶段安全检测模块
│       ├── input_security/
│       ├── retrieval_security/
│       ├── generation_security/
│       └── output_security/
├── docs/                   # 架构、接口、实验文档
├── data/                   # 测试/实验数据
├── members/                # 各成员个人开发区
│   ├── HK/
│   ├── e/
│   ├── qiuji/
│   └── xinyue/
└── assets images/          # 图片素材
```

## 开发约定

1. 个人实验和未稳定代码可先放 `members/<name>/`。
2. 准备联调的安全模块整理到 `src/modules/` 对应阶段。
3. 公共接口统一放 `src/interfaces/`，不要各自定义不兼容的数据结构。
4. 全流程控制代码统一放 `src/orchestrator/`。
5. **Detector 报告风险，Orchestrator 决定流程。** 检测模块不要自行决定最终 BLOCK / ROLLBACK。
6. 接口变更先更新 `docs/INTERFACES.md`，再进行联调。

## Retrieval V1 接口

```python
detect(query: str, documents: list[RetrievedChunk])
```

`RetrievedChunk` 必须包含 `chunk_id/content/source/score/metadata`。具体规范见 `docs/INTERFACES.md`。

## 分支规范

- `main` 为稳定版本，不直接推送。
- 每个人在自己的 feature 分支开发。
- 完成后通过 Pull Request 合并到 `main`。
