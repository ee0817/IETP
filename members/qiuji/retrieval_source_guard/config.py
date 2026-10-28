# -*- coding: utf-8 -*-
"""集中配置：阈值、注入规则、恶意意图词表、来源信任分级、角色-资源权限矩阵。

data/ 下的词表文件存在且解析成功时覆盖内置默认值；
文件缺失 / 解析失败 / 规则为空时自动回退默认配置（永不返回空规则，防止静默放行）。
"""
from __future__ import annotations

import functools
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

PACKAGE_DIR = Path(__file__).resolve().parent
DATA_DIR = PACKAGE_DIR / "data"
PATTERNS_DIR = DATA_DIR / "patterns"

# ------------------------------------------------------------------ 阈值配置


@dataclass
class Thresholds:
    report_min: float = 0.35        # 综合风险分低于该值不上报事件
    injection_confirm: float = 0.60  # >= 判 prompt_injection / poisoned_document
    injection_suspect: float = 0.30  # >= 判 suspicious_input / malicious_context
    intent_min: float = 0.50         # 恶意意图最低上报分数
    pair_window: int = 24            # 动作-资源关键词配对的最大字符间距


THRESHOLDS = Thresholds()

# ------------------------------------------------------- 注入规则（内置默认值）
# 三元组：(权重 0~1, 规则标签, 正则表达式)，词表文件格式与之相同（Tab 分隔）

DEFAULT_INJECTION_PATTERNS: List[Tuple[float, str, str]] = [
    # ---------------- 英文 ----------------
    (0.95, "en_ignore_instructions",
     r"ignore\s+(?:all\s+|the\s+)?(?:previous|prior|above|earlier|above)\s+"
     r"(?:instructions?|prompts?|context|rules)"),
    (0.90, "en_disregard_instructions",
     r"disregard\s+(?:all\s+|the\s+|any\s+)?(?:previous|prior|above)\s+"
     r"(?:instructions?|prompts?|rules)"),
    (0.90, "en_forget_instructions",
     r"forget\s+(?:all\s+|your\s+|the\s+)?(?:previous|prior|earlier)\s+"
     r"(?:instructions?|prompts?|rules)"),
    (0.90, "en_dan", r"do\s+anything\s+now|\bDAN\b"),
    (0.85, "en_reveal_system_prompt",
     r"(?:reveal|show|print|repeat|leak)\s+(?:me\s+)?(?:your|the)\s+"
     r"(?:system\s+)?(?:prompt|instructions|initial\s+instructions)"),
    (0.75, "en_developer_mode", r"(?:enable|enter|activate)\s+developer\s+mode"),
    (0.70, "en_you_are_now", r"you\s+are\s+now\s+(?:a|an|in)\b"),
    (0.55, "en_new_instructions", r"new\s+instructions?\s*[:：]"),
    (0.45, "en_system_prompt", r"system\s+prompt"),
    # ---------------- 中文 ----------------
    (0.95, "zh_ignore_instructions",
     r"(?:忽略|无视|不管)(?:以上|之前|前面|上述|此前|所有|先前)[^\n。；;]{0,8}"
     r"(?:指令|提示词?|要求|规则|内容)"),
    (0.85, "zh_forget_instructions",
     r"(?:忘记|忘掉|清空)(?:所有|之前|以前|此前)?[^\n。；;]{0,4}(?:指令|规则|提示)"),
    (0.85, "zh_reveal_system_prompt",
     r"(?:输出|泄露|透露|显示|告诉我)(?:你的|您的|系统)?(?:系统)?(?:提示词|初始指令|系统指令)"),
    (0.80, "zh_developer_mode",
     r"(?:进入|开启|启用|切换到)(?:开发者|调试|越狱|管理员)模式"),
    (0.70, "zh_you_are_now",
     r"你现在是(?:一个|一名|一位)?|你不再是[^\n。；;]{0,10}(?:助手|AI)"),
    (0.45, "zh_role_play", r"扮演(?:一个|一名|一位)?"),
]

# ------------------------------------------------------- 恶意意图关键词（默认）
# 三元组：(意图类别, 权重, 关键词)，文件格式相同（Tab 分隔，大小写不敏感匹配）

DEFAULT_MALICIOUS_KEYWORDS: List[Tuple[str, float, str]] = [
    # 数据窃取
    ("data_theft", 0.85, "全部用户数据"),
    ("data_theft", 0.85, "所有用户数据"),
    ("data_theft", 0.80, "用户密码"),
    ("data_theft", 0.80, "数据库密码"),
    ("data_theft", 0.85, "导出密钥"),
    ("data_theft", 0.75, "身份证号"),
    ("data_theft", 0.80, "credentials"),
    ("data_theft", 0.85, "password list"),
    ("data_theft", 0.85, "dump the database"),
    # 系统破坏
    ("destruction", 0.90, "删除数据库"),
    ("destruction", 0.90, "删除所有数据"),
    ("destruction", 0.90, "删除审计日志"),
    ("destruction", 0.85, "清空数据库"),
    ("destruction", 0.85, "格式化磁盘"),
    ("destruction", 0.90, "drop table"),
    ("destruction", 0.90, "rm -rf"),
    ("destruction", 0.85, "wipe all"),
    # 欺诈 / 违法
    ("fraud_illegal", 0.80, "洗钱"),
    ("fraud_illegal", 0.85, "制造毒品"),
    ("fraud_illegal", 0.85, "制作炸药"),
    ("fraud_illegal", 0.80, "诈骗话术"),
    ("fraud_illegal", 0.80, "伪造证件"),
    ("fraud_illegal", 0.80, "money laundering"),
]

# ------------------------------------------------------- 来源可信度（默认值）

DEFAULT_TRUST_LEVELS: Dict[str, float] = {
    "official": 0.99,  # 官方权威来源
    "internal": 0.90,  # 企业内部可信来源
    "external": 0.55,  # 外部来源（可信度有限）
    "unknown": 0.15,   # 未知来源
}

# (source 子串（大小写不敏感）, 信任等级)，按顺序首次命中
DEFAULT_TRUST_SOURCES: List[Tuple[str, str]] = [
    ("official-docs.corp", "official"),
    ("gov.cn", "official"),
    ("wiki.corp", "internal"),
    ("confluence", "internal"),
    ("wikipedia.org", "external"),
    ("mozilla.org", "external"),
]

# 来源黑名单（子串匹配，大小写不敏感）：命中 -> trust_status=BLOCKED, risk_score 高
# 默认为空，可由 data/trust_sources.yaml 或上层配置扩展
DEFAULT_BLACKLISTED_SOURCES: Set[str] = set()

# ------------------------------------------------------- 请求侧越权：权限矩阵
# 角色 -> 资源 -> 允许的动作集合；"*" 表示通配（admin 全权）

DEFAULT_ROLE_MATRIX: Dict[str, Dict[str, Set[str]]] = {
    "admin": {"*": {"*"}},
    "staff": {
        "user_data": {"read"},
        "reports": {"read", "export"},
        "knowledge_base": {"read"},
    },
    "viewer": {
        "knowledge_base": {"read"},
        "reports": {"read"},
    },
}

# 仅管理员可访问的资源：普通用户命中时定性为 privilege_escalation
ADMIN_ONLY_RESOURCES: Set[str] = {"system_config", "audit_logs", "secret_data"}

DEFAULT_ACTION_KEYWORDS: Dict[str, List[str]] = {
    "read": ["查询", "查看", "读取", "看一下", "检索", "read", "view", "query"],
    "export": ["导出", "下载", "export", "download"],
    "delete": ["删除", "清空", "delete", "drop", "remove"],
    "modify": ["修改", "更改", "更新", "配置", "调整", "modify", "update", "edit"],
}

DEFAULT_RESOURCE_KEYWORDS: Dict[str, List[str]] = {
    "user_data": ["用户数据", "用户信息", "个人信息", "user data", "users table"],
    "system_config": ["系统配置", "权限配置", "系统设置", "system config"],
    "audit_logs": ["审计日志", "操作日志", "audit log", "audit logs"],
    "reports": ["报表", "报告", "report", "reports"],
    "knowledge_base": ["知识库", "文档", "knowledge base", "documents"],
}

# ------------------------------------------------------- 检索侧越权：密级映射
# 文档 metadata.classification -> 允许访问的角色列表；None 表示公开（任何人）

DEFAULT_CLASSIFICATION_ROLES: Dict[str, Optional[List[str]]] = {
    "public": None,
    "internal": ["admin", "staff", "viewer"],
    "confidential": ["admin", "staff"],
    "secret": ["admin"],
}

# ------------------------------------------- Prompt Guard 可选增强（默认关闭）
# 开启需安装可选依赖：pip install -r requirements-optional.txt（transformers + torch）
# 依赖或模型加载失败时自动降级，v1.0 纯规则路径不受影响。

PROMPT_GUARD_ENABLED = False  # 默认 False：仅规则；True 后弱信号会调 Prompt Guard
PROMPT_GUARD_THRESHOLD = 0.5  # 模型攻击概率 >= 该值判为 prompt_injection

# 官方 HuggingFace 三分类权重（0=benign, 1=injection, 2=jailbreak）
PROMPT_GUARD_HF_MODEL_ID = "meta-llama/Prompt-Guard-2-22M"


@functools.cache
def _find_models_root() -> Optional[Path]:
    """从 PACKAGE_DIR.parent 向上查找名为 "models" 的目录（最多回溯 6 层）。

    迁移到 members/qiuji/ 子目录后，PACKAGE_DIR.parent 不再是项目根，
    需向上回溯才能定位项目级 models/ 目录（Prompt Guard / BGE-M3 权重存放处）。
    从 PACKAGE_DIR.parent 起步以跳过本包自带的 models/ 子目录（Python 包目录，
    非 ML 权重目录）；找不到时返回 None，由上层回退到 HF 仓库 ID（允许联网下载）。
    """
    current = PACKAGE_DIR.parent
    for _ in range(6):
        candidate = current / "models"
        if candidate.is_dir():
            # 排除包内 Python models/ 子目录（含 __init__.py 的），
            # 仅接受含 config.json 的 ML 权重目录或空目录之外的真实权重目录。
            # 这里仅按目录存在性返回，由上层 _find_local_*_dir() 用 rglob(config.json)
            # 二次确认；若该 models/ 下无权重快照，上层返回 None 走 HF 回退。
            return candidate
        if current.parent == current:
            break
        current = current.parent
    return None


@functools.cache
def _find_local_prompt_guard_dir() -> Optional[Path]:
    """在 _find_models_root() 下递归查找 Llama-Prompt-Guard-2-22M 快照目录。

    匹配规则：路径包含 "llama-prompt-guard-2-22m"（大小写不敏感）且同级存在
    config.json 的目录；多匹配时按路径长度升序取**最短**，保证选择最浅层
    目录且结果稳定可复现（不受 rglob 顺序影响）。

    不写死 models/models/.../snapshots/master 层级，兼容 ModelScope 缓存、
    HuggingFace 缓存或人工放置等任意目录结构；找不到或读取异常返回 None，
    由上层回退到 HF 仓库 ID。

    加 @functools.cache 缓存：本函数在 import 期即被调用一次取
    PROMPT_GUARD_MODEL_ID / LOCAL_FILES_ONLY，后续多次调用复用结果，
    避免重复遍历 models 目录树。
    """
    models_root = _find_models_root()
    if not models_root:
        return None
    marker = "llama-prompt-guard-2-22m"
    candidates: List[Path] = []
    try:
        for config_json in models_root.rglob("config.json"):
            if marker in str(config_json).lower():
                candidates.append(config_json.parent)
    except OSError:
        return None
    if not candidates:
        return None
    # 多匹配时取路径最短者：层级最浅、最稳定；同长度时按字符串排序保持确定性
    candidates.sort(key=lambda p: (len(str(p)), str(p)))
    return candidates[0]


# 本地快照存在则默认使用本地路径（local_files_only=True，不联网），
# 否则回退 HF 仓库 ID。
_PROMPT_GUARD_LOCAL_DIR = _find_local_prompt_guard_dir()
PROMPT_GUARD_MODEL_ID: str = (
    str(_PROMPT_GUARD_LOCAL_DIR) if _PROMPT_GUARD_LOCAL_DIR else PROMPT_GUARD_HF_MODEL_ID
)
PROMPT_GUARD_LOCAL_FILES_ONLY: bool = _PROMPT_GUARD_LOCAL_DIR is not None


# ------------------------------------------- BGE-M3 语义离群可选增强（默认关闭）
# 开启需安装可选依赖：transformers + torch（与 Prompt Guard 共用 requirements-optional.txt）
# 用途：检测语义离群的疑似投毒文档；模型不可用时降级为 v1.0 规则路径。
BGE_M3_ENABLED = False  # 默认 False：仅规则；True 后投毒检测增加语义离群路径
BGE_M3_HF_MODEL_ID = "BAAI/bge-m3"
BGE_M3_OUTLIER_THRESHOLD = 0.65  # 综合离群分 >= 该值判为 poisoned_document
BGE_M3_DOC_KNN_K = 3              # 文档间 kNN 信号的 K（< 文档数时跳过该信号）
BGE_M3_BASELINE_TOPK = 5         # 基线偏离信号取 Top-K 均值（基线不足 K 时用全部）
# 三信号权重（任一信号因数据不足跳过时，剩余权重归一化）
BGE_M3_WEIGHT_DOC_KNN = 0.40     # 文档间 kNN：与同批其它文档的平均相似度越低越离群
BGE_M3_WEIGHT_QUERY_DEVIATION = 0.30  # 查询偏离：与查询相似度越低越偏离用户意图
BGE_M3_WEIGHT_BASELINE_DEVIATION = 0.30  # 基线偏离：与干净语料相似度越低越可疑


@functools.cache
def _find_local_bge_m3_dir() -> Optional[Path]:
    """在 _find_models_root() 下递归查找 BGE-M3 模型目录。

    匹配规则：路径包含 "bge-m3"（大小写不敏感）且同级存在 config.json；
    多匹配按路径长度升序取最短，同长度按字符串次序兜底，结果稳定可复现。
    找不到或读取异常返回 None，由上层回退到 HF 仓库 ID。
    """
    models_root = _find_models_root()
    if not models_root:
        return None
    marker = "bge-m3"
    candidates: List[Path] = []
    try:
        for config_json in models_root.rglob("config.json"):
            if marker in str(config_json).lower():
                candidates.append(config_json.parent)
    except OSError:
        return None
    if not candidates:
        return None
    candidates.sort(key=lambda p: (len(str(p)), str(p)))
    return candidates[0]


_BGE_M3_LOCAL_DIR = _find_local_bge_m3_dir()
BGE_M3_MODEL_PATH: str = (
    str(_BGE_M3_LOCAL_DIR) if _BGE_M3_LOCAL_DIR else BGE_M3_HF_MODEL_ID
)
BGE_M3_LOCAL_FILES_ONLY: bool = _BGE_M3_LOCAL_DIR is not None


# ------------------------------------------------------------------ 词表加载


def _read_tsv_rules(path: Path) -> List[Tuple[str, ...]]:
    """读取 Tab 分隔的规则文件，忽略空行与 # 注释；任何异常返回空列表。"""
    rows: List[Tuple[str, ...]] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                parts = tuple(p.strip() for p in line.split("\t") if p.strip())
                if len(parts) >= 3:
                    rows.append(parts[:3])
    except OSError:
        return []
    return rows


def load_injection_patterns() -> List[Tuple[float, str, str]]:
    raw = _read_tsv_rules(PATTERNS_DIR / "injection_patterns.txt")
    patterns: List[Tuple[float, str, str]] = []
    for weight, label, regex in raw:
        try:
            patterns.append((float(weight), label, regex))
        except ValueError:
            continue
    # 词表缺失或为空时回退内置规则，避免规则静默失效导致全部放行
    return patterns or list(DEFAULT_INJECTION_PATTERNS)


def load_malicious_keywords() -> List[Tuple[str, float, str]]:
    raw = _read_tsv_rules(PATTERNS_DIR / "malicious_keywords.txt")
    keywords: List[Tuple[str, float, str]] = []
    for category, weight, keyword in raw:
        try:
            keywords.append((category, float(weight), keyword))
        except ValueError:
            continue
    return keywords or list(DEFAULT_MALICIOUS_KEYWORDS)


def load_trust_config() -> Tuple[Dict[str, float], List[Tuple[str, str]]]:
    """优先读取 data/trust_sources.yaml（需 PyYAML），否则回退内置默认值。"""
    path = DATA_DIR / "trust_sources.yaml"
    try:  # 可选依赖：没有 PyYAML 时静默回退
        import yaml  # type: ignore

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        levels = {str(k): float(v) for k, v in data["levels"].items()}
        sources = [(str(s["match"]), str(s["level"])) for s in data["sources"]]
        if levels and sources:
            return levels, sources
    except Exception:
        pass
    return dict(DEFAULT_TRUST_LEVELS), list(DEFAULT_TRUST_SOURCES)


# ------------------------------------------------------------------ 配置聚合


@dataclass
class MaliciousKeyword:
    category: str
    weight: float
    keyword: str


@dataclass
class GuardConfig:
    thresholds: Thresholds
    injection_rules: List[Any] = field(default_factory=list)  # List[scoring.PatternRule]
    malicious_keywords: List[MaliciousKeyword] = field(default_factory=list)
    trust_levels: Dict[str, float] = field(default_factory=dict)
    trust_sources: List[Tuple[str, str]] = field(default_factory=list)
    blacklisted_sources: Set[str] = field(default_factory=set)
    role_matrix: Dict[str, Dict[str, Set[str]]] = field(default_factory=dict)
    action_keywords: Dict[str, List[str]] = field(default_factory=dict)
    resource_keywords: Dict[str, List[str]] = field(default_factory=dict)
    classification_roles: Dict[str, Optional[List[str]]] = field(default_factory=dict)
    # Prompt Guard 可选增强
    prompt_guard_enabled: bool = PROMPT_GUARD_ENABLED
    prompt_guard_model_id: str = PROMPT_GUARD_MODEL_ID
    prompt_guard_threshold: float = PROMPT_GUARD_THRESHOLD
    prompt_guard_local_files_only: bool = PROMPT_GUARD_LOCAL_FILES_ONLY
    # BGE-M3 语义离群可选增强（默认关闭，关闭时投毒检测退回纯规则）
    bge_m3_enabled: bool = BGE_M3_ENABLED
    bge_m3_model_path: str = BGE_M3_MODEL_PATH
    bge_m3_local_files_only: bool = BGE_M3_LOCAL_FILES_ONLY
    bge_m3_outlier_threshold: float = BGE_M3_OUTLIER_THRESHOLD
    bge_m3_doc_knn_k: int = BGE_M3_DOC_KNN_K
    bge_m3_baseline_topk: int = BGE_M3_BASELINE_TOPK
    bge_m3_weight_doc_knn: float = BGE_M3_WEIGHT_DOC_KNN
    bge_m3_weight_query_deviation: float = BGE_M3_WEIGHT_QUERY_DEVIATION
    bge_m3_weight_baseline_deviation: float = BGE_M3_WEIGHT_BASELINE_DEVIATION


@functools.cache
def load_config() -> GuardConfig:
    """加载并缓存全局配置；正则在此阶段一次性编译（运行期只做匹配）。"""
    from .scoring import compile_rules  # 延迟导入避免循环依赖

    rules = compile_rules(load_injection_patterns())
    if not rules:  # 双保险：编译结果为空时回退内置规则
        rules = compile_rules(DEFAULT_INJECTION_PATTERNS)

    return GuardConfig(
        thresholds=THRESHOLDS,
        injection_rules=rules,
        malicious_keywords=[
            MaliciousKeyword(category=c, weight=float(w), keyword=k)
            for c, w, k in load_malicious_keywords()
        ],
        trust_levels=dict(load_trust_config()[0]),
        trust_sources=list(load_trust_config()[1]),
        blacklisted_sources=set(DEFAULT_BLACKLISTED_SOURCES),
        role_matrix={r: dict(v) for r, v in DEFAULT_ROLE_MATRIX.items()},
        action_keywords={a: list(kws) for a, kws in DEFAULT_ACTION_KEYWORDS.items()},
        resource_keywords={r: list(kws) for r, kws in DEFAULT_RESOURCE_KEYWORDS.items()},
        classification_roles={
            k: (list(v) if v is not None else None)
            for k, v in DEFAULT_CLASSIFICATION_ROLES.items()
        },
    )
