#!/usr/bin/env python3
"""导出引擎全量 category 枚举（class_key 中文映射对账的静态清单，设计 3b）。

用法（仓库根）：
    cd apps/security-engine && python3 tools/export_categories.py > ../web-console/src/utils/engine_categories.json

范围：确定性的规则/正则层 category（prompt_injection / data_leak / content_safety /
prompt_stego / sensitive_data / engine 内置 secret·code·chinese 表）。语义层（semantic_*）与自定义规则
category 由租户配置动态决定，不进静态清单——前端以 startsWith 前缀兜底。

engine.py 的三张表是 SecurityEngine.__init__ 内联字典；脚本不实例化 SecurityEngine
（其 __init__ 会拉起语义/裁判配置），改为静态镜像清单 + tests/test_category_export.py
与真引擎对账防漂移。
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.detectors.content_safety import ContentSafetyDetector
from app.detectors.data_leak import DataLeakDetector
from app.detectors.prompt_injection import PromptInjectionDetector
from app.detectors.policy_catalog import POLICY_CATALOG_CATEGORIES
from app.detectors.sensitive_data import SENSITIVE_DATA_CATEGORIES

# —— engine.py 内联表的静态镜像（由 pytest 对账防漂移）——
ENGINE_SECRET_CATEGORIES = [
    "aws_access_key", "aws_secret_key", "github_token", "generic_api_key",
    "jwt_token", "openai_key", "anthropic_key",
]
ENGINE_CODE_CATEGORIES = ["env_file", "ssh_private_key", "openssh_private_key", "config_file"]
ENGINE_CHINESE_CATEGORIES = ["phone_cn", "id_card_cn", "bank_card_cn", "email"]
# prompt_stego.py 的四个字面量 category（检测器无模式表，直接静态列出）
PROMPT_STEGO_CATEGORIES = [
    "apostrophe_variant", "date_separator_variant", "zero_width_char", "quote_variant",
]
# content_safety.py detect() 内六个复合判定的字面量 category
CONTENT_SAFETY_COMPOSITE = [
    "illegal_hazardous_chemical_instructions", "self_harm_actionable_guidance",
    "illegal_system_command_instructions", "debug_secret_template",
    "ssrf_metadata_instruction", "agent_canary_token_leak",
]


def collect() -> list:
    cats = set()
    pi = PromptInjectionDetector()
    for layer, patterns in [
        ("keyword", pi.keyword_patterns), ("encoding", pi.encoding_patterns),
        ("semantic", pi.semantic_patterns), ("structured", pi.structured_patterns),
    ]:
        for p in patterns:
            cats.add(f"{layer}_{p['type']}")
    dl = DataLeakDetector()
    for prefix, patterns in [
        ("classified", dl.classified_markers), ("sensitive_file", dl.sensitive_files),
        ("code_leak", dl.code_leak_patterns),
    ]:
        for p in patterns:
            cats.add(f"{prefix}_{p['type']}")
    cs = ContentSafetyDetector()
    for prefix, patterns in [
        ("political", cs.political_patterns), ("illegal", cs.illegal_patterns),
        ("multilingual", cs.multilingual_patterns), ("discrimination", cs.discrimination_patterns),
    ]:
        for p in patterns:
            cats.add(f"{prefix}_{p['type']}")
    cats.update(CONTENT_SAFETY_COMPOSITE)
    cats.update(PROMPT_STEGO_CATEGORIES)
    cats.update(ENGINE_SECRET_CATEGORIES)
    cats.update(ENGINE_CODE_CATEGORIES)
    cats.update(ENGINE_CHINESE_CATEGORIES)
    cats.update(SENSITIVE_DATA_CATEGORIES)
    cats.update(POLICY_CATALOG_CATEGORIES)
    return sorted(cats)


if __name__ == "__main__":
    json.dump(collect(), sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
