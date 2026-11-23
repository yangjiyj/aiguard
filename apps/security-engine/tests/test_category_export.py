"""class_key 对账（设计 3b）：静态清单 vs 真引擎/检测器，防止枚举漂移。"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from export_categories import (
    ENGINE_CHINESE_CATEGORIES,
    ENGINE_CODE_CATEGORIES,
    ENGINE_SECRET_CATEGORIES,
    SENSITIVE_DATA_CATEGORIES,
    collect,
)
from app.detectors.engine import SecurityEngine


def test_engine_static_lists_match_live_engine():
    engine = SecurityEngine()
    assert set(ENGINE_SECRET_CATEGORIES) == set(engine.secret_patterns.keys())
    assert set(ENGINE_CODE_CATEGORIES) == set(engine.code_patterns.keys())
    assert set(ENGINE_CHINESE_CATEGORIES) == set(engine.chinese_patterns.keys())
    assert set(engine.sensitive_data.categories) == set(SENSITIVE_DATA_CATEGORIES)


def test_exported_json_in_sync_with_detectors():
    fixture = Path(__file__).resolve().parents[2] / "web-console" / "src" / "utils" / "engine_categories.json"
    assert fixture.exists(), (
        "缺少静态清单：cd apps/security-engine && "
        "python3 tools/export_categories.py > ../web-console/src/utils/engine_categories.json"
    )
    assert json.loads(fixture.read_text(encoding="utf-8")) == collect(), (
        "engine_categories.json 落后于检测器源码：重新运行 tools/export_categories.py 并提交"
    )
