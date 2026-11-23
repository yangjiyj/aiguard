#!/usr/bin/env python3
# deploy/maintenance/gen_capability_docs.py
"""把引擎里的检测能力说明目录合并成控制面嵌入用的一份 JSON。

来源：apps/security-engine/app/data/capability_docs/*.json（唯一来源，人工维护）
产物：apps/control-plane/internal/repository/capability_docs_gen.json（生成物，不要手改）

用法：
    python3 deploy/maintenance/gen_capability_docs.py          # 重新生成
    python3 deploy/maintenance/gen_capability_docs.py --check  # 只检查是否过期
"""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "apps/security-engine/app/data/capability_docs"
TARGET = ROOT / "apps/control-plane/internal/repository/capability_docs_gen.json"


def render(source: pathlib.Path = SOURCE) -> str:
    entries = {}
    for path in sorted(source.glob("*.json")):
        for entry in json.loads(path.read_text(encoding="utf-8")):
            category = entry["category"]
            if category in entries:
                raise ValueError(f"{path.name}: {category} 重复出现")
            entries[category] = entry
    ordered = [entries[key] for key in sorted(entries)]
    return json.dumps(ordered, ensure_ascii=False, indent=1, sort_keys=True) + "\n"


def main() -> int:
    text = render()
    if "--check" in sys.argv:
        if not TARGET.exists() or TARGET.read_text(encoding="utf-8") != text:
            print("控制面的能力说明副本过期了，重新生成：python3 deploy/maintenance/gen_capability_docs.py")
            return 1
        return 0
    TARGET.write_text(text, encoding="utf-8")
    print(f"已生成 {TARGET.relative_to(ROOT)}，共 {len(json.loads(text))} 条")
    return 0


if __name__ == "__main__":
    sys.exit(main())
