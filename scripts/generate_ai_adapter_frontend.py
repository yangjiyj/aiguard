#!/usr/bin/env python3
"""Generate web-console agent metadata from built-in AI adapter manifests."""
from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
ADAPTER_DIR = ROOT / "packages/shared-go/aiadapters/adapters"
OUT_PATH = ROOT / "apps/web-console/src/generated/agent-definitions.json"


def load_agents() -> list[dict[str, Any]]:
    agents: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in sorted(ADAPTER_DIR.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        for agent in data.get("agent_definitions", []):
            agent_type = str(agent.get("type", "")).strip()
            if not agent_type:
                raise SystemExit(f"{path}: agent definition missing type")
            if agent_type in seen:
                raise SystemExit(f"duplicate agent type {agent_type!r} in {path}")
            seen.add(agent_type)
            agents.append(
                {
                    "type": agent_type,
                    "label": str(agent.get("label") or agent_type),
                    "vendor": str(agent.get("vendor") or ""),
                    "color": str(agent.get("color") or "#1677ff"),
                }
            )
    return agents


def render(agents: list[dict[str, Any]]) -> str:
    return json.dumps(agents, ensure_ascii=False, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if generated file is stale")
    args = parser.parse_args()

    content = render(load_agents())
    if args.check:
        current = OUT_PATH.read_text(encoding="utf-8") if OUT_PATH.exists() else ""
        if current != content:
            print(f"{OUT_PATH} is stale; run scripts/generate_ai_adapter_frontend.py", file=sys.stderr)
            return 1
        print(f"{OUT_PATH} is up to date")
        return 0

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(content, encoding="utf-8")
    print(f"wrote {OUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
