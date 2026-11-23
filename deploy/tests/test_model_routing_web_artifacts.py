#!/usr/bin/env python3
"""模型路由 Web 产物契约校验器单元测试（重建版）。

校验器自身是 home web-console 受控发布的构建期闸门，所以它的**误放**比误拒更危险：
一个漏检的旧页面会直接上线。本文件因此重点覆盖负向用例——缺标记、旧标记、
符号链接、悬空引用、不可达资源、越界引用——每条都要求闸门真的红。

同时固定两条容易写反的语义：
- 只校验**从入口可达**的文本资源（sourcemap 与未引用文件不算数），与
  deploy/release/home-service-release.sh 的 verify_web_contract_directory 保持一致；
- 结构问题（符号链接、悬空引用、可达资源不足）与标记问题是同一类硬失败，不分级。

重建说明：本文件原为未跟踪状态、在 2026-09-12 的工作树清理中丢失，
按 deploy/release/validate-model-routing-web-artifacts.py 的实际行为与
home-service-release.sh 内嵌契约检查的同源代码重建。
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "deploy/release/validate-model-routing-web-artifacts.py"
REQUIRED_MARKER = "这里只显示多上游模型"
LEGACY_MARKER = "路由保障中"


def _load_validator():
    spec = importlib.util.spec_from_file_location(
        "validate_model_routing_web_artifacts", VALIDATOR
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


validator = _load_validator()


class DistFixture:
    """在临时目录里拼一棵 dist 树。"""

    def __init__(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._temporary.name) / "dist"
        self.root.mkdir()

    def cleanup(self) -> None:
        self._temporary.cleanup()

    def write(self, relative: str, content: str) -> pathlib.Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def index(self, references: list[str]) -> None:
        tags = "\n".join(
            f'<script type="module" src="{reference}"></script>'
            for reference in references
        )
        self.write("index.html", f"<!doctype html>\n<html><body>{tags}</body></html>\n")

    def clean(self) -> None:
        """一棵通过契约的最小产物：入口 + 一个被引用的 chunk。"""
        self.index(["/assets/app.js"])
        self.write("assets/app.js", f"export const label = '{REQUIRED_MARKER}';\n")

    def symlink(self, relative: str, target: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(target)


class DistContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = DistFixture()
        self.addCleanup(self.fixture.cleanup)

    def inspect(self) -> dict:
        return validator.inspect_dist(self.fixture.root)

    # ---- 正向 ----

    def test_clean_dist_passes(self) -> None:
        self.fixture.clean()
        report = self.inspect()
        self.assertTrue(report["ok"], report["problems"])
        self.assertEqual(report["problems"], [])
        self.assertIn("index.html", report["reachable_assets"])
        self.assertIn("assets/app.js", report["reachable_assets"])

    def test_reachability_follows_the_reference_graph(self) -> None:
        """入口没直接引用的 chunk，只要被别的可达 chunk 引用，也算可达。"""
        self.fixture.index(["/assets/app.js"])
        self.fixture.write(
            "assets/app.js",
            f"import './chunk.js';\nexport const label = '{REQUIRED_MARKER}';\n",
        )
        self.fixture.write("assets/chunk.js", "export const value = 1;\n")
        report = self.inspect()
        self.assertTrue(report["ok"], report["problems"])
        self.assertIn("assets/chunk.js", report["reachable_assets"])

    def test_preload_and_stylesheet_links_are_followed(self) -> None:
        self.fixture.write(
            "index.html",
            '<!doctype html><html><head>'
            '<link rel="stylesheet" href="/assets/app.css">'
            '<link rel="modulepreload" href="/assets/app.js">'
            "</head><body></body></html>\n",
        )
        self.fixture.write("assets/app.css", "body{margin:0}\n")
        self.fixture.write("assets/app.js", f"export const label = '{REQUIRED_MARKER}';\n")
        report = self.inspect()
        self.assertTrue(report["ok"], report["problems"])
        self.assertIn("assets/app.css", report["reachable_assets"])

    # ---- 标记类负向 ----

    def test_missing_required_marker_fails(self) -> None:
        self.fixture.index(["/assets/app.js"])
        self.fixture.write("assets/app.js", "export const label = '多上游模型';\n")
        report = self.inspect()
        self.assertFalse(report["ok"])
        self.assertTrue(
            any(REQUIRED_MARKER in problem for problem in report["problems"]),
            report["problems"],
        )

    def test_legacy_marker_in_a_reachable_asset_fails(self) -> None:
        self.fixture.clean()
        self.fixture.write(
            "assets/app.js",
            f"export const label = '{REQUIRED_MARKER}';\nconst legacy = '{LEGACY_MARKER}';\n",
        )
        report = self.inspect()
        self.assertFalse(report["ok"])
        self.assertTrue(
            any(LEGACY_MARKER in problem for problem in report["problems"]),
            report["problems"],
        )

    def test_legacy_marker_only_in_an_unreachable_asset_is_ignored(self) -> None:
        """与 verify_web_contract_directory 同源：只看可达闭包，不看整棵产物树。"""
        self.fixture.clean()
        self.fixture.write("assets/orphan.js", f"const legacy = '{LEGACY_MARKER}';\n")
        report = self.inspect()
        self.assertTrue(report["ok"], report["problems"])

    def test_sourcemap_assets_are_not_scanned(self) -> None:
        self.fixture.clean()
        self.fixture.write("assets/app.js.map", f'{{"legacy":"{LEGACY_MARKER}"}}\n')
        report = self.inspect()
        self.assertTrue(report["ok"], report["problems"])

    # ---- 结构类负向 ----

    def test_symlink_inside_the_tree_fails(self) -> None:
        self.fixture.clean()
        self.fixture.symlink("assets/evil.js", "../../etc/passwd")
        report = self.inspect()
        self.assertFalse(report["ok"])
        self.assertTrue(
            any("符号链接" in problem for problem in report["problems"]),
            report["problems"],
        )

    def test_dangling_entry_reference_fails(self) -> None:
        self.fixture.index(["/assets/app.js"])
        report = self.inspect()
        self.assertFalse(report["ok"])
        self.assertTrue(
            any("入口引用的资源缺失" in problem for problem in report["problems"]),
            report["problems"],
        )

    def test_entry_without_any_reachable_text_asset_fails(self) -> None:
        """index.html 能打开但 JS 没打进包 —— 上线就是白屏，必须拦。"""
        self.fixture.write("index.html", "<!doctype html><html><body></body></html>\n")
        report = self.inspect()
        self.assertFalse(report["ok"])
        # 入口自身算一个可达文本资源；这里只有它，所以闭包不足 2 个 → 拦下。
        self.assertEqual(report["reachable_assets"], ["index.html"])
        self.assertTrue(
            any("可达的文本资源" in problem for problem in report["problems"]),
            report["problems"],
        )

    def test_parent_traversal_reference_fails(self) -> None:
        self.fixture.write(
            "index.html",
            '<!doctype html><html><body><script src="../outside.js"></script></body></html>\n',
        )
        self.fixture.write("assets/app.js", f"export const label = '{REQUIRED_MARKER}';\n")
        report = self.inspect()
        self.assertFalse(report["ok"])
        self.assertTrue(
            any("不安全的 Web 资源引用" in problem for problem in report["problems"]),
            report["problems"],
        )

    def test_missing_dist_directory_fails(self) -> None:
        report = validator.inspect_dist(self.fixture.root / "does-not-exist")
        self.assertFalse(report["ok"])
        self.assertTrue(report["problems"])

    def test_external_references_are_not_fetched_or_required(self) -> None:
        self.fixture.write(
            "index.html",
            '<!doctype html><html><head>'
            '<script src="https://cdn.example.test/app.js"></script>'
            "</head><body><script src=\"/assets/app.js\"></script></body></html>\n",
        )
        self.fixture.write("assets/app.js", f"export const label = '{REQUIRED_MARKER}';\n")
        report = self.inspect()
        self.assertTrue(report["ok"], report["problems"])
        self.assertNotIn("https://cdn.example.test/app.js", report["reachable_assets"])


class CommandLineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = DistFixture()
        self.addCleanup(self.fixture.cleanup)

    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(VALIDATOR), *arguments],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_passing_dist_exits_zero_and_can_write_a_json_report(self) -> None:
        self.fixture.clean()
        report_path = self.fixture.root.parent / "receipt.json"
        result = self.run_cli("--dist", str(self.fixture.root), "--json", str(report_path))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("[ok]", result.stdout)
        payload = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["problems"], [])

    def test_failing_dist_exits_one_with_the_problem_on_stderr(self) -> None:
        self.fixture.index(["/assets/app.js"])
        self.fixture.write("assets/app.js", "export const label = 'nothing useful';\n")
        result = self.run_cli("--dist", str(self.fixture.root))
        self.assertEqual(result.returncode, 1)
        self.assertIn(REQUIRED_MARKER, result.stderr)

    def test_dist_and_image_are_mutually_exclusive(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            validator.main(
                ["--dist", str(self.fixture.root), "--image", "jjdguard/web-console:x"]
            )
        self.assertEqual(raised.exception.code, 2)

    def test_one_of_dist_or_image_is_required(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            validator.main([])
        self.assertEqual(raised.exception.code, 2)


class ContractParityTests(unittest.TestCase):
    """契约标记必须与发布脚本内嵌的那份逐字一致，否则会出现构建期过、发布期拒的假绿。"""

    def test_markers_match_the_release_entry(self) -> None:
        release_entry = (ROOT / "deploy/release/home-service-release.sh").read_text(
            encoding="utf-8"
        )
        for marker in validator.REQUIRED_MARKERS:
            self.assertIn(f'"{marker}"', release_entry)
        for marker in validator.FORBIDDEN_MARKERS:
            self.assertIn(f'"{marker}"', release_entry)
        # 发布脚本里是单引号赋值，这里只要求版本串出现，且唯一来源与回执校验器一致。
        self.assertIn("model-routing-multi-upstream/v1", release_entry)

    def test_receipt_validator_pins_the_same_contract_version(self) -> None:
        receipt_validator = (
            ROOT / "deploy/release/verify-home-release-receipt.py"
        ).read_text(encoding="utf-8")
        self.assertIn("model-routing-multi-upstream/v1", receipt_validator)


if __name__ == "__main__":
    unittest.main()
