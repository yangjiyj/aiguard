#!/usr/bin/env python3
"""模型路由 Web 产物契约校验（home web-console 受控发布的构建期闸门）。

用途：在 web-console 镜像产出之后、切入生产之前，先证明**构建产物里的模型路由
文案契约是对的**。这是 `deploy/release/home-service-release.sh` 内嵌 web 契约
检查的构建期前置版本：同一套标记，但更早失败、且能独立留证，坏镜像生不出来。

契约（与 home-service-release.sh 的 verify_web_contract_directory 保持一致）
--------------------------------------------------------------------
必须出现：
    这里只显示多上游模型
禁止出现（旧版模型路由界面遗留文案）：
    路由保障中
    需要处理

结构约束：
- 入口 index.html 必须存在、不得是符号链接；
- index.html 引用的本地脚本/样式必须存在且不是符号链接；
- 产物树里不允许出现任何符号链接；
- 从入口可达的文本资源至少 2 个（入口自身 + 至少一个被引用的 chunk），
  避免"index.html 能打开但 JS 没打进包"的假绿。

用法
----
    validate-model-routing-web-artifacts.py --dist apps/web-console/dist
    validate-model-routing-web-artifacts.py --image jjdguard/web-console:release-id
    validate-model-routing-web-artifacts.py --dist DIR --json receipt.json

    --image 需要本机 docker：脚本用 docker create + docker cp 抽 /app/dist
    （只读挂载，不启动容器、不执行镜像内代码）。

退出码：0 = 通过；1 = 契约不满足（问题逐条打印）；2 = 用法/环境错误。

重建说明：本文件原为未跟踪状态、在 2026-09-12 的工作树清理中丢失，
按同批次归档的改动（AGENTS.md：home 的 web-console 必须经受控发布入口）与
仓库内既有的同名契约检查重建。
"""
from __future__ import annotations

import argparse
import json
import pathlib
import posixpath
import shutil
import stat
import subprocess
import sys
import tempfile
from html.parser import HTMLParser
from urllib.parse import urlsplit

# 契约标记：与 deploy/release/home-service-release.sh 的 verify_web_contract_directory 同源。
# 这里刻意保持与发布脚本完全一致——两个闸门对同一份产物必须给出同一结论，
# 否则会出现"构建期过了、发布期被拒"的假绿。
REQUIRED_MARKERS = ("这里只显示多上游模型",)
FORBIDDEN_MARKERS = ("路由保障中", "需要处理")

TEXT_SUFFIXES = frozenset({".html", ".js", ".css", ".json"})
IN_IMAGE_DIST = "/app/dist"
EXIT_OK = 0
EXIT_CONTRACT = 1
EXIT_USAGE = 2


class EntryParser(HTMLParser):
    """只收集入口页引用的本地脚本与样式，忽略外链与 data URI。"""

    def __init__(self) -> None:
        super().__init__()
        self.references: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value for key, value in attrs}
        if tag.lower() == "script" and values.get("src"):
            self.references.append(values["src"] or "")
        if tag.lower() == "link" and values.get("href"):
            rel = set((values.get("rel") or "").lower().split())
            if rel & {"stylesheet", "modulepreload", "preload"}:
                self.references.append(values["href"] or "")


def _local_reference(value: str, parent: pathlib.PurePosixPath) -> str | None:
    """把页内引用归一化成产物树内相对路径；外链返回 None，越界直接判失败。"""
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or not parsed.path:
        return None
    raw = (
        parsed.path.lstrip("/")
        if parsed.path.startswith("/")
        else str(parent / parsed.path)
    )
    normalized = posixpath.normpath(raw)
    if normalized in {"", "."} or normalized == ".." or normalized.startswith("../"):
        raise ValueError(f"不安全的 Web 资源引用: {value}")
    return normalized


def inspect_dist(dist: pathlib.Path) -> dict:
    """校验一个已构建的 dist 目录，返回结构化报告（不打印、不退出）。"""
    problems: list[str] = []
    report: dict = {
        "dist": str(dist),
        "ok": False,
        "reachable_assets": [],
        "required_markers": list(REQUIRED_MARKERS),
        "forbidden_markers": list(FORBIDDEN_MARKERS),
        "problems": problems,
    }

    if not dist.is_dir() or dist.is_symlink():
        problems.append(f"dist 目录缺失或不安全: {dist}")
        return report

    index = dist / "index.html"
    if not index.is_file() or index.is_symlink():
        problems.append("index.html 缺失或不安全")
        return report

    text_files: dict[str, pathlib.Path] = {}
    for path in sorted(dist.rglob("*"), key=lambda value: value.as_posix()):
        metadata = path.lstat()
        relative = path.relative_to(dist).as_posix()
        if stat.S_ISLNK(metadata.st_mode):
            problems.append(f"产物包含符号链接: {relative}")
            continue
        if (
            stat.S_ISREG(metadata.st_mode)
            and path.suffix.lower() in TEXT_SUFFIXES
            and not path.name.endswith(".map")
        ):
            text_files[relative] = path

    parser = EntryParser()
    try:
        parser.feed(index.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as exc:
        problems.append(f"无法读取 index.html: {exc}")
        return report

    queue: list[str] = []
    for reference in parser.references:
        try:
            relative = _local_reference(reference, pathlib.PurePosixPath("."))
        except ValueError as exc:
            problems.append(str(exc))
            continue
        if relative is None:
            continue
        target = dist / relative
        if not target.is_file() or target.is_symlink():
            problems.append(f"入口引用的资源缺失或不安全: {relative}")
            continue
        if relative in text_files:
            queue.append(relative)

    # 可达性不是"文件在不在"，而是"入口能不能顺着引到"：build 配置错了会把
    # chunk 打出来却没被 index 引用，那种包上线就是白屏。
    reachable: set[str] = set()
    frontier = ["index.html", *queue]
    while frontier:
        relative = frontier.pop(0)
        if relative in reachable:
            continue
        path = text_files.get(relative)
        if path is None:
            continue
        reachable.add(relative)
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            problems.append(f"无法读取产物 {relative}: {exc}")
            continue
        parent = pathlib.PurePosixPath(relative).parent
        for candidate in text_files:
            if candidate in reachable or candidate == relative:
                continue
            candidate_path = pathlib.PurePosixPath(candidate)
            rel_token = posixpath.relpath(str(candidate_path), str(parent))
            tokens = {candidate, f"/{candidate}", rel_token}
            if not rel_token.startswith("."):
                tokens.add(f"./{rel_token}")
            if any(token in content for token in tokens):
                frontier.append(candidate)

    report["reachable_assets"] = sorted(reachable)
    if len(reachable) < 2:
        problems.append("入口没有引用到任何可达的文本资源（JS/CSS 未打进包）")

    combined = "\n".join(
        text_files[name].read_text(encoding="utf-8", errors="replace")
        for name in sorted(reachable)
    )
    for marker in REQUIRED_MARKERS:
        if marker not in combined:
            problems.append(f"缺少模型路由契约标记: {marker}")
    for marker in FORBIDDEN_MARKERS:
        if marker in combined:
            problems.append(f"存在旧版模型路由契约标记: {marker}")

    report["ok"] = not problems
    return report


def extract_dist_from_image(image: str) -> tuple[pathlib.Path, pathlib.Path]:
    """用 docker create + docker cp 从镜像抽出 /app/dist（不启动容器、不执行镜像代码）。

    返回 (临时根目录, dist 路径)；调用方负责清理临时根目录。
    """
    docker = shutil.which("docker")
    if docker is None:
        raise RuntimeError("--image 需要本机 docker，但 PATH 里找不到 docker")

    created = subprocess.run(
        [docker, "create", "--entrypoint", "/bin/true", image],
        capture_output=True,
        text=True,
        check=False,
    )
    if created.returncode != 0:
        raise RuntimeError(f"docker create 失败: {created.stderr.strip()}")
    container_id = created.stdout.strip()
    temporary_root = pathlib.Path(tempfile.mkdtemp(prefix="web-console-dist-"))
    try:
        copied = subprocess.run(
            [docker, "cp", f"{container_id}:{IN_IMAGE_DIST}", str(temporary_root)],
            capture_output=True,
            text=True,
            check=False,
        )
        if copied.returncode != 0:
            raise RuntimeError(f"docker cp 失败: {copied.stderr.strip()}")
        dist = temporary_root / "dist"
        if not dist.is_dir():
            raise RuntimeError(f"镜像内没有 {IN_IMAGE_DIST}")
        return temporary_root, dist
    finally:
        subprocess.run(
            [docker, "rm", "-f", container_id],
            capture_output=True,
            text=True,
            check=False,
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="校验 web-console 构建产物的模型路由契约。",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--dist", help="已构建的 dist 目录")
    source.add_argument("--image", help="含 /app/dist 的 web-console 镜像引用")
    parser.add_argument("--json", help="把结构化报告写到该路径")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    temporary_root: pathlib.Path | None = None
    try:
        if args.dist:
            dist = pathlib.Path(args.dist)
        else:
            temporary_root, dist = extract_dist_from_image(args.image)
        report = inspect_dist(dist)
    except (RuntimeError, OSError) as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return EXIT_USAGE
    finally:
        if temporary_root is not None:
            shutil.rmtree(temporary_root, ignore_errors=True)

    if args.json:
        pathlib.Path(args.json).write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )

    if report["ok"]:
        print(
            f"[ok] 模型路由 Web 契约通过：{report['dist']}"
            f"（可达文本资源 {len(report['reachable_assets'])} 个）"
        )
        return EXIT_OK

    for problem in report["problems"]:
        print(f"[error] {problem}", file=sys.stderr)
    print(
        f"[error] 模型路由 Web 契约未通过：{report['dist']}"
        f"（{len(report['problems'])} 个问题）",
        file=sys.stderr,
    )
    return EXIT_CONTRACT


if __name__ == "__main__":
    raise SystemExit(main())
