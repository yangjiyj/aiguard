import os
import re

HERE = os.path.dirname(__file__)
# tests -> tier1-classifier -> apps -> <repo root>
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
OFFLINE_YML = os.path.join(
    REPO_ROOT, "deploy", "docker-compose", "docker-compose.offline.yml"
)
DOCKERFILE = os.path.join(HERE, "..", "Dockerfile")
ENTRYPOINT = os.path.join(HERE, "..", "entrypoint.sh")

# 镜像内模型唯一真实路径（Dockerfile COPY 目标 + ENV + entrypoint 默认 + model.py 默认逐字一致）。
CANONICAL_MODEL_DIR = "/models/prompt-guard-2"
# 计划早期草稿用过的旧路径，全仓不应再有任何运行期引用（无任何机制往此路径放模型）。
STALE_MODEL_DIR = "/opt/tier1/model"


def _read(p):
    with open(p, "r", encoding="utf-8") as f:
        return f.read()


def _tier1_service_block():
    """抽出 offline.yml 中 tier1-classifier 服务块（到下一个同缩进服务键前）。"""
    body = _read(OFFLINE_YML)
    lines = body.splitlines()
    start = None
    for i, ln in enumerate(lines):
        if re.match(r"^  tier1-classifier:\s*$", ln):
            start = i
            break
    assert start is not None, "offline.yml 缺 tier1-classifier 服务（E-3 应已加入）"
    end = len(lines)
    for j in range(start + 1, len(lines)):
        # 下一个二级缩进键（两空格 + 非空格）= 下一服务/顶层段
        if re.match(r"^  \S", lines[j]):
            end = j
            break
    return "\n".join(lines[start:end])


def test_offline_tier1_model_dir_matches_image_path():
    """offline.yml 的 tier1-classifier 须指向镜像内真实模型路径，否则开机 fatal 守卫炸、容器永不健康。"""
    block = _tier1_service_block()
    # 若声明了 TIER1_MODEL_DIR，必须等于真实镜像路径
    m = re.search(r"TIER1_MODEL_DIR=(\S+)", block)
    if m is not None:
        assert m.group(1) == CANONICAL_MODEL_DIR, (
            f"offline.yml TIER1_MODEL_DIR={m.group(1)}，与镜像内真实路径 "
            f"{CANONICAL_MODEL_DIR} 不一致 → entrypoint 空模型守卫开机 fatal exit 1"
        )


def test_offline_no_stale_opt_tier1_path():
    """全离线 compose 不得残留 /opt/tier1 旧草稿路径（无任何机制往该路径放模型）。"""
    body = _read(OFFLINE_YML)
    assert STALE_MODEL_DIR not in body, (
        f"offline.yml 残留旧路径 {STALE_MODEL_DIR}（计划早期草稿），镜像无此路径模型 → 启动 fatal"
    )


def test_offline_model_dir_consistent_with_dockerfile_and_entrypoint():
    """三处真实路径必须一致：Dockerfile ENV / entrypoint 默认 / offline.yml（若声明）。"""
    df = _read(DOCKERFILE)
    ep = _read(ENTRYPOINT)
    assert CANONICAL_MODEL_DIR in df
    assert CANONICAL_MODEL_DIR in ep
    block = _tier1_service_block()
    m = re.search(r"TIER1_MODEL_DIR=(\S+)", block)
    if m is not None:
        assert m.group(1) == CANONICAL_MODEL_DIR


def test_offline_tier1_threads_declared_and_tunable():
    """FIX-3 + C4：TIER1_THREADS 可经 .env 显式调高；留空时跟随 P1 CPU 档位
    （ENGINE_RESOURCE_EFFECTIVE_TIER1_THREADS），再回落 model.py 的默认 2。"""
    block = _tier1_service_block()
    assert "TIER1_THREADS=${TIER1_THREADS:-}" in block, (
        "offline.yml tier1-classifier 缺可调 TIER1_THREADS 声明"
        "（应为 - TIER1_THREADS=${TIER1_THREADS:-}，留空跟随 P1 档位）"
    )
    assert "ENGINE_RESOURCE_EFFECTIVE_TIER1_THREADS=" in block, (
        "offline.yml tier1-classifier 未透传 engine-resource-autotune.sh 的生效线程数"
    )
    assert "TIER1_BATCH_WINDOWS=${TIER1_BATCH_WINDOWS:-}" in block, (
        "offline.yml tier1-classifier 缺 TIER1_BATCH_WINDOWS 声明"
    )
