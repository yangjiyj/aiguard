import os
import stat

HERE = os.path.dirname(__file__)
ROOT = os.path.abspath(os.path.join(HERE, ".."))
DOCKERFILE = os.path.join(ROOT, "Dockerfile")
BUILD = os.path.join(ROOT, "scripts", "build-tier1-image.sh")
REQS = os.path.join(ROOT, "requirements.txt")
ENTRYPOINT = os.path.join(ROOT, "entrypoint.sh")


def _read(p):
    with open(p, "r", encoding="utf-8") as f:
        return f.read()


def test_dockerfile_basics():
    body = _read(DOCKERFILE)
    assert "python:3.11-slim" in body
    assert "EXPOSE 8000" in body  # 端口契约（uvicorn 实际监听由 entrypoint 默认 8000）
    # 启动经 entrypoint.sh（含空模型目录开机 fatal 守卫），uvicorn app.main:app 在脚本内 exec
    assert "entrypoint.sh" in body
    assert "USER appuser" in body  # 非 root 运行
    # 模型烤进镜像（COPY 暂存 ONNX → /models/prompt-guard-2）
    assert "/models/prompt-guard-2" in body
    assert "TIER1_MODEL_DIR" in body


def test_requirements_pins_inference_deps():
    body = _read(REQS)
    for dep in ("fastapi", "uvicorn", "onnxruntime", "transformers", "numpy"):
        assert dep in body


def test_legacy_build_script_is_explicitly_retired():
    assert os.stat(BUILD).st_mode & stat.S_IXUSR
    body = _read(BUILD)
    assert "exit 78" in body
    assert "TIER1_OWNED_MODEL_INPUT" in body
    assert "build-baseline-model.sh" not in body
    assert "set -eu" in body


def test_entrypoint_has_empty_model_dir_fatal_guard():
    # plan E-2 字面要求：entrypoint 须对空/缺失的模型目录开机 fatal 阻断（[ ! -d MODEL_DIR ] || exit 1）。
    # 这是 build-tier1-image.sh 构建期校验之外的【运行期最后一道】守卫：镜像若被错灌空模型卷/COPY 失败，
    # 必须开机当场 exit 1 暴露，不静默起一个永远 503 的服务。
    assert os.path.exists(ENTRYPOINT), "缺 entrypoint.sh（plan E-2 明列的产物，含空模型目录开机 fatal 守卫）"
    assert os.stat(ENTRYPOINT).st_mode & stat.S_IXUSR, "entrypoint.sh 须可执行"
    body = _read(ENTRYPOINT)
    assert "set -eu" in body
    # 空模型目录开机 fatal：检测目录不存在或为空 → exit 1
    assert "TIER1_MODEL_DIR" in body
    assert "exit 1" in body
    assert "-d" in body  # 目录存在性判断
    # 仍以 uvicorn 起 app.main:app（启动功能等价）
    assert "uvicorn" in body and "app.main:app" in body


def test_dockerfile_uses_entrypoint_script():
    # Dockerfile 须把 entrypoint.sh COPY 进镜像、置可执行位、作为 ENTRYPOINT（取代裸 CMD uvicorn），
    # 这样空模型目录开机 fatal 守卫才真正生效于容器启动路径。
    body = _read(DOCKERFILE)
    assert "entrypoint.sh" in body
    assert "ENTRYPOINT" in body
    # 候选归档在 umask 077 下解包；必须显式恢复非 root 用户可读可执行权限。
    assert "chmod 0755 /usr/local/bin/entrypoint.sh" in body


def test_dockerfile_verifies_baseline_model():
    # COPY 自训基线后须构建期 RUN 校验融合 ONNX + config 实际进镜像（缺则 build 当场红）。
    body = _read(DOCKERFILE)
    assert "/models/prompt-guard-2/model.onnx" in body
    assert "/models/prompt-guard-2/config.json" in body
    # 校验失败要让 build 非零退出
    assert "exit 1" in body or "test -f" in body
