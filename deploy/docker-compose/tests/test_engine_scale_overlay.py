"""Render the multi-replica Compose overlays with synthetic config; never start services."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
BASES = ("docker-compose.yml", "docker-compose.offline.yml")
SCALE = "docker-compose.scale.yml"
TIER1_GPU = "tier1-gpu.override.yml"
TIER1_CPU = "tier1-cpu.override.yml"
TIER1_SCALE_SH = "tier1-scale.sh"
TIER1_TOPOLOGY_SH = "tier1-topology.sh"
PACKAGER = "package-offline-bundle.sh"
GPU_IMAGE = "tier1-gpu@sha256:" + "a" * 64


def _render(base, *overlays, profile=None, **overrides):
    if not shutil.which("docker"):
        pytest.skip("Docker Compose is required for rendering")
    files = (base,) + overlays
    text = "\n".join((ROOT / name).read_text(encoding="utf-8") for name in files)
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
    }
    env.update({
        key: "synthetic-fixture-value-only"
        for key in re.findall(r"\$\{([A-Z0-9_]+):\?", text)
    })
    env.update({key: str(value) for key, value in overrides.items()})
    cmd = ["docker", "compose", "--env-file", "/dev/null"]
    if profile:
        cmd += ["--profile", profile]
    for name in files:
        cmd += ["-f", str(ROOT / name)]
    cmd += ["config", "--format", "json"]
    result = subprocess.run(cmd, env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)["services"]


@pytest.mark.parametrize("base", BASES)
def test_scale_overlay_renders_with_both_bases(base):
    services = _render(base, SCALE)
    engine = services["security-engine"]
    # Replicas must be declared, and the fixed single-instance host port must
    # be gone: two replicas cannot bind the same host port.
    assert engine["deploy"]["replicas"] == 2
    assert not engine.get("ports"), engine.get("ports")


@pytest.mark.parametrize("base", BASES)
@pytest.mark.parametrize("replicas", [1, 8, 16])
def test_replica_count_is_operator_controlled(base, replicas):
    services = _render(base, SCALE, SECURITY_ENGINE_REPLICAS=replicas)
    assert services["security-engine"]["deploy"]["replicas"] == replicas


@pytest.mark.parametrize("base", BASES)
def test_replicas_keep_shared_state_and_global_judge_budget(base):
    env = _render(base, SCALE)["security-engine"]["environment"]
    # Multi-replica correctness is impossible without shared state.
    assert env["SECURITY_SHARED_STATE_URL"].endswith("/3")
    assert env["SECURITY_SHARED_STATE_REQUIRED"] == "true"
    # Blank node id means runtime_profile derives hostname#pid per replica.
    assert env["SECURITY_NODE_ID"] == ""
    assert env["SECURITY_JUDGE_GLOBAL_CONCURRENCY"] == "96"
    # R1: the measured-safe default. 4000 is opt-in only (recall cost).
    assert env["SECURITY_SEMANTIC_WINDOW_CHARS"] == "1200"


def test_scale_overlay_does_not_reference_offline_only_service():
    body = (ROOT / SCALE).read_text(encoding="utf-8").split("services:", 1)[1]
    assert "tier1-classifier:" not in body
    assert "security-engine:" in body


def test_tier1_replicas_and_cuda_use_existing_mechanism():
    gpu = (ROOT / TIER1_GPU).read_text(encoding="utf-8")
    cpu = (ROOT / TIER1_CPU).read_text(encoding="utf-8")
    script = (ROOT / TIER1_SCALE_SH).read_text(encoding="utf-8")
    assert "TIER1_EXECUTION_PROVIDER: cuda" in gpu
    assert "driver: nvidia" in gpu
    assert "TIER1_EXECUTION_PROVIDER: cpu" in cpu
    assert '--scale "tier1-classifier=$replicas"' in script
    # U2: the GPU preconditions live in the shared topology library so first
    # scaling, upgrades and the offline installer all run the same checks.
    topology = (ROOT / TIER1_TOPOLOGY_SH).read_text(encoding="utf-8")
    assert "tier1_gpu_preflight" in script
    assert "CUDAExecutionProvider" in topology
    assert "tier1_capacity_verdict" in topology
    # Both overlays, the scale script and the shared library must ship in the bundle.
    packager = (ROOT / PACKAGER).read_text(encoding="utf-8")
    for name in (TIER1_GPU, TIER1_CPU, TIER1_SCALE_SH, SCALE, TIER1_TOPOLOGY_SH):
        assert "/%s " % name in packager or "/%s\"" % name in packager, name


def test_cuda_overlay_renders_with_offline_base_and_scale_overlay():
    services = _render(
        "docker-compose.offline.yml", SCALE, TIER1_GPU,
        profile="full", TIER1_GPU_IMAGE=GPU_IMAGE,
    )
    tier1 = services["tier1-classifier"]
    assert tier1["environment"]["TIER1_EXECUTION_PROVIDER"] == "cuda"
    devices = tier1["deploy"]["resources"]["reservations"]["devices"]
    assert any(d.get("driver") == "nvidia" for d in devices)
    assert services["security-engine"]["deploy"]["replicas"] == 2


# ---------------------------------------------------------------------------
# What the engine reports about its own sizing has to be able to reach it.
# autotune writes 17 ENGINE_RESOURCE_* keys into .env and runtime_profile.py reads all 17, but
# the two compose files only handed 12 to security-engine. On the real stack /health therefore
# said profile=manual (the install was auto), left the detected CPU / memory / source blank and
# the judge budget status empty: every test was green because none of them looked at the
# environment the container actually gets.
# ---------------------------------------------------------------------------

def _engine_resource_keys_read_by_the_engine():
    source = (ROOT.parents[1] / "apps" / "security-engine" / "app" / "runtime_profile.py").read_text(encoding="utf-8")
    return sorted(set(re.findall(r"ENGINE_RESOURCE_[A-Z0-9_]+", source)))


@pytest.mark.parametrize("base", BASES)
def test_every_engine_resource_key_the_engine_reads_reaches_the_container(base):
    wanted = _engine_resource_keys_read_by_the_engine()
    assert len(wanted) >= 15, wanted          # the scan itself must not silently find nothing
    environment = _render(base)["security-engine"]["environment"]
    missing = [key for key in wanted if key not in environment]
    assert not missing, "not passed to security-engine in %s: %s" % (base, missing)


@pytest.mark.parametrize("base", BASES)
def test_engine_resource_profile_defaults_are_the_ones_the_engine_assumes(base):
    environment = _render(base)["security-engine"]["environment"]
    assert environment["ENGINE_RESOURCE_PROFILE"] == "manual"
    for key in ("ENGINE_RESOURCE_DETECTED_CPUS", "ENGINE_RESOURCE_DETECTED_MEM_MB",
                "ENGINE_RESOURCE_DETECTED_CPU_SOURCE", "ENGINE_RESOURCE_JUDGE_BUDGET_STATUS"):
        assert environment[key] == ""


@pytest.mark.parametrize("base", BASES)
def test_engine_resource_values_from_env_file_win_over_the_defaults(base, tmp_path):
    env_file = tmp_path / "e.env"
    env_file.write_text("ENGINE_RESOURCE_PROFILE=auto\nENGINE_RESOURCE_DETECTED_CPUS=64\n"
                        "ENGINE_RESOURCE_DETECTED_MEM_MB=257570\nENGINE_RESOURCE_DETECTED_CPU_SOURCE=nproc\n"
                        "ENGINE_RESOURCE_JUDGE_BUDGET_STATUS=bounded_by_global:128\n", encoding="utf-8")
    if not shutil.which("docker"):
        pytest.skip("Docker Compose is required for rendering")
    text = (ROOT / base).read_text(encoding="utf-8")
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/tmp")}
    env.update({key: "synthetic-fixture-value-only" for key in re.findall(r"\$\{([A-Z0-9_]+):\?", text)})
    result = subprocess.run(["docker", "compose", "--env-file", str(env_file), "-f", str(ROOT / base),
                             "config", "--format", "json"], env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    environment = json.loads(result.stdout)["services"]["security-engine"]["environment"]
    assert environment["ENGINE_RESOURCE_PROFILE"] == "auto"
    assert environment["ENGINE_RESOURCE_DETECTED_CPUS"] == "64"
    assert environment["ENGINE_RESOURCE_DETECTED_MEM_MB"] == "257570"
    assert environment["ENGINE_RESOURCE_DETECTED_CPU_SOURCE"] == "nproc"
    assert environment["ENGINE_RESOURCE_JUDGE_BUDGET_STATUS"] == "bounded_by_global:128"
