import os

HERE = os.path.dirname(__file__)
DOC = os.path.abspath(os.path.join(HERE, "..", "docs", "deploy-selftrained-baseline.md"))


def _body():
    with open(DOC, "r", encoding="utf-8") as f:
        return f.read()


def test_doc_exists():
    assert os.path.isfile(DOC)


def test_doc_covers_key_steps():
    body = _body()
    # 训基线 → 构建镜像 → 起 sidecar → 开开关 → 验收闸 → live 标注
    assert "build-baseline-model.sh" in body
    assert "build-tier1-image.sh" in body
    assert "SECURITY_TIER1_ENABLED" in body
    assert "acceptance-gate" in body
    assert "full" in body  # full profile/包
    assert "需用户发起" in body or "live" in body.lower()


def test_doc_unlocks_gated_block():
    body = _body()
    # 明示解锁此前卡在 gated 模型(hf-mirror 403)的部署
    assert "gated" in body.lower() or "Prompt-Guard" in body
