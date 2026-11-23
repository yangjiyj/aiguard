import anyio
import httpx

import app.main as main_module


async def _preview(matcher, samples, token=None):
    transport = httpx.ASGITransport(app=main_module.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://engine") as client:
        return await client.post(
            "/admin/v1/internal/policies/quick-create/preview/",
            json={"matcher": matcher, "samples": samples},
            headers={"X-JJDGuard-Internal-Token": token} if token else {},
        )


def test_preview_reuses_custom_matcher_and_never_returns_plaintext(monkeypatch):
    monkeypatch.setenv("JJD_INTERNAL_API_SECRET", "test-secret")
    response = anyio.run(
        _preview,
        {"type": "keyword", "config": {"keywords": ["mysecretvalue"]}},
        ["here is mysecretvalue", "nothing"], "test-secret",
    )
    assert response.status_code == 200
    matches = response.json()["matches"]
    assert matches[0]["matched"] is True
    assert matches[0]["location"] == "content[8:21]"
    assert matches[1]["matched"] is False
    assert "mysecretvalue" not in response.text


def test_preview_rejects_unsafe_regex_and_large_samples(monkeypatch):
    monkeypatch.setenv("JJD_INTERNAL_API_SECRET", "test-secret")
    invalid = anyio.run(
        _preview, {"type": "regex", "config": {"regex": "(a+)+$"}},
        ["a"], "test-secret",
    )
    assert invalid.status_code == 422
    oversized = anyio.run(
        _preview, {"type": "keyword", "config": {"keywords": ["foo"]}},
        ["x" * 4097], "test-secret",
    )
    assert oversized.status_code == 422


def test_preview_needs_internal_token_even_when_middleware_unset(monkeypatch):
    monkeypatch.delenv("JJD_INTERNAL_API_SECRET", raising=False)
    response = anyio.run(
        _preview, {"type": "keyword", "config": {"keywords": ["foo"]}},
        ["foo"], None,
    )
    assert response.status_code == 503


def test_invalid_request_never_reflects_sensitive_sample(monkeypatch):
    monkeypatch.setenv("JJD_INTERNAL_API_SECRET", "test-secret")
    response = anyio.run(
        _preview, {"type": "keyword", "config": {"keywords": ["hiddenvalue"]}},
        [42], "test-secret",
    )
    assert response.status_code == 422
    assert "hiddenvalue" not in response.text


def test_builtin_preview_uses_checksum_and_production_location(monkeypatch):
    monkeypatch.setenv("JJD_INTERNAL_API_SECRET", "test-secret")
    from app.detectors.engine import engine
    monkeypatch.setattr(engine, "pii_checksum_enabled", True)
    monkeypatch.setattr(engine, "pii_checksum_drop_invalid", True)
    valid = "11010519491231002X"
    invalid = "110105194912310021"
    assert engine._detect_regex_pii(valid)
    async def request():
        transport = httpx.ASGITransport(app=main_module.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://engine") as client:
            return await client.post("/admin/v1/internal/policies/quick-create/preview/",
                json={"capability_categories":["id_card_cn"], "stage":"output", "samples":[valid,invalid]},
                headers={"X-JJDGuard-Internal-Token":"test-secret"})
    response=anyio.run(request)
    assert response.status_code==200
    assert response.json()["matches"] == [
        {"sample_index":0,"matched":True,"location":"content[0:18]","redacted_evidence":"<REDACTED>"},
        {"sample_index":1,"matched":False,"location":None,"redacted_evidence":None}]
    assert valid not in response.text and invalid not in response.text


def test_builtin_preview_rejects_unsupported_capabilities_and_stages(monkeypatch):
    monkeypatch.setenv("JJD_INTERNAL_API_SECRET", "test-secret")
    async def request(payload):
        transport = httpx.ASGITransport(app=main_module.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://engine") as client:
            return await client.post("/admin/v1/internal/policies/quick-create/preview/", json=payload,
                headers={"X-JJDGuard-Internal-Token":"test-secret"})
    for payload in (
        {"capability_categories":["unknown"],"samples":["x"]},
        {"capability_categories":["email","phone_cn"],"samples":["x"]},
        {"capability_categories":["email"],"matcher":{"type":"keyword","config":{"keywords":["x"]}},"samples":["x"]},
        {"capability_categories":["email"],"stage":"agent","samples":["x"]},
    ):
        assert anyio.run(request,payload).status_code==422


def test_preview_rejects_invalid_unicode_matcher_without_reflection(monkeypatch):
    monkeypatch.setenv("JJD_INTERNAL_API_SECRET", "test-secret")

    async def request(payload):
        transport = httpx.ASGITransport(app=main_module.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://engine") as client:
            return await client.post(
                "/admin/v1/internal/policies/quick-create/preview/",
                content=payload,
                headers={"X-JJDGuard-Internal-Token": "test-secret", "Content-Type": "application/json"},
            )

    for payload in (
        b'{"matcher":{"type":"keyword","config":{"keywords":["hiddenvalue\\ud800"]}},"samples":["hiddenvalue"]}',
        b'{"matcher":{"type":"regex","config":{"regex":"hiddenvalue\\ud800"}},"samples":["hiddenvalue"]}',
    ):
        response = anyio.run(request, payload)
        assert response.status_code == 422
        assert response.json()["detail"]["code"] == "invalid_matcher"
        assert "hiddenvalue" not in response.text


def test_number_generated_regex_matches_runtime_with_ascii_boundaries(monkeypatch):
    monkeypatch.setenv("JJD_INTERNAL_API_SECRET", "test-secret")
    from app.custom_rules import CompiledRule, CustomRuleSet

    pattern = r"(?<![A-Za-z0-9_])120[0-9]{3}99(?![A-Za-z0-9_])"
    matcher = {"type": "regex", "config": {"regex": pattern}}
    samples = [
        "编号12010199已核实", "编号12080899已核实",
        "x12010199", "12010199x", "_12010199", "12010199_",
        "012010199", "120101990", "正常文本",
    ]
    response = anyio.run(_preview, matcher, samples, "test-secret")
    assert response.status_code == 200
    matches = response.json()["matches"]
    assert [entry["matched"] for entry in matches] == [True, True, False, False, False, False, False, False, False]
    assert [matches[index]["location"] for index in (0, 1)] == ["content[2:10]", "content[2:10]"]
    assert all(sample not in response.text for sample in samples)

    rules = CustomRuleSet([CompiledRule(
        rule_id="generated_number", rule_name="generated_number", rule_type="regex",
        category="custom", severity="medium", action="audit", regex=pattern,
    )])
    assert not rules.skipped
    for index, sample in enumerate(samples):
        findings = rules.match(sample)
        assert bool(findings) is matches[index]["matched"]
        if findings:
            assert findings[0].matched_location == matches[index]["location"]


def test_number_with_fixed_punctuation_is_literal_in_python_runtime(monkeypatch):
    monkeypatch.setenv("JJD_INTERNAL_API_SECRET", "test-secret")
    from app.custom_rules import CompiledRule, CustomRuleSet

    pattern = r"(?<![A-Za-z0-9_])AB\.120[0-9]{3}99-X(?![A-Za-z0-9_])"
    matcher = {"type": "regex", "config": {"regex": pattern}}
    samples = ["编号AB.12010199-X在此", "AB.12099999-X", "ABz12010199-X", "XAB.12010199-X", "AB.12010199-XX"]
    response = anyio.run(_preview, matcher, samples, "test-secret")
    assert response.status_code == 200
    assert [item["matched"] for item in response.json()["matches"]] == [True, True, False, False, False]
    rules = CustomRuleSet([CompiledRule(
        rule_id="mixed_number", rule_name="mixed_number", rule_type="regex",
        category="custom", severity="medium", action="audit", regex=pattern,
    )])
    assert not rules.skipped
    assert [bool(rules.match(sample)) for sample in samples] == [True, True, False, False, False]


def test_number_generated_regex_full_span_and_neighbors(monkeypatch):
    monkeypatch.setenv("JJD_INTERNAL_API_SECRET", "test-secret")
    from app.custom_rules import CompiledRule, CustomRuleSet
    pattern = r"(?<![A-Za-z0-9_])HT-2026-[0-9]{6}(?![A-Za-z0-9_])"
    samples = [
        "\u7f16\u53f7HT-2026-000123\u5df2\u6838\u5b9e",
        "(HT-2026-000456)", "HT-2026-999999",
        "xHT-2026-000123", "HT-2026-000123x",
        "_HT-2026-000123", "HT-2026-000123_",
        "1HT-2026-000123", "HT-2026-0001231", "ordinary text",
    ]
    response = anyio.run(_preview, {"type": "regex", "config": {"regex": pattern}}, samples, "test-secret")
    assert response.status_code == 200
    matches = response.json()["matches"]
    assert [item["matched"] for item in matches] == [True, True, True, False, False, False, False, False, False, False]
    assert [item["location"] for item in matches[:3]] == ["content[2:16]", "content[1:15]", "content[0:14]"]
    assert all(item not in response.text for item in samples)
    rules = CustomRuleSet([CompiledRule(rule_id="full_number", rule_name="full_number", rule_type="regex", category="custom", severity="medium", action="audit", regex=pattern)])
    assert not rules.skipped
    assert [bool(rules.match(sample)) for sample in samples] == [item["matched"] for item in matches]
