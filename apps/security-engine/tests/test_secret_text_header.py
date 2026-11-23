"""秘密本体只在请求带 X-JJD-Want-Secret-Text: 1 时才随检测响应返回。"""
import pytest
from fastapi.testclient import TestClient

import app.main as main_module

HEADER_NAME = "X-JJD-Want-Secret-Text"
KEY_HEADER = "-----BEGIN RSA PRIVATE KEY-----"
BODY = "\nMIIEowIBAAKCAQEA" + "Zz9y" * 60 + "\n"
CONTENT = "帮我看看这个密钥对不对\n" + KEY_HEADER + BODY + "-----END RSA PRIVATE KEY-----\n谢谢"


@pytest.fixture
def client():
    return TestClient(main_module.app)


def _all_findings(payload):
    return list(payload.get("findings", [])) + list(payload.get("raw_findings", []))


def _key(payload):
    return next(f for f in payload["findings"] if f["category"] == "ssh_private_key")


def _input_body(request_id):
    return {"request_id": request_id, "content": CONTENT, "content_source": "user", "skip_semantic": True}


@pytest.mark.parametrize("headers,expected", [({}, False), ({HEADER_NAME: "0"}, False),
                                              ({HEADER_NAME: "yes"}, False), ({HEADER_NAME: "1"}, True)])
def test_check_input(client, headers, expected):
    response = client.post("/check-input/", json=_input_body("hdr-in"), headers=headers)
    assert response.status_code == 200
    payload = response.json()
    assert bool(_key(payload)["secret_text"]) is expected
    if not expected:
        assert all(f["secret_text"] == "" for f in _all_findings(payload))
    assert all(f["secret_text"] == "" for f in payload["raw_findings"])


@pytest.mark.parametrize("headers,expected", [({}, False), ({HEADER_NAME: "1"}, True)])
def test_check_input_batch(client, headers, expected):
    response = client.post("/check-input/batch", json=[_input_body("hdr-b1"), _input_body("hdr-b2")],
                           headers=headers)
    assert response.status_code in (200, 207)
    for item in response.json():
        assert bool(_key(item)["secret_text"]) is expected
        if not expected:
            assert all(f["secret_text"] == "" for f in _all_findings(item))


@pytest.mark.parametrize("headers,expected", [({}, False), ({HEADER_NAME: "1"}, True)])
def test_check_output(client, headers, expected):
    response = client.post("/check-output/", json={"request_id": "hdr-out", "content": CONTENT,
                                                   "skip_semantic": True}, headers=headers)
    assert response.status_code == 200
    payload = response.json()
    assert bool(_key(payload)["secret_text"]) is expected
    if not expected:
        assert all(f["secret_text"] == "" for f in _all_findings(payload))


@pytest.mark.parametrize("headers,expected", [({}, False), ({HEADER_NAME: "1"}, True)])
def test_apply_context(client, headers, expected):
    first = client.post("/check-input/", json=_input_body("hdr-ctx"), headers={HEADER_NAME: "1"}).json()
    response = client.post("/apply-context/", headers=headers, json={
        "tenant_id": "tenant_default", "raw_findings": first["raw_findings"],
        "context": {"content_source": "user"},
    })
    assert response.status_code == 200, response.text
    assert bool(_key(response.json())["secret_text"]) is expected
    if not expected:
        assert all(f["secret_text"] == "" for f in response.json()["findings"])


def test_test_endpoint_never_returns_secret_text(client):
    response = client.post("/test/", json={"text": CONTENT})
    assert response.status_code == 200
    findings = response.json()["findings"]
    assert any(f["category"] == "ssh_private_key" for f in findings)
    assert all(f["secret_text"] == "" for f in findings)
    response = client.post("/test/", json={"text": CONTENT}, headers={HEADER_NAME: "1"})
    assert all(f["secret_text"] == "" for f in response.json()["findings"])
