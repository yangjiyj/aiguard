from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
OFFLINE = (ROOT / "docker-compose.offline.yml").read_text(encoding="utf-8")
ENV_EXAMPLE = (ROOT / ".env.example").read_text(encoding="utf-8")

def _control_plane_block(body: str) -> str:
    marker = "  control-plane:"
    start = body.index(marker)
    return body[start:]

def test_control_plane_exposes_lse_allowlist_and_rbac_gate():
    for body in (COMPOSE, OFFLINE):
        block = _control_plane_block(body)
        assert "LSE_BASE_URL_ALLOWLIST=${LSE_BASE_URL_ALLOWLIST:-}" in block
        assert "UAG_RBAC_ENFORCE=${UAG_RBAC_ENFORCE:-false}" in block

def test_env_example_documents_fail_closed_integration_controls():
    assert "LSE_BASE_URL_ALLOWLIST=" in ENV_EXAMPLE
    assert "UAG_RBAC_ENFORCE=false" in ENV_EXAMPLE
