"""Regression from reviewed personal gateway alert fragments, not whole-request labels."""
import pytest
from app.detectors.engine import SecurityEngine

@pytest.mark.parametrize("content", [
    "Chunk ID: fcd4b0\nWall time: 0.0000 seconds\nProcess exited with code 0\n"
    "Original token count: 15281\nOutput:\nWarning: truncated output (original token count: 15281)\n",
    "Exit code 2\nbash: -c: line 1: syntax error near unexpected token `('\"\n",
    "Stderr: bash: -c: line 2: syntax error near unexpected token `2'\n",
    "IMPORTANT: Assist with authorized security testing. Credential testing requires clear authorization.\n",
    "service: worker\nnotes: connection closed while processing a token count\n",
    "MODE=review\nNOTES=inspect token counts and credential documentation\n",
    "MODE=review\nTOKEN_COUNT=15281\nINTERNAL_SECRET_NAME=documentation\n",
])
def test_config_detection_does_not_treat_described_sensitive_words_as_credentials(content):
    findings = SecurityEngine()._detect_code_config(content)
    assert not [f for f in findings if f.rule_id in {"code_config_file", "code_env_file"}]

@pytest.mark.parametrize("content", [
    "service: worker\npassword: synthetic-credential-only\n",
    'service: worker\n"password": "synthetic-credential-only"\n',
    "MODE=production\nPASSWORD=synthetic-credential-only\n",
    "MODE=production\nFRONTEND_TOKEN=synthetic-credential-only\n",
    "service: worker\napi_key = synthetic-credential-only\n",
    "service: worker\nurl: postgres://fixture:fixture@db.example.invalid/db\n",
    "Output:\nWarning: truncated output (original token count: 15281)\n"
    "service: worker\npassword: synthetic-credential-only\n",
])
def test_config_detection_keeps_real_assignments_and_connection_strings(content):
    findings = SecurityEngine()._detect_code_config(content)
    assert any(f.rule_id in {"code_config_file", "code_env_file"} for f in findings)

def test_config_word_fix_does_not_suppress_private_key_markers():
    findings = SecurityEngine()._detect_code_config("-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n")
    assert any(f.rule_id == "code_openssh_private_key" for f in findings)
