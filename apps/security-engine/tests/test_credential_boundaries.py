"""Production password prompts, serialized shell templates and path tokens."""
import pytest
from app.detectors.engine import SecurityEngine

BAD_CATEGORIES = {"plain_password", "code_leak_password_in_code", "openai_key"}

@pytest.mark.parametrize("text", [
    "连接仍停在 `yj@host's password:`。请在底部终端中输入密码并回车；下一步继续。",
    "password: Please enter your password to continue",
    "password:\nPlease enter your password to continue",
    'password="${ADMIN_PASSWORD}"',
    'password=$ADMIN_PASSWORD',
    r"BOOTSTRAP_ADMIN_PASSWORD=$ADMIN_PASSWORD\nWEB_PORT=$WEB_PORT\nWEB_BIND=$EXTERNAL_BIND",
    r"REDIS_PASSWORD=$REDIS_PASSWORD\nGATEWAY_ENVIRONMENT_SCOPE=customer\nSECURITY_AUDIT_ONLY=false",
    r"POSTGRES_PASSWORD=${CHAT_POSTGRES_PASSWORD:-}\nPOSTGRES_DB=jjdguard",
    r"DATABASE_URL=postgresql://postgres:${CHAT_POSTGRES_PASSWORD:-}@chat-postgres:5432/${CHAT_POSTGRES_DB:-portal}\n",
    r"POSTGRES_PASSWORD=$POSTGRES_PASSWORD\nPOSTGRES_DB=jjdguard\nEOF\n",
    'password="<your-password>"',
    r'C:\work\chkdsk-r-progress-20260920T143236Z.bmp',
    "task-sk-r-progress-20260920T143236Z",
])
def test_normal_programming_text_is_not_a_credential(text):
    result = SecurityEngine().check_output("regression", text)
    assert not [f for f in result.raw_findings if f.category in BAD_CATEGORIES]

@pytest.mark.parametrize("text,category", [
    ('password: `SyntheticPassword42!`', "code_leak_password_in_code"),
    ('password="SyntheticPassword42!"', "code_leak_password_in_code"),
    ('password="密码甲乙丙丁戊己"', "code_leak_password_in_code"),
    ('登录密码：N3w-Passw0rd!', "plain_password"),
    ('password=$ADMIN_PASSWORD; password="SyntheticPassword42!"', "code_leak_password_in_code"),
    ('password="${PASSWORD}"; password="SyntheticPassword42!"', "code_leak_password_in_code"),
    ('api_key="sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"', "openai_key"),
    ('Bearer sk-Q7mR2vW9xL4cN8pT5aB3dF6hJ1kZ0sE4', "openai_key"),
    ('path=/tmp/sk-proj-abcdefghijklmnopqrstuvwxyz1234567890', "openai_key"),
])
def test_literal_credentials_remain_detectable(text, category):
    assert any(f.category == category for f in SecurityEngine().check_output("control", text).raw_findings)
