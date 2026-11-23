import json
import secrets
from pathlib import Path
import pytest
from app.detectors.engine import SecurityEngine
from app.detectors.config_evidence import read_credential_value

CREDENTIALS={'plain_password','code_leak_password_in_code','code_leak_database_url'}
ROWS=json.loads((Path(__file__).parent/'fixtures/credential_replay/production_password_group.json').read_text())

def detections(text):
    return [f for f in SecurityEngine().check_output('grammar',text,context={'agent_type':'openai-codex','access_type':'ai_ide'}).findings if f.category in CREDENTIALS and f.counts_as_security_finding]

# Positive controls are generated in the isolated test process, not sent as
# literal credentials through the assistant's production model conversation.
@pytest.fixture
def literal():
    return secrets.token_urlsafe(24)+'aA9!'

@pytest.mark.parametrize('depth',range(5))
@pytest.mark.parametrize('source',[
    "text = 'PASSWORD=' + value + '\\n'",
    'text = "PASSWORD=" + value',
    'text = "password: " + lookup_value()',
    'text = "password=%s" % value',
    'text = "password={}".format(value)',
    'text = f"password={password}"',
    'text = `password=${process.env.PASSWORD}`',
    'password=$env:DB_PASSWORD',
    'password=%DB_PASSWORD%',
    'password=${PASSWORD:?required}',
    'password=process.env["DB_PASSWORD"]',
    'password=load_password()',
    'dsn = "postgres://postgres:test@" + address',
    'dsn = "postgres://user:password@" + host',
])
def test_code_construction_has_no_concrete_secret(depth,source):
    for _ in range(depth):source=json.dumps({'cmd':source})
    assert not detections(source)

@pytest.mark.parametrize('depth',range(5))
def test_expression_does_not_hide_next_literal(depth,literal):
    source="text = 'PASSWORD=' + value + '\\n'\npassword='"+literal+"'"
    for _ in range(depth):source=json.dumps({'cmd':source})
    hits=detections(source)
    assert hits and any(literal in f.raw_evidence for f in hits)
    assert all('+ value +' not in f.raw_evidence for f in hits)

@pytest.mark.parametrize('value',['process.env.PASSWORD','load_password()','test','; punctuation +','a+b','+abc'])
def test_quoted_literal_is_not_unquoted_code(value):
    parsed=read_credential_value('"'+value+'"')
    assert parsed.kind=='literal'

# A quote whose content opens with an infix operator is the gap between two
# string literals ('KEY=' + value + '\n'); it is source, not a quoted secret.
@pytest.mark.parametrize('value',['+ value +',' + value + ',' . $name . ','+ value'])
def test_quoted_concatenation_gap_is_an_expression(value):
    assert read_credential_value('"'+value+'"').kind=='expression'

@pytest.mark.parametrize('host',['db.internal','localhost','127.0.0.1','[::1]','${DB_HOST}'])
def test_complete_url_credentials_are_not_exempted_by_test_context(host,literal):
    text='test_fixture = "postgresql://admin:'+literal+'@'+host+'/db"'
    assert any(f.category=='code_leak_database_url' for f in detections(text))

@pytest.mark.parametrize('host',['','\\','\\\\','<','{'])
def test_incomplete_authority_is_not_a_connection_string(host):
    assert not [f for f in detections('postgres://postgres:test@'+host) if f.category=='code_leak_database_url']

def test_weak_password_on_real_endpoint_is_still_detected(literal):
    weak=literal[:4].lower()
    assert any(f.category=='code_leak_database_url' for f in detections('postgres://postgres:'+weak+'@db.internal/test'))

@pytest.mark.parametrize('row',ROWS,ids=lambda r:r['request_id'])
def test_every_original_request_has_only_explicit_literal_controls(row):
    hits=detections(row['content'])
    allowed=('Synthetic','Acceptance','N3w-Passw0rd','DoNotReveal')
    unexpected=[f for f in hits if not any(v in f.raw_evidence for v in allowed)]
    assert not unexpected,[(f.category,f.matched_location) for f in unexpected]

@pytest.mark.parametrize('depth',range(5))
def test_direct_literal_concatenation_remains_detectable(depth,literal):
    text="text = 'password=' + '"+literal+"'"
    for _ in range(depth):text=json.dumps({'cmd':text})
    assert any(literal in f.raw_evidence for f in detections(text))

@pytest.mark.parametrize('prefix',['test_','Synthetic_','example_'])
def test_test_words_do_not_exempt_real_literal_values(prefix,literal):
    value=prefix+literal
    assert any(value in f.raw_evidence for f in detections("password='"+value+"'"))

@pytest.mark.parametrize('field',['password','PASSWORD','dbPassword','db_password','用户密码'])
@pytest.mark.parametrize('depth',range(5))
def test_field_spelling_does_not_change_construction_semantics(field,depth):
    text="output = '"+field+"=' + value + '\\n'"
    for _ in range(depth):text=json.dumps({'cmd':text},ensure_ascii=False)
    assert not detections(text)

@pytest.mark.parametrize('component',['load_password()','process.env.PASSWORD','z.String9()','space%20inside'])
def test_uri_password_component_is_data_not_executable_code(component):
    text='postgresql://account:'+component+'@db.internal/prod'
    assert any(f.category=='code_leak_database_url' for f in detections(text))
