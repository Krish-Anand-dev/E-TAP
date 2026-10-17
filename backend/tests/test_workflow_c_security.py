import hashlib
import json
import pytest
from fastapi.testclient import TestClient
from app import app
from db.connection import set_db
from db.fake_mongo import FakeDatabase
from db.scoped import ScopedDatabase
from security import _usage

@pytest.fixture
def client(monkeypatch):
    entries = [{'owner_id': name, 'role': role, 'sha256': hashlib.sha256((name+'-synthetic-test-key').encode()).hexdigest()} for name, role in [('alice', 'analyst'), ('bob', 'reporter')]]
    monkeypatch.setenv('ETAP_API_KEYS', json.dumps(entries))
    monkeypatch.setenv('THREAT_INTEL_LIVE', '0')
    monkeypatch.setenv('GEMINI_API_KEY', '')
    monkeypatch.setenv('USE_FAKE_DB', '1')
    _usage.clear()
    db = FakeDatabase()
    set_db(db)
    db['analyzed_emails'].insert_one({'_id': 'bob-report', 'owner_id': 'bob', 'subject': 'BOB PRIVATE', 'ioc_analysis': {'domains': ['shared.example']}})
    db['analyzed_emails'].insert_one({'_id': 'legacy', 'subject': 'LEGACY PRIVATE'})
    with TestClient(app) as c:
        yield c

def headers(name='alice'):
    return {'Authorization': 'Bearer '+name+'-synthetic-test-key'}

@pytest.mark.parametrize('method,path', [('get','/investigations/bob-report'),('get','/investigations'),('get','/campaigns'),('post','/chat'),('post','/analyze')])
def test_anonymous(client, method, path):
    assert getattr(client, method)(path).status_code == 401

def test_owner_and_legacy_isolation(client):
    for path in ['/investigations/bob-report', '/investigations/legacy']:
        assert client.get(path, headers=headers()).status_code == 404
    assert client.get('/investigations', headers=headers()).json() == []
    assert client.post('/chat', headers=headers(), json={'question':'show report', 'email_id':'bob-report'}).status_code == 404
    result = client.post('/chat', headers=headers(), json={'question':'show everything'})
    assert result.status_code == 200
    assert 'BOB PRIVATE' not in result.text and 'LEGACY PRIVATE' not in result.text
    assert result.json()['sources'] == []
    assert client.post('/chat', headers=headers(), json={'question':'show', 'email_context': {'email_id':'bob-report'}}).status_code == 400

def test_size_and_budget(client, monkeypatch):
    assert client.post('/chat', headers=headers(), content=b'x'*65537).status_code == 413
    monkeypatch.setenv('ETAP_PROVIDER_OPERATIONS_PER_DAY','1')
    assert client.post('/chat', headers=headers(), json={'question':'hi'}).status_code == 429

def test_scoped_correlation_and_rag():
    from correlation.engine import correlate_and_store
    from rag.chat import search_similar_investigations
    db = FakeDatabase()
    a, b = ScopedDatabase(db, 'a'), ScopedDatabase(db, 'b')
    first = correlate_and_store({'domains':['shared.example']}, db=b, message_id='same')
    second = correlate_and_store({'domains':['shared.example']}, db=a, message_id='same')
    assert second['related_emails'] == []
    assert first['email_id'] != second['email_id']
    assert a['analyzed_emails'].count_documents({}) == 1
    assert len(list(db['analyzed_emails'].find({}))) == 2
    assert all(x['email_id'] != first['email_id'] for x in search_similar_investigations('shared', a))

@pytest.mark.parametrize('body,source', [(b'Hello, meeting at noon.', 'full_message'),(b'Urgent verify your password at https://login.example.test', 'full_message'),(b'Hello from the visible message.', 'quick_content_check')])
def test_pipeline_smoke(client, body, source):
    message = b'From: sender@example.test\r\nSubject: Synthetic smoke\r\nContent-Type: text/plain\r\n\r\n'+body
    result = client.post('/analyze', headers=headers(), files={'file':('synthetic.eml',message,'message/rfc822')}, data={'source':source})
    assert result.status_code == 200, result.text
    report = result.json()
    assert report['evidence_report'] and report['provider_status']
    assert client.get('/investigations/'+report['email_id'], headers=headers()).status_code == 200
    assert client.get('/investigations/'+report['email_id'], headers=headers('bob')).status_code == 404

def test_atlas_prefilter_cannot_be_overridden():
    from unittest.mock import MagicMock
    from db.scoped import ScopedCollection
    raw=MagicMock()
    scoped=ScopedCollection(raw,'alice','analyzed_emails')
    scoped.aggregate([{'$vectorSearch':{'filter':{'owner_id':'bob'},'limit':5}}])
    assert raw.aggregate.call_args.args[0][0]['$vectorSearch']['filter'] == {'owner_id':'alice'}
    with pytest.raises(ValueError): scoped.aggregate([{'$lookup':{'from':'analyzed_emails'}}])

def test_late_background_rag_is_scoped_and_cannot_resurrect(monkeypatch):
    import threading
    from security import principal
    from pipeline import analyze_email_upload
    from db.connection import get_db
    captured=[]
    class DeferredThread:
        def __init__(self,target,args,**kwargs): captured.append((target,args))
        def start(self): pass
    monkeypatch.setattr(threading,'Thread',DeferredThread)
    monkeypatch.setenv('USE_FAKE_DB','1')
    monkeypatch.setenv('THREAT_INTEL_LIVE','0')
    monkeypatch.setenv('GEMINI_API_KEY','')
    monkeypatch.setenv('USE_FALLBACK_EMBEDDINGS','1')
    raw=FakeDatabase(); set_db(raw)
    token=principal.set({'owner_id':'alice','role':'analyst'})
    try:
        report=analyze_email_upload('synthetic.eml',b'From: sender@example.test\r\nSubject: Hello\r\n\r\nMeeting notes', 'quick_content_check')
    finally: principal.reset(token)
    target,args=captured[-1]
    target(*args)  # no request identity in this execution context
    doc=raw['analyzed_emails'].find_one({'owner_id':'alice'})
    assert doc.get('rag_embedding') and doc.get('rag_summary')
    raw['analyzed_emails'].delete_many({'owner_id':'alice'})
    target(*args)
    assert raw['analyzed_emails'].count_documents({}) == 0

def test_chunked_request_limit_before_app(client):
    import asyncio
    from security import SecurityBoundary
    called=[]
    sent=[]
    messages=[{'type':'http.request','body':b'x'*32768,'more_body':True} for _ in range(3)]
    async def receive(): return messages.pop(0)
    async def send(message): sent.append(message)
    async def endpoint(*args): called.append(True)
    scope={'type':'http','method':'POST','path':'/chat','headers':[(b'authorization',b'Bearer alice-synthetic-test-key')]}
    asyncio.run(SecurityBoundary(endpoint)(scope,receive,send))
    assert not called
    assert sent[0]['status'] == 413

def test_forged_identity_headers_ignored(client):
    spoofed={**headers('bob'),'X-Owner-Id':'alice','X-Role':'admin'}
    assert client.get('/me',headers=spoofed).json() == {'owner_id':'bob','role':'reporter'}

def test_migration_quarantine_is_idempotent():
    from migrate_workflow_c import migrate
    raw=FakeDatabase()
    raw['analyzed_emails'].insert_one({'_id':'legacy','subject':'synthetic'})
    raw['analyzed_emails'].insert_one({'_id':'owned','owner_id':'alice'})
    for name,index in [('analyzed_emails','message_id_1'),('campaigns','campaign_id_1')]:
        indices={index:{}}
        raw[name].index_information=lambda indices=indices: indices
        raw[name].drop_index=lambda key,indices=indices: indices.pop(key)
    migrate(raw); migrate(raw)
    assert raw['analyzed_emails'].find_one({'_id':'legacy'})['owner_id'] == '__quarantine__'
    assert raw['analyzed_emails'].find_one({'_id':'owned'})['owner_id'] == 'alice'
