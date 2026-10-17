"""API smoke tests. The API is open: no keys, no sign-in, no per-user scoping."""
import pytest
from fastapi.testclient import TestClient
from app import app
from db.connection import set_db
from db.fake_mongo import FakeDatabase


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv('THREAT_INTEL_LIVE', '0')
    monkeypatch.setenv('GEMINI_API_KEY', '')
    monkeypatch.setenv('USE_FAKE_DB', '1')
    set_db(FakeDatabase())
    with TestClient(app) as c:
        yield c


def test_data_routes_need_no_credentials(client):
    assert client.get('/investigations').status_code == 200
    assert client.get('/campaigns').status_code == 200
    assert client.get('/recovery').status_code == 200


def test_stray_authorization_header_is_ignored(client):
    assert client.get('/investigations', headers={'Authorization': 'Bearer anything'}).status_code == 200


def test_auth_layer_is_gone(client):
    assert client.get('/me').status_code == 404
    for module in ('security', 'db.scoped', 'provision_key', 'migrate_workflow_c'):
        with pytest.raises(ImportError):
            __import__(module)


@pytest.mark.parametrize('body,source', [
    (b'Hello, meeting at noon.', 'full_message'),
    (b'Urgent verify your password at https://login.example.test', 'full_message'),
    (b'Hello from the visible message.', 'quick_content_check'),
])
def test_pipeline_smoke(client, body, source):
    message = b'From: sender@example.test\r\nSubject: Synthetic smoke\r\nContent-Type: text/plain\r\n\r\n' + body
    result = client.post('/analyze', files={'file': ('synthetic.eml', message, 'message/rfc822')}, data={'source': source})
    assert result.status_code == 200, result.text
    report = result.json()
    assert report['evidence_report'] and report['provider_status']
    assert client.get('/investigations/' + report['email_id']).status_code == 200


def test_late_background_rag_cannot_resurrect_deleted_record(monkeypatch):
    import threading
    from pipeline import analyze_email_upload
    captured = []

    class DeferredThread:
        def __init__(self, target, args, **kwargs):
            captured.append((target, args))

        def start(self):
            pass

    monkeypatch.setattr(threading, 'Thread', DeferredThread)
    monkeypatch.setenv('USE_FAKE_DB', '1')
    monkeypatch.setenv('THREAT_INTEL_LIVE', '0')
    monkeypatch.setenv('GEMINI_API_KEY', '')
    monkeypatch.setenv('USE_FALLBACK_EMBEDDINGS', '1')
    raw = FakeDatabase()
    set_db(raw)
    analyze_email_upload('synthetic.eml', b'From: sender@example.test\r\nSubject: Hello\r\n\r\nMeeting notes', 'quick_content_check')
    target, args = captured[-1]
    target(*args)
    doc = raw['analyzed_emails'].find_one({})
    assert doc.get('rag_embedding') and doc.get('rag_summary')
    raw['analyzed_emails'].delete_many({})
    target(*args)
    assert raw['analyzed_emails'].count_documents({}) == 0
