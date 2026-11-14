"""Optional email sign-in: codes, sessions, limits, and "my reports". Anonymous use must not change."""
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

import login
from app import app
from db.connection import get_db, set_db
from db.fake_mongo import FakeDatabase

EML = (b'From: sender@example.test\r\nSubject: Login smoke\r\nContent-Type: text/plain\r\n\r\n'
       b'Hello, meeting at noon.')


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv('THREAT_INTEL_LIVE', '0')
    monkeypatch.setenv('GEMINI_API_KEY', '')
    monkeypatch.setenv('USE_FAKE_DB', '1')
    monkeypatch.delenv('BREVO_API_KEY', raising=False)
    monkeypatch.delenv('RESEND_API_KEY', raising=False)
    monkeypatch.setenv('AUTH_DEV_ECHO', '1')
    monkeypatch.setenv('AUTH_SECRET', 'test-secret')
    login._ip_hits.clear()
    set_db(FakeDatabase())
    with TestClient(app) as c:
        yield c


def sign_in(client, email='Person@Example.test'):
    code = client.post('/auth/request-code', json={'email': email}).json()['dev_code']
    reply = client.post('/auth/verify-code', json={'email': email, 'code': code})
    assert reply.status_code == 200, reply.text
    return reply.json()


def bearer(token):
    return {'Authorization': f'Bearer {token}'}


def test_full_sign_in_and_out(client):
    session = sign_in(client)
    assert session['email'] == 'person@example.test'
    assert client.get('/auth/me', headers=bearer(session['token'])).json() == {'email': 'person@example.test'}
    assert client.post('/auth/logout', headers=bearer(session['token'])).json() == {'ok': True}
    assert client.get('/auth/me', headers=bearer(session['token'])).status_code == 401


def test_me_needs_a_real_token(client):
    assert client.get('/auth/me').status_code == 401
    assert client.get('/auth/me', headers=bearer('nonsense')).status_code == 401


def test_token_and_code_are_not_stored_in_clear(client):
    email = 'person@example.test'
    code = client.post('/auth/request-code', json={'email': email}).json()['dev_code']
    stored = get_db()[login.CODES].find_one({'email': email})
    assert code not in str(stored)
    token = client.post('/auth/verify-code', json={'email': email, 'code': code}).json()['token']
    assert token not in str(get_db()[login.SESSIONS].find_one({'email': email}))


def test_status_and_unconfigured_server(client, monkeypatch):
    assert client.get('/auth/status').json() == {'enabled': True}
    monkeypatch.delenv('AUTH_DEV_ECHO')
    assert client.get('/auth/status').json() == {'enabled': False}
    assert client.post('/auth/request-code', json={'email': 'a@b.test'}).status_code == 503


def test_dev_code_is_never_returned_when_a_provider_is_configured(client, monkeypatch):
    monkeypatch.setenv('BREVO_API_KEY', 'key')
    monkeypatch.setenv('LOGIN_FROM_EMAIL', 'sender@example.test')
    sent = []
    monkeypatch.setattr(login, 'send_code_email', lambda email, code: sent.append((email, code)))
    reply = client.post('/auth/request-code', json={'email': 'a@b.test'})
    assert reply.json() == {'ok': True}
    assert len(sent) == 1 and len(sent[0][1]) == 6 and sent[0][1].isdigit()


@pytest.mark.parametrize('bad', ['', 'nope', 'a@b', 'a b@c.test', 'x' * 260 + '@c.test'])
def test_rejects_bad_email(client, bad):
    assert client.post('/auth/request-code', json={'email': bad}).status_code in {400, 422}


def test_wrong_code_then_burned_after_five_tries(client):
    email = 'person@example.test'
    client.post('/auth/request-code', json={'email': email})
    for _ in range(login.MAX_ATTEMPTS):
        assert client.post('/auth/verify-code', json={'email': email, 'code': '000000x'}).status_code == 400
    assert client.post('/auth/verify-code', json={'email': email, 'code': '000000'}).status_code == 429
    assert client.post('/auth/verify-code', json={'email': email, 'code': '000000'}).status_code == 400


def test_code_cannot_be_reused(client):
    email = 'person@example.test'
    code = client.post('/auth/request-code', json={'email': email}).json()['dev_code']
    assert client.post('/auth/verify-code', json={'email': email, 'code': code}).status_code == 200
    assert client.post('/auth/verify-code', json={'email': email, 'code': code}).status_code == 400


def test_expired_code_is_refused(client):
    email = 'person@example.test'
    code = client.post('/auth/request-code', json={'email': email}).json()['dev_code']
    entry = get_db()[login.CODES].find_one({'email': email})
    get_db()[login.CODES].update_one({'email': email},
                                     {'$set': {'expires_at': entry['expires_at'] - timedelta(hours=1)}})
    assert client.post('/auth/verify-code', json={'email': email, 'code': code}).status_code == 400


def test_expired_session_is_refused(client):
    session = sign_in(client)
    row = get_db()[login.SESSIONS].find_one({'email': session['email']})
    get_db()[login.SESSIONS].update_one({'email': session['email']},
                                        {'$set': {'expires_at': row['expires_at'] - timedelta(days=60)}})
    assert client.get('/auth/me', headers=bearer(session['token'])).status_code == 401


def test_cooldown_between_codes(client):
    assert client.post('/auth/request-code', json={'email': 'a@b.test'}).status_code == 200
    assert client.post('/auth/request-code', json={'email': 'a@b.test'}).status_code == 429


def test_hourly_cap_per_email(client):
    email = 'a@b.test'
    for _ in range(login.MAX_CODES_PER_HOUR):
        assert client.post('/auth/request-code', json={'email': email}).status_code == 200
        entry = get_db()[login.CODES].find_one({'email': email})
        get_db()[login.CODES].update_one({'email': email},
                                         {'$set': {'last_sent_at': entry['last_sent_at'] - timedelta(minutes=2)}})
        login._ip_hits.clear()
    assert client.post('/auth/request-code', json={'email': email}).status_code == 429


def test_ip_throttle(client):
    codes = [client.post('/auth/request-code', json={'email': f'u{i}@b.test'}).status_code
             for i in range(login.IP_MAX_REQUESTS_PER_HOUR + 1)]
    assert codes[:-1] == [200] * login.IP_MAX_REQUESTS_PER_HOUR and codes[-1] == 429


def test_provider_failure_is_a_clean_503_and_leaves_no_code(client, monkeypatch):
    monkeypatch.setenv('BREVO_API_KEY', 'key')

    def boom(email, code):
        raise RuntimeError('provider down')
    monkeypatch.setattr(login, 'send_code_email', boom)
    assert client.post('/auth/request-code', json={'email': 'a@b.test'}).status_code == 503
    assert get_db()[login.CODES].find_one({'email': 'a@b.test'}) is None


def test_brevo_request_shape(monkeypatch):
    monkeypatch.setenv('BREVO_API_KEY', 'secret-key')
    monkeypatch.setenv('LOGIN_FROM_EMAIL', 'sender@example.test')
    seen = {}

    class Reply:
        status_code = 201

    def fake_post(url, headers, json, timeout):
        seen.update(url=url, headers=headers, json=json, timeout=timeout)
        return Reply()
    monkeypatch.setattr(login.requests, 'post', fake_post)
    login.send_code_email('to@example.test', '123456')
    assert seen['url'] == 'https://api.brevo.com/v3/smtp/email'
    assert seen['headers']['api-key'] == 'secret-key'
    assert seen['json']['to'] == [{'email': 'to@example.test'}]
    assert '123456' in seen['json']['textContent'] and seen['timeout'] == 10


def test_anonymous_analysis_and_listing_still_work(client):
    reply = client.post('/analyze', files={'file': ('a.eml', EML, 'message/rfc822')})
    assert reply.status_code == 200, reply.text
    assert client.get('/investigations').status_code == 200
    assert get_db()['analyzed_emails'].find_one({'owner_email': {'$ne': None}}) is None


def test_my_reports_lists_only_my_own(client):
    mine = sign_in(client, 'me@example.test')
    other = sign_in(client, 'other@example.test')
    mine_id = client.post('/analyze', files={'file': ('a.eml', EML.replace(b'Login smoke', b'Mine'), 'message/rfc822')},
                          headers=bearer(mine['token'])).json()['email_id']
    client.post('/analyze', files={'file': ('b.eml', EML.replace(b'Login smoke', b'Theirs'), 'message/rfc822')},
                headers=bearer(other['token']))
    client.post('/analyze', files={'file': ('c.eml', EML.replace(b'Login smoke', b'Anon'), 'message/rfc822')})

    listed = client.get('/investigations?mine=1', headers=bearer(mine['token'])).json()
    assert [row['email_id'] for row in listed] == [mine_id]
    assert len(client.get('/investigations').json()) == 3
    assert client.get('/investigations?mine=1').status_code == 401


def test_job_route_tags_the_owner(client):
    import time
    session = sign_in(client)
    started = client.post('/analyze/jobs', files={'file': ('a.eml', EML, 'message/rfc822')},
                          headers=bearer(session['token'])).json()
    for _ in range(100):
        job = client.get(f"/analyze/jobs/{started['job_id']}").json()
        if job['status'] != 'running':
            break
        time.sleep(0.1)
    assert job['status'] == 'done', job
    listed = client.get('/investigations?mine=1', headers=bearer(session['token'])).json()
    assert [row['email_id'] for row in listed] == [job['report']['email_id']]
