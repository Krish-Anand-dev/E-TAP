"""Linking a WhatsApp number to an account, proven by sending a code to the bot (one-way, no replies needed)."""
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

import login
import whatsapp
import whatsapp_link
from app import app
from db.connection import get_db, set_db
from db.fake_mongo import FakeDatabase

SECRET = 'meta-app-secret'
USER = '919876543210'
OTHER = '911111111111'


def sign(raw: bytes):
    return 'sha256=' + hmac.new(SECRET.encode(), raw, hashlib.sha256).hexdigest()


def text_payload(sender, body, mid):
    message = {'from': sender, 'id': mid, 'type': 'text', 'text': {'body': body}}
    value = {'messaging_product': 'whatsapp', 'metadata': {'phone_number_id': '1'}, 'messages': [message]}
    return {'object': 'whatsapp_business_account', 'entry': [{'id': 'W', 'changes': [{'field': 'messages', 'value': value}]}]}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv('THREAT_INTEL_LIVE', '0')
    monkeypatch.setenv('GEMINI_API_KEY', '')
    monkeypatch.setenv('USE_FAKE_DB', '1')
    monkeypatch.setenv('AUTH_DEV_ECHO', '1')
    monkeypatch.setenv('AUTH_SECRET', 'test-secret')
    monkeypatch.setenv('META_APP_SECRET', SECRET)
    monkeypatch.setenv('META_VERIFY_TOKEN', 'v')
    monkeypatch.setenv('META_ACCESS_TOKEN', 'tok')
    monkeypatch.setenv('META_PHONE_NUMBER_ID', '1')
    monkeypatch.setenv('WHATSAPP_REPLIES', '0')   # replies are blocked by Meta; the link must not need them
    monkeypatch.setenv('WHATSAPP_BOT_NUMBER', '+1 555 186 1218')
    monkeypatch.delenv('WHATSAPP_MAX_PER_HOUR', raising=False)

    def refuse_any_network(*args, **kwargs):
        raise AssertionError('no message may be sent while replies are off')
    monkeypatch.setattr(whatsapp.requests, 'post', refuse_any_network)
    monkeypatch.setattr(whatsapp, '_submit', lambda task, *args: task(*args))
    whatsapp._seen.clear()
    whatsapp._sender_hits.clear()
    login._ip_hits.clear()
    set_db(FakeDatabase())
    with TestClient(app) as c:
        yield c


def sign_in(client, email):
    code = client.post('/auth/request-code', json={'email': email}).json()['dev_code']
    return client.post('/auth/verify-code', json={'email': email, 'code': code}).json()


def bearer(session):
    return {'Authorization': f"Bearer {session['token']}"}


def send(client, sender, body, mid):
    raw = json.dumps(text_payload(sender, body, mid)).encode()
    return client.post('/whatsapp/meta', content=raw, headers={'Content-Type': 'application/json', 'X-Hub-Signature-256': sign(raw)})


def link(client, session, sender, mid='m-link'):
    code = client.post('/whatsapp/link/code', headers=bearer(session)).json()['code']
    assert send(client, sender, code, mid).status_code == 200
    return code


# --- the link flow -----------------------------------------------------------

def test_link_needs_sign_in(client):
    assert client.get('/whatsapp/link').status_code == 401
    assert client.post('/whatsapp/link/code').status_code == 401
    assert client.delete('/whatsapp/link').status_code == 401


def test_code_then_message_links_the_number(client):
    session = sign_in(client, 'me@example.test')
    issued = client.post('/whatsapp/link/code', headers=bearer(session)).json()
    assert issued['code'].startswith('ETAP-') and len(issued['code']) == 11
    assert issued['bot_number'] == '+1 555 186 1218'
    assert client.get('/whatsapp/link', headers=bearer(session)).json()['linked'] is False

    assert send(client, USER, issued['code'], 'm1').status_code == 200
    status = client.get('/whatsapp/link', headers=bearer(session)).json()
    assert status['linked'] is True
    assert whatsapp_link.owner_for(USER) == 'me@example.test'
    assert whatsapp_link.owner_for(OTHER) is None


@pytest.mark.parametrize('typed', ['etap-{n}', 'ETAP {n}', ' etap{n} ', 'ETAP-{n}.'])
def test_code_is_accepted_however_it_is_typed(client, typed):
    session = sign_in(client, 'me@example.test')
    number = client.post('/whatsapp/link/code', headers=bearer(session)).json()['code'][-6:]
    send(client, USER, typed.format(n=number), 'm1')
    assert whatsapp_link.owner_for(USER) == 'me@example.test'


def test_code_works_once_and_a_wrong_code_does_nothing(client):
    session = sign_in(client, 'me@example.test')
    code = client.post('/whatsapp/link/code', headers=bearer(session)).json()['code']
    send(client, USER, 'ETAP-000000' if code != 'ETAP-000000' else 'ETAP-000001', 'm1')
    assert whatsapp_link.owner_for(USER) is None
    send(client, USER, code, 'm2')
    assert whatsapp_link.owner_for(USER) == 'me@example.test'
    send(client, OTHER, code, 'm3')          # reused
    assert whatsapp_link.owner_for(OTHER) is None


def test_expired_code_is_refused(client):
    session = sign_in(client, 'me@example.test')
    code = client.post('/whatsapp/link/code', headers=bearer(session)).json()['code']
    get_db()[whatsapp_link.CODES].update_one({}, {'$set': {'expires_at': datetime.now(timezone.utc) - timedelta(minutes=1)}})
    send(client, USER, code, 'm1')
    assert whatsapp_link.owner_for(USER) is None


def test_a_new_code_replaces_the_old_one(client):
    session = sign_in(client, 'me@example.test')
    old = client.post('/whatsapp/link/code', headers=bearer(session)).json()['code']
    new = client.post('/whatsapp/link/code', headers=bearer(session)).json()['code']
    if old != new:
        send(client, USER, old, 'm1')
        assert whatsapp_link.owner_for(USER) is None
    send(client, USER, new, 'm2')
    assert whatsapp_link.owner_for(USER) == 'me@example.test'


def test_one_number_per_account_and_the_latest_wins(client):
    me = sign_in(client, 'me@example.test')
    other = sign_in(client, 'other@example.test')
    link(client, me, USER, 'a1')
    link(client, other, USER, 'a2')                      # the same phone now belongs to the other account
    assert whatsapp_link.owner_for(USER) == 'other@example.test'
    assert client.get('/whatsapp/link', headers=bearer(me)).json()['linked'] is False
    link(client, other, OTHER, 'a3')                     # an account keeps one number
    assert whatsapp_link.owner_for(OTHER) == 'other@example.test' and whatsapp_link.owner_for(USER) is None


def test_unlink(client):
    session = sign_in(client, 'me@example.test')
    link(client, session, USER)
    assert client.delete('/whatsapp/link', headers=bearer(session)).json() == {'linked': False}
    assert whatsapp_link.owner_for(USER) is None


def test_phone_number_is_never_stored_in_clear(client):
    session = sign_in(client, 'me@example.test')
    link(client, session, USER)
    assert USER not in json.dumps(list(get_db()[whatsapp_link.LINKS].find({})), default=str)
    assert whatsapp_link.normalize_phone('whatsapp:+91 98765-43210') == '919876543210'
    assert whatsapp_link.phone_hash('whatsapp:+919876543210') == whatsapp_link.phone_hash(USER)


def test_a_code_with_an_attachment_or_extra_words_is_an_ordinary_message(client):
    session = sign_in(client, 'me@example.test')
    code = client.post('/whatsapp/link/code', headers=bearer(session)).json()['code']
    send(client, USER, f'is this real? {code}', 'm1')
    assert whatsapp_link.owner_for(USER) is None


# --- forwarded messages land in My reports -----------------------------------

def test_forwarded_message_from_a_linked_number_shows_under_my_reports(client):
    me = sign_in(client, 'me@example.test')
    stranger = sign_in(client, 'stranger@example.test')
    link(client, me, USER)
    send(client, USER, 'Your KYC expired, verify now at http://kyc-update-hdfc-secure.top/login', 'm-fwd')
    mine = client.get('/investigations?mine=true', headers=bearer(me)).json()
    assert len(mine['items'] if isinstance(mine, dict) and 'items' in mine else mine) == 1
    theirs = client.get('/investigations?mine=true', headers=bearer(stranger)).json()
    assert len(theirs['items'] if isinstance(theirs, dict) and 'items' in theirs else theirs) == 0


def test_forwarded_message_from_an_unlinked_number_is_analysed_but_has_no_owner(client):
    me = sign_in(client, 'me@example.test')
    send(client, OTHER, 'Verify your account at http://kyc-update-hdfc-secure.top/login now', 'm-fwd')
    assert get_db()['analyzed_emails'].count_documents({}) == 1
    mine = client.get('/investigations?mine=true', headers=bearer(me)).json()
    assert len(mine['items'] if isinstance(mine, dict) and 'items' in mine else mine) == 0


def test_replies_can_be_switched_off_without_touching_the_network(client):
    # the fixture's requests.post raises if anything is sent, so a clean run proves it
    assert whatsapp.replies_enabled() is False
    assert whatsapp.send_meta(USER, 'hello') is False
