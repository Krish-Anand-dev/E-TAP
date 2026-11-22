"""WhatsApp bot, Meta Cloud API provider: handshake, signature, messages, media, replies. Meta is faked."""
import email
import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

import whatsapp
from app import app
from db.connection import get_db, set_db
from db.fake_mongo import FakeDatabase

SECRET = 'meta-app-secret'
VERIFY = 'my-verify-token'
PHONE_ID = '1234567890'
USER = '919876543210'
GRAPH = 'https://graph.facebook.com/v23.0'


def sign(raw: bytes, secret=SECRET):
    return 'sha256=' + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()


def payload(*messages, statuses=None):
    value = {'messaging_product': 'whatsapp', 'metadata': {'phone_number_id': PHONE_ID}}
    if messages:
        value['messages'] = list(messages)
    if statuses:
        value['statuses'] = statuses
    return {'object': 'whatsapp_business_account', 'entry': [{'id': 'WABA', 'changes': [{'field': 'messages', 'value': value}]}]}


def text_message(body, mid='wamid.1'):
    return {'from': USER, 'id': mid, 'type': 'text', 'text': {'body': body}}


class FakeMeta:
    def __init__(self):
        self.sent = []
        self.lookups = {}   # media id -> {'url':..., 'bytes':...}
        self.requested = []

    def post(self, url, headers=None, json=None, timeout=None):
        self.sent.append({'url': url, 'headers': headers, 'json': json})
        return type('R', (), {'status_code': 200})()

    def get(self, url, headers=None, timeout=None, stream=None):
        self.requested.append(url)
        media_id = url.rsplit('/', 1)[-1]
        if url.startswith(GRAPH) and media_id in self.lookups:
            info = self.lookups[media_id]
            return type('R', (), {'status_code': 200, 'json': staticmethod(lambda: {'url': info['url']})})()
        for info in self.lookups.values():
            if url == info['url']:
                body = info['bytes']
                return type('R', (), {'status_code': 200, 'iter_content': staticmethod(lambda size: iter([body]))})()
        return type('R', (), {'status_code': 404, 'json': staticmethod(lambda: {})})()

    def bodies(self):
        return [s['json']['text']['body'] for s in self.sent]


@pytest.fixture
def bot(monkeypatch):
    monkeypatch.setenv('THREAT_INTEL_LIVE', '0')
    monkeypatch.setenv('GEMINI_API_KEY', '')
    monkeypatch.setenv('USE_FAKE_DB', '1')
    monkeypatch.setenv('META_APP_SECRET', SECRET)
    monkeypatch.setenv('META_VERIFY_TOKEN', VERIFY)
    monkeypatch.setenv('META_ACCESS_TOKEN', 'tok-secret')
    monkeypatch.setenv('META_PHONE_NUMBER_ID', PHONE_ID)
    monkeypatch.setenv('WHATSAPP_REPLIES', '1')
    monkeypatch.setenv('PUBLIC_FRONTEND_URL', 'https://site.example.test')
    monkeypatch.delenv('WHATSAPP_MAX_PER_HOUR', raising=False)
    monkeypatch.delenv('META_GRAPH_VERSION', raising=False)
    fake = FakeMeta()
    monkeypatch.setattr(whatsapp.requests, 'post', fake.post)
    monkeypatch.setattr(whatsapp.requests, 'get', fake.get)
    monkeypatch.setattr(whatsapp, '_submit', lambda task, *args: task(*args))
    whatsapp._seen.clear()
    whatsapp._sender_hits.clear()
    set_db(FakeDatabase())
    with TestClient(app) as client:
        client.fake = fake
        yield client


def deliver(client, body, signature=None):
    raw = json.dumps(body).encode()
    headers = {'Content-Type': 'application/json', 'X-Hub-Signature-256': signature or sign(raw)}
    return client.post('/whatsapp/meta', content=raw, headers=headers)


def stored():
    return get_db()['analyzed_emails'].count_documents({})


# --- handshake -------------------------------------------------------------

def test_handshake_echoes_the_challenge(bot):
    reply = bot.get('/whatsapp/meta', params={'hub.mode': 'subscribe', 'hub.verify_token': VERIFY, 'hub.challenge': '98765'})
    assert reply.status_code == 200 and reply.text == '98765'


@pytest.mark.parametrize('token', ['wrong', ''])
def test_handshake_refuses_a_wrong_token(bot, token):
    reply = bot.get('/whatsapp/meta', params={'hub.mode': 'subscribe', 'hub.verify_token': token, 'hub.challenge': '1'})
    assert reply.status_code == 403


def test_handshake_is_off_without_a_token(bot, monkeypatch):
    monkeypatch.delenv('META_VERIFY_TOKEN')
    assert bot.get('/whatsapp/meta', params={'hub.mode': 'subscribe', 'hub.verify_token': 'x', 'hub.challenge': '1'}).status_code == 503


# --- signature -------------------------------------------------------------

def test_off_without_an_app_secret(bot, monkeypatch):
    monkeypatch.delenv('META_APP_SECRET')
    assert deliver(bot, payload(text_message('hello there'))).status_code == 503


@pytest.mark.parametrize('signature', ['', 'sha256=bogus', 'bogus'])
def test_forged_signature_is_refused(bot, signature):
    raw = json.dumps(payload(text_message('Click http://x.example.test'))).encode()
    headers = {'Content-Type': 'application/json', 'X-Hub-Signature-256': signature}
    assert bot.post('/whatsapp/meta', content=raw, headers=headers).status_code == 403
    assert bot.fake.sent == [] and stored() == 0


def test_signature_made_with_another_secret_is_refused(bot):
    raw = json.dumps(payload(text_message('hello there'))).encode()
    assert deliver(bot, payload(text_message('hello there')), signature=sign(raw, 'other-secret')).status_code == 403


def test_signed_but_malformed_body_is_a_400(bot):
    raw = b'{not json'
    reply = bot.post('/whatsapp/meta', content=raw, headers={'X-Hub-Signature-256': sign(raw)})
    assert reply.status_code == 400


# --- messages --------------------------------------------------------------

def test_forwarded_text_is_acknowledged_then_answered(bot):
    reply = deliver(bot, payload(text_message('Urgent: verify your account at http://login.example.test now')))
    assert reply.status_code == 200 and reply.json() == {'status': 'ok'}
    assert stored() == 1
    bodies = bot.fake.bodies()
    assert len(bodies) == 2 and 'Checking now' in bodies[0]
    assert bodies[1].startswith('E-TAP result:') and 'https://site.example.test/?dossier=' in bodies[1]
    first = bot.fake.sent[0]
    assert first['url'] == f'{GRAPH}/{PHONE_ID}/messages'
    assert first['headers']['Authorization'] == 'Bearer tok-secret'
    assert first['json']['to'] == USER and first['json']['messaging_product'] == 'whatsapp'


def test_the_report_link_opens_a_stored_report(bot):
    deliver(bot, payload(text_message('Please verify http://login.example.test')))
    link = bot.fake.bodies()[1].split('/?dossier=')[1].split()[0]
    assert bot.get(f'/investigations/{link}').status_code == 200


def test_a_redelivered_message_is_not_analysed_twice(bot):
    body = payload(text_message('Please verify http://login.example.test', mid='wamid.dup'))
    deliver(bot, body)
    deliver(bot, body)
    assert stored() == 1 and len(bot.fake.sent) == 2


def test_status_updates_are_ignored(bot):
    reply = deliver(bot, payload(statuses=[{'id': 'wamid.x', 'status': 'delivered'}]))
    assert reply.status_code == 200 and bot.fake.sent == [] and stored() == 0


def test_other_webhook_fields_are_ignored(bot):
    body = {'object': 'whatsapp_business_account', 'entry': [{'changes': [{'field': 'account_update', 'value': {}}]}]}
    assert deliver(bot, body).status_code == 200 and bot.fake.sent == []


@pytest.mark.parametrize('greeting', ['hi', 'Hello', 'help'])
def test_greetings_get_instructions(bot, greeting):
    deliver(bot, payload(text_message(greeting, mid=f'wamid.{greeting}')))
    assert bot.fake.bodies() == [whatsapp.HELP_TEXT] and stored() == 0


def test_unsupported_types_are_told_what_works(bot):
    deliver(bot, payload({'from': USER, 'id': 'wamid.a', 'type': 'audio', 'audio': {'id': '5'}}))
    assert bot.fake.bodies() == [whatsapp.UNSUPPORTED_TEXT] and stored() == 0


def test_per_sender_limit(bot, monkeypatch):
    monkeypatch.setenv('WHATSAPP_MAX_PER_HOUR', '1')
    deliver(bot, payload(text_message('First message to check', mid='wamid.l1')))
    before = len(bot.fake.sent)
    deliver(bot, payload(text_message('Second message to check', mid='wamid.l2')))
    assert bot.fake.bodies()[before:] == [whatsapp.BUSY_TEXT] and stored() == 1


# --- files -----------------------------------------------------------------

def test_an_image_is_looked_up_downloaded_and_attached(bot, monkeypatch):
    seen = {}
    from pipeline import analyze_email_upload as real

    def spy(filename, raw, source, progress=None, sandbox=None):
        seen.update(raw=raw, source=source, sandbox=sandbox)
        return real(filename, raw, source, progress, sandbox)
    monkeypatch.setattr('pipeline.analyze_email_upload', spy)
    bot.fake.lookups['555'] = {'url': 'https://lookaside.fbsbx.com/whatsapp_business/attachments/?mid=555', 'bytes': b'\x89PNG tiny'}
    message = {'from': USER, 'id': 'wamid.img', 'type': 'image',
               'image': {'id': '555', 'mime_type': 'image/png', 'caption': 'is this my bank?'}}
    deliver(bot, payload(message))
    assert seen['source'] == 'forwarded_message' and seen['sandbox']['requested'] is False
    parsed = email.message_from_bytes(seen['raw'])
    assert [p.get_filename() for p in parsed.walk() if p.get_filename()] == ['whatsapp-file-1.png']
    assert 'is this my bank?' in parsed.get_payload(0).get_payload(0).get_payload(decode=True).decode()
    assert 'could not be checked' not in bot.fake.bodies()[-1]


def test_a_document_keeps_its_file_name(bot, monkeypatch):
    seen = {}
    from pipeline import analyze_email_upload as real
    monkeypatch.setattr('pipeline.analyze_email_upload',
                        lambda f, raw, s, p=None, sb=None: (seen.update(raw=raw), real(f, raw, s, p, sb))[1])
    bot.fake.lookups['777'] = {'url': 'https://lookaside.fbsbx.com/x/777', 'bytes': b'%PDF-1.4 tiny'}
    deliver(bot, payload({'from': USER, 'id': 'wamid.doc', 'type': 'document',
                          'document': {'id': '777', 'mime_type': 'application/pdf', 'filename': 'invoice ../final.pdf'}}))
    names = [p.get_filename() for p in email.message_from_bytes(seen['raw']).walk() if p.get_filename()]
    assert names == ['invoice .._final.pdf'] or names == ['invoice _final.pdf'] or all('/' not in n for n in names)
    assert stored() == 1


def test_a_file_from_an_unexpected_host_is_never_downloaded(bot):
    bot.fake.lookups['888'] = {'url': 'https://evil.example.test/steal', 'bytes': b'x'}
    deliver(bot, payload({'from': USER, 'id': 'wamid.evil', 'type': 'image',
                          'image': {'id': '888', 'mime_type': 'image/png', 'caption': 'look at this'}}))
    assert 'https://evil.example.test/steal' not in bot.fake.requested
    assert 'could not be checked' in bot.fake.bodies()[-1] and stored() == 1


def test_a_media_id_that_is_not_a_number_is_never_looked_up(bot):
    deliver(bot, payload({'from': USER, 'id': 'wamid.bad', 'type': 'image',
                          'image': {'id': '../../me/accounts', 'mime_type': 'image/png', 'caption': 'see this'}}))
    assert all('accounts' not in url for url in bot.fake.requested)


def test_an_unreachable_file_is_noted(bot):
    deliver(bot, payload({'from': USER, 'id': 'wamid.gone', 'type': 'image',
                          'image': {'id': '999', 'mime_type': 'image/jpeg', 'caption': 'please check'}}))
    assert 'could not be checked' in bot.fake.bodies()[-1]


def test_oversized_file_is_skipped(bot, monkeypatch):
    monkeypatch.setattr(whatsapp, 'MAX_FILE_BYTES', 5)
    bot.fake.lookups['444'] = {'url': 'https://lookaside.fbsbx.com/x/444', 'bytes': b'x' * 50}
    deliver(bot, payload({'from': USER, 'id': 'wamid.big', 'type': 'document',
                          'document': {'id': '444', 'mime_type': 'application/zip', 'filename': 'a.zip',
                                       'caption': 'open this right now'}}))
    assert 'could not be checked' in bot.fake.bodies()[-1]


def test_a_file_only_message_whose_file_is_skipped_gets_an_apology(bot, monkeypatch):
    monkeypatch.setattr(whatsapp, 'MAX_FILE_BYTES', 5)
    bot.fake.lookups['445'] = {'url': 'https://lookaside.fbsbx.com/x/445', 'bytes': b'x' * 50}
    deliver(bot, payload({'from': USER, 'id': 'wamid.big2', 'type': 'document',
                          'document': {'id': '445', 'mime_type': 'application/zip', 'filename': 'a.zip'}}))
    assert bot.fake.bodies()[-1] == whatsapp.FAILED_TEXT and stored() == 0


# --- failure handling ------------------------------------------------------

def test_a_pipeline_failure_gets_an_apology(bot, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError('pipeline down')
    monkeypatch.setattr('pipeline.analyze_email_upload', boom)
    assert deliver(bot, payload(text_message('Check this please', mid='wamid.err'))).status_code == 200
    assert bot.fake.bodies()[-1] == whatsapp.FAILED_TEXT


def test_a_failed_reply_never_raises(bot, monkeypatch):
    def refuse(*args, **kwargs):
        raise ConnectionError('graph down')
    monkeypatch.setattr(whatsapp.requests, 'post', refuse)
    assert deliver(bot, payload(text_message('Check this please', mid='wamid.net'))).status_code == 200
    assert whatsapp.send_meta(USER, 'x') is False


def test_unconfigured_sender_does_not_send(bot, monkeypatch):
    monkeypatch.delenv('META_ACCESS_TOKEN')
    assert whatsapp.send_meta(USER, 'x') is False and bot.fake.sent == []


def test_graph_version_can_be_overridden(bot, monkeypatch):
    monkeypatch.setenv('META_GRAPH_VERSION', 'v99.0')
    whatsapp.send_meta(USER, 'x')
    assert bot.fake.sent[-1]['url'] == f'https://graph.facebook.com/v99.0/{PHONE_ID}/messages'


def test_delivery_lock_is_logged_without_disclosing_payload(bot, caplog):
    reply = deliver(bot, payload(statuses=[{
        'id': 'private-message-id', 'recipient_id': USER, 'status': 'failed',
        'errors': [{'code': 131031, 'title': 'private-provider-text',
                    'error_data': {'details': 'tok-secret'}}],
    }]))
    assert reply.status_code == 200 and bot.fake.sent == [] and stored() == 0
    assert 'delivery failed (code 131031' in caplog.text
    assert 'Meta Business Support Home' in caplog.text
    for private in (USER, 'private-message-id', 'private-provider-text', 'tok-secret'):
        assert private not in caplog.text


def test_rejected_api_request_logs_provider_code(bot, monkeypatch, caplog):
    def refuse(*args, **kwargs):
        return type('R', (), {'status_code': 400, 'json': staticmethod(lambda: {
            'error': {'code': 131031, 'error_subcode': 7, 'message': 'tok-secret'}
        })})()
    monkeypatch.setattr(whatsapp.requests, 'post', refuse)
    assert whatsapp.send_meta(USER, 'private message') is False
    assert 'request failed (code 131031, subcode 7)' in caplog.text
    assert 'tok-secret' not in caplog.text and 'private message' not in caplog.text


def test_failed_delivery_without_error_details_still_acknowledged(bot, caplog):
    assert deliver(bot, payload(statuses=[{'status': 'failed'}])).status_code == 200
    assert 'delivery failed (code unknown' in caplog.text


def test_nonnumeric_error_codes_are_not_logged(bot, caplog):
    deliver(bot, payload(statuses=[{'status': 'failed', 'errors': [{
        'code': 'private-code', 'error_subcode': 'private-subcode',
    }]}]))
    assert 'code unknown, subcode unknown' in caplog.text
    assert 'private-code' not in caplog.text and 'private-subcode' not in caplog.text
