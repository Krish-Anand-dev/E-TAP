"""WhatsApp bot: signature check, acknowledgement, background analysis, reply, limits. Twilio is faked."""
import base64
import email
import hashlib
import hmac

import pytest
from fastapi.testclient import TestClient

import whatsapp
from app import app
from db.connection import get_db, set_db
from db.fake_mongo import FakeDatabase

TOKEN = 'twilio-test-token'
URL = 'http://testserver/whatsapp/twilio'
USER = 'whatsapp:+15551230000'


def sign(params, url=URL, token=TOKEN):
    payload = url + ''.join(f'{k}{params[k]}' for k in sorted(params))
    return base64.b64encode(hmac.new(token.encode(), payload.encode(), hashlib.sha1).digest()).decode()


class Fake:
    """Records what the bot sends to Twilio and serves canned media."""
    def __init__(self):
        self.sent = []
        self.media = {}

    def post(self, url, auth=None, data=None, timeout=None):
        self.sent.append(data)
        return type('R', (), {'status_code': 201})()

    def get(self, url, auth=None, timeout=None, stream=None):
        body = self.media.get(url)
        status = 200 if body is not None else 404

        class R:
            status_code = status

            @staticmethod
            def iter_content(size):
                if body:
                    yield body
        return R()


@pytest.fixture
def bot(monkeypatch):
    monkeypatch.setenv('THREAT_INTEL_LIVE', '0')
    monkeypatch.setenv('GEMINI_API_KEY', '')
    monkeypatch.setenv('USE_FAKE_DB', '1')
    monkeypatch.setenv('TWILIO_ACCOUNT_SID', 'ACtest')
    monkeypatch.setenv('TWILIO_AUTH_TOKEN', TOKEN)
    monkeypatch.setenv('TWILIO_WHATSAPP_FROM', 'whatsapp:+14155238886')
    monkeypatch.setenv('PUBLIC_API_URL', 'http://testserver')
    monkeypatch.setenv('PUBLIC_FRONTEND_URL', 'https://site.example.test')
    monkeypatch.delenv('WHATSAPP_MAX_PER_HOUR', raising=False)
    fake = Fake()
    monkeypatch.setattr(whatsapp.requests, 'post', fake.post)
    monkeypatch.setattr(whatsapp.requests, 'get', fake.get)
    monkeypatch.setattr(whatsapp, '_submit', lambda task, *args: task(*args))  # run the worker inline
    whatsapp._seen.clear()
    whatsapp._sender_hits.clear()
    set_db(FakeDatabase())
    with TestClient(app) as client:
        client.fake = fake
        yield client


def hit(client, sid='SM1', body='Urgent: verify your account at http://login.example.test now', **extra):
    params = {'MessageSid': sid, 'From': USER, 'To': 'whatsapp:+14155238886', 'Body': body, 'NumMedia': '0', **extra}
    return client.post('/whatsapp/twilio', data=params, headers={'X-Twilio-Signature': sign(params)})


def stored():
    return get_db()['analyzed_emails'].count_documents({})


def test_off_without_a_token(bot, monkeypatch):
    monkeypatch.delenv('TWILIO_AUTH_TOKEN')
    assert hit(bot).status_code == 503


@pytest.mark.parametrize('signature', ['', 'bogus', None])
def test_unsigned_or_forged_requests_are_refused(bot, signature):
    params = {'MessageSid': 'SM9', 'From': USER, 'Body': 'hi there', 'NumMedia': '0'}
    headers = {} if signature is None else {'X-Twilio-Signature': signature}
    assert bot.post('/whatsapp/twilio', data=params, headers=headers).status_code == 403
    assert bot.fake.sent == [] and stored() == 0


def test_a_tampered_field_breaks_the_signature(bot):
    params = {'MessageSid': 'SM2', 'From': USER, 'Body': 'original', 'NumMedia': '0'}
    signature = sign(params)
    params['Body'] = 'changed'
    assert bot.post('/whatsapp/twilio', data=params, headers={'X-Twilio-Signature': signature}).status_code == 403


def test_forwarded_text_is_acknowledged_then_answered(bot):
    reply = hit(bot)
    assert reply.status_code == 200 and 'Checking now' in reply.text
    assert reply.headers['content-type'].startswith('application/xml')
    assert stored() == 1
    assert len(bot.fake.sent) == 1
    sent = bot.fake.sent[0]
    assert sent['To'] == USER and sent['From'] == 'whatsapp:+14155238886'
    text = sent['Body']
    assert text.startswith('E-TAP result:') and 'Risk score' in text and 'What to do:' in text
    assert 'https://site.example.test/?dossier=' in text
    assert len(text) <= whatsapp.MAX_REPLY_CHARS


def test_the_report_link_opens_a_stored_report(bot):
    hit(bot)
    link = bot.fake.sent[0]['Body'].split('/?dossier=')[1].split()[0]
    assert bot.get(f'/investigations/{link}').status_code == 200


def test_a_retry_of_the_same_message_is_not_analysed_twice(bot):
    hit(bot, sid='SMdup')
    again = hit(bot, sid='SMdup')
    assert again.status_code == 200 and again.text == '<Response/>'
    assert stored() == 1 and len(bot.fake.sent) == 1


@pytest.mark.parametrize('greeting', ['hi', 'Hello', 'help', ''])
def test_greetings_get_instructions_not_an_analysis(bot, greeting):
    reply = hit(bot, sid=f'SMg{greeting}', body=greeting)
    assert 'm E-TAP. Forward me a suspicious message' in reply.text and stored() == 0 and bot.fake.sent == []


def test_per_sender_limit(bot, monkeypatch):
    monkeypatch.setenv('WHATSAPP_MAX_PER_HOUR', '2')
    assert 'Checking now' in hit(bot, sid='A1').text
    assert 'Checking now' in hit(bot, sid='A2', body='Second message to check').text
    third = hit(bot, sid='A3', body='Third message to check')
    assert 'try again a little later' in third.text
    assert stored() == 2


def test_files_are_downloaded_and_attached(bot, monkeypatch):
    seen = {}
    from pipeline import analyze_email_upload as real

    def spy(filename, raw, source, progress=None, sandbox=None):
        seen.update(raw=raw, source=source, sandbox=sandbox)
        return real(filename, raw, source, progress, sandbox)
    monkeypatch.setattr('pipeline.analyze_email_upload', spy)
    url = 'https://api.twilio.com/2010-04-01/Accounts/ACtest/Messages/MM1/Media/ME1'
    bot.fake.media[url] = b'plain attachment text'
    reply = hit(bot, sid='SMm', body='see attached', NumMedia='1', MediaUrl0=url, MediaContentType0='text/plain')
    assert 'Checking now' in reply.text
    assert seen['source'] == 'forwarded_message' and seen['sandbox']['requested'] is False
    parsed = email.message_from_bytes(seen['raw'])
    names = [part.get_filename() for part in parsed.walk() if part.get_filename()]
    assert names == ['whatsapp-file-1.txt']
    assert bot.fake.sent and 'could not be checked' not in bot.fake.sent[0]['Body']


def test_a_file_only_message_is_analysed(bot):
    url = 'https://media.twiliocdn.com/ACtest/abc'
    bot.fake.media[url] = b'%PDF-1.4 tiny'
    reply = hit(bot, sid='SMf', body='', NumMedia='1', MediaUrl0=url, MediaContentType0='application/pdf')
    assert 'Checking now' in reply.text and stored() == 1


def test_media_from_other_hosts_is_never_fetched(bot):
    fetched = []
    original = bot.fake.get
    bot.fake.get = lambda *a, **k: (fetched.append(a), original(*a, **k))[1]
    whatsapp.requests.get = bot.fake.get
    hit(bot, sid='SMx', body='check this', NumMedia='1', MediaUrl0='https://evil.example.test/steal',
        MediaContentType0='image/png')
    assert fetched == []
    assert 'could not be checked' in bot.fake.sent[0]['Body']
    assert stored() == 1


def test_unreachable_file_is_noted_but_text_is_still_checked(bot):
    url = 'https://api.twilio.com/missing'
    hit(bot, sid='SMu', body='please open the file', NumMedia='1', MediaUrl0=url, MediaContentType0='image/jpeg')
    assert 'could not be checked' in bot.fake.sent[0]['Body'] and stored() == 1


def test_oversized_file_is_skipped(bot, monkeypatch):
    monkeypatch.setattr(whatsapp, 'MAX_FILE_BYTES', 10)
    url = 'https://api.twilio.com/big'
    bot.fake.media[url] = b'x' * 100
    hit(bot, sid='SMb', body='big file', NumMedia='1', MediaUrl0=url, MediaContentType0='application/zip')
    assert 'could not be checked' in bot.fake.sent[0]['Body']


def test_a_pipeline_failure_gets_an_apology_not_a_crash(bot, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError('pipeline down')
    monkeypatch.setattr('pipeline.analyze_email_upload', boom)
    assert hit(bot, sid='SMe').status_code == 200
    assert bot.fake.sent[0]['Body'] == whatsapp.FAILED_TEXT


def test_a_failed_reply_never_raises(bot, monkeypatch):
    def refuse(*args, **kwargs):
        raise ConnectionError('twilio down')
    monkeypatch.setattr(whatsapp.requests, 'post', refuse)
    assert hit(bot, sid='SMr').status_code == 200
    assert whatsapp.send_whatsapp(USER, 'x') is False


def test_eml_has_no_sender_headers_and_links_are_clickable():
    raw = whatsapp.build_eml('Click www.bad.example.test/login or http://x.example.test/a.', [], 'SM77')
    parsed = email.message_from_bytes(raw)
    assert parsed['From'] is None and parsed['To'] is None and parsed['Date'] is None
    assert parsed['Subject'].startswith('WhatsApp message: Click')
    html_part = [p for p in parsed.walk() if p.get_content_type() == 'text/html'][0].get_payload(decode=True).decode()
    assert 'href="http://www.bad.example.test/login"' in html_part and 'href="http://x.example.test/a"' in html_part


def test_reply_never_calls_a_clean_result_safe():
    report = {'verdict': 'Safe', 'risk_score': 3, 'email_id': 'abc',
              'evidence_report': {'conclusion': {'band': 'safe', 'limitations': []}}}
    text = whatsapp.reply_text(report)
    assert 'NO PROBLEMS FOUND' in text and 'SAFE' not in text.upper().replace('NO PROBLEMS FOUND', '')
    limited = whatsapp.reply_text({**report, 'evidence_report': {'conclusion': {'band': 'safe', 'limitations': ['x']}}})
    assert 'LIMITED CHECK' in limited
