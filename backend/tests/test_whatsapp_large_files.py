"""Big attachments: the 25 MB limits, byte-exact attachments in the .eml, and one-big-analysis-at-a-time."""
import email
import os
import threading
import time
from email import policy

import pytest

import heavy_gate
import whatsapp
from db.connection import get_db, set_db
from db.fake_mongo import FakeDatabase

MB = 1024 * 1024


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    monkeypatch.setenv('THREAT_INTEL_LIVE', '0')
    monkeypatch.setenv('GEMINI_API_KEY', '')
    monkeypatch.setenv('USE_FAKE_DB', '1')
    monkeypatch.setenv('CLOUDINARY_ENABLED', '0')
    set_db(FakeDatabase())


def run_worker(text, files):
    """files: [(content_type, bytes)]. Returns the replies the bot would send."""
    store = {str(i): data for i, (_t, data) in enumerate(files)}
    items = [(str(i), t, None) for i, (t, _d) in enumerate(files)]
    sent = []
    whatsapp._check_and_reply(text, items, lambda ref: store.get(ref), sent.append, 'SMbig')
    return sent


# --- limits ----------------------------------------------------------------

def test_limits_match_the_website():
    assert whatsapp.MAX_FILE_BYTES == 25 * MB and whatsapp.MAX_TOTAL_BYTES == 25 * MB
    assert whatsapp.MAX_FILES == 5


def test_a_file_just_under_25_mb_is_analysed():
    data = b'%PDF-1.4\n' + os.urandom(25 * MB - 64)
    sent = run_worker('see attached invoice', [('application/pdf', data)])
    assert len(sent) == 1 and sent[0].startswith('E-TAP result:')
    assert 'could not be checked' not in sent[0]
    assert get_db()['analyzed_emails'].count_documents({}) == 1


def test_five_files_totalling_25_mb_are_all_analysed():
    files = [('application/pdf', os.urandom(5 * MB - 32)) for _ in range(5)]
    sent = run_worker('five files', files)
    assert sent[0].startswith('E-TAP result:') and 'could not be checked' not in sent[0]


def test_a_file_over_25_mb_is_skipped_but_the_text_is_still_checked():
    sent = run_worker('Verify now at http://login.example.test', [('application/zip', os.urandom(26 * MB))])
    assert sent[0].startswith('E-TAP result:') and '1 file(s) could not be checked' in sent[0]


def test_a_sixth_file_is_skipped():
    files = [('text/plain', b'file %d' % i) for i in range(6)]
    sent = run_worker('six small files', files)
    assert '1 file(s) could not be checked' in sent[0]


# --- the hand-built .eml ---------------------------------------------------

def test_attachments_survive_byte_for_byte():
    originals = {
        'big.bin': os.urandom(3 * MB + 7),          # not a multiple of the base64 chunk size
        'tiny.txt': b'x',
        'empty.dat': b'',
    }
    raw = whatsapp.build_eml('hello', [(n, 'application/octet-stream', d) for n, d in originals.items()], 'SM1')
    parsed = email.message_from_bytes(raw, policy=policy.default)
    found = {part.get_filename(): part.get_payload(decode=True) for part in parsed.walk() if part.get_filename()}
    assert found == originals


def test_base64_lines_are_short_and_crlf_terminated():
    raw = whatsapp.build_eml('hi', [('a.bin', 'application/octet-stream', os.urandom(200_000))], 'SM2')
    lines = raw.split(b'\r\n')
    assert max(len(line) for line in lines) <= 76 + len('Content-Disposition: attachment; filename="a.bin"')
    assert b'\n' not in raw.replace(b'\r\n', b'')


def test_headers_and_text_are_intact_and_there_is_no_sender():
    body = 'Click www.bad.example.test/login now. Hindi: नमस्ते and a smiley \U0001F600'
    raw = whatsapp.build_eml(body, [], 'SM-3/x')
    parsed = email.message_from_bytes(raw, policy=policy.default)
    assert parsed['From'] is None and parsed['To'] is None and parsed['Date'] is None
    assert parsed['Message-ID'] == '<whatsapp-SM3x@etap.local>'
    assert parsed['Subject'].startswith('WhatsApp message: Click www.bad.example.test/login now')
    plain = parsed.get_body(preferencelist=('plain',)).get_content().strip()
    assert plain == body
    html_part = parsed.get_body(preferencelist=('html',)).get_content()
    assert 'href="http://www.bad.example.test/login"' in html_part


def test_hostile_names_and_types_cannot_break_the_headers():
    raw = whatsapp.build_eml('x', [('evil"\r\nBcc: a@b.test.pdf', 'text/plain\r\nX-Evil: 1', b'data')], 'SM4')
    parsed = email.message_from_bytes(raw, policy=policy.default)
    assert parsed['Bcc'] is None and parsed['X-Evil'] is None
    part = [p for p in parsed.walk() if p.get_filename()][0]
    assert part.get_content_type() == 'application/octet-stream'
    assert '\r' not in part.get_filename() and '\n' not in part.get_filename()


def test_files_only_message_has_placeholder_text():
    raw = whatsapp.build_eml('', [('a.txt', 'text/plain', b'a')], 'SM5')
    parsed = email.message_from_bytes(raw, policy=policy.default)
    assert parsed.get_body(preferencelist=('plain',)).get_content().strip() == '(no text, files only)'


# --- one big analysis at a time ---------------------------------------------

def _overlap(sizes):
    state = {'now': 0, 'max': 0}
    lock = threading.Lock()

    def job(size):
        with heavy_gate.heavy_analysis(size):
            with lock:
                state['now'] += 1
                state['max'] = max(state['max'], state['now'])
            time.sleep(0.05)
            with lock:
                state['now'] -= 1
    threads = [threading.Thread(target=job, args=(s,)) for s in sizes]
    [t.start() for t in threads]
    [t.join() for t in threads]
    return state['max']


def test_big_analyses_take_turns():
    assert _overlap([9 * MB] * 4) == 1


def test_small_analyses_run_in_parallel():
    assert _overlap([1 * MB] * 4) > 1


def test_the_gate_is_released_when_an_analysis_fails():
    with pytest.raises(RuntimeError):
        with heavy_gate.heavy_analysis(30 * MB):
            raise RuntimeError('boom')
    with heavy_gate.heavy_analysis(30 * MB):
        pass  # would hang forever if the failed one had kept the gate


def test_release_memory_never_raises():
    heavy_gate.release_memory()
